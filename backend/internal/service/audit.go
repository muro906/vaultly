package service

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"vaultly/backend/internal/db/sqlcgen"
	"vaultly/backend/internal/domain"
)

// Actor identifies who performed an action. Exactly one of UserID and TokenID
// is set: a human acting through the UI, or a machine acting through a scoped
// access token.
type Actor struct {
	UserID  *uuid.UUID
	TokenID *uuid.UUID
	// IP and UserAgent describe where the action came from. They are recorded
	// so that a leaked credential can be traced after the fact.
	IP        netip.Addr
	UserAgent string
}

// UserActor builds an Actor for a human.
func UserActor(userID uuid.UUID) Actor { return Actor{UserID: &userID} }

// TokenActor builds an Actor for a machine credential.
func TokenActor(tokenID uuid.UUID) Actor { return Actor{TokenID: &tokenID} }

// Event is one entry queued for the audit log.
type Event struct {
	WorkspaceID  uuid.UUID
	Actor        Actor
	Action       string
	ResourceType string
	ResourceID   *uuid.UUID
	Metadata     map[string]any
}

// AuditRecorder writes audit entries asynchronously.
//
// Auditing must not be on the critical path of a request: a secret read should
// not wait for an INSERT, and a slow audit write must never turn into a slow
// API. Events are therefore queued and drained by a background goroutine that
// batches them into one transaction per flush.
//
// The trade-off is explicit. If the process is killed without Close, queued
// events are lost. That is acceptable for an activity feed, and Close is
// wired into graceful shutdown so an orderly stop always flushes.
type AuditRecorder struct {
	queries *sqlcgen.Queries
	store   *Store
	logger  *slog.Logger

	events chan Event

	// flushSize and flushInterval bound how long an event waits and how large
	// a batch grows.
	flushSize     int
	flushInterval time.Duration

	// dropped counts events discarded because the queue was full, so the
	// condition is visible rather than silent.
	dropped atomic.Int64

	wg   sync.WaitGroup
	done chan struct{}
	// closeOnce keeps Close idempotent, since shutdown paths can overlap.
	closeOnce sync.Once
}

// AuditConfig tunes the recorder. The zero value is filled in with defaults.
type AuditConfig struct {
	QueueSize     int
	FlushSize     int
	FlushInterval time.Duration
}

func (c AuditConfig) withDefaults() AuditConfig {
	if c.QueueSize <= 0 {
		c.QueueSize = 1024
	}
	if c.FlushSize <= 0 {
		c.FlushSize = 64
	}
	if c.FlushInterval <= 0 {
		c.FlushInterval = time.Second
	}
	return c
}

// NewAuditRecorder starts a recorder and its background writer. Call Close to
// flush and stop it.
func NewAuditRecorder(store *Store, logger *slog.Logger, cfg AuditConfig) *AuditRecorder {
	cfg = cfg.withDefaults()

	r := &AuditRecorder{
		queries:       store.Queries(),
		store:         store,
		logger:        logger,
		events:        make(chan Event, cfg.QueueSize),
		flushSize:     cfg.FlushSize,
		flushInterval: cfg.FlushInterval,
		done:          make(chan struct{}),
	}

	r.wg.Add(1)
	go r.run()

	return r
}

// Record queues an event. It never blocks: if the queue is full the event is
// dropped and counted, because stalling a request to record that the request
// happened would be the wrong trade.
func (r *AuditRecorder) Record(event Event) {
	select {
	case r.events <- event:
	default:
		n := r.dropped.Add(1)
		// Log the first drop and then every thousandth, so a sustained
		// overload is visible without flooding the log.
		if n == 1 || n%1000 == 0 {
			r.logger.Warn("audit queue full, dropping events",
				slog.String("action", event.Action),
				slog.Int64("dropped_total", n))
		}
	}
}

// Dropped reports how many events have been discarded due to a full queue.
func (r *AuditRecorder) Dropped() int64 { return r.dropped.Load() }

// run drains the queue until Close.
func (r *AuditRecorder) run() {
	defer r.wg.Done()

	ticker := time.NewTicker(r.flushInterval)
	defer ticker.Stop()

	batch := make([]Event, 0, r.flushSize)

	for {
		select {
		case event, ok := <-r.events:
			if !ok {
				// Channel closed by Close: write what is left and stop.
				r.flush(batch)
				return
			}
			batch = append(batch, event)
			if len(batch) >= r.flushSize {
				r.flush(batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			if len(batch) > 0 {
				r.flush(batch)
				batch = batch[:0]
			}
		}
	}
}

// flush writes a batch in a single transaction.
func (r *AuditRecorder) flush(batch []Event) {
	if len(batch) == 0 {
		return
	}

	// Detached from any request context: the requests that produced these
	// events have long since returned, so their contexts may be cancelled.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := r.store.InTx(ctx, func(q *sqlcgen.Queries) error {
		for _, event := range batch {
			params, err := auditParams(event)
			if err != nil {
				// A single unencodable event must not sink the batch.
				r.logger.Error("skipping unencodable audit event",
					slog.String("action", event.Action),
					slog.String("error", err.Error()))
				continue
			}
			if err := q.CreateAuditLog(ctx, params); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		r.logger.Error("failed to write audit batch",
			slog.Int("events", len(batch)),
			slog.String("error", err.Error()))
	}
}

func auditParams(event Event) (sqlcgen.CreateAuditLogParams, error) {
	metadata := []byte("{}")
	if len(event.Metadata) > 0 {
		encoded, err := json.Marshal(event.Metadata)
		if err != nil {
			return sqlcgen.CreateAuditLogParams{}, err
		}
		metadata = encoded
	}

	params := sqlcgen.CreateAuditLogParams{
		WorkspaceID:  event.WorkspaceID,
		ActorUserID:  event.Actor.UserID,
		ActorTokenID: event.Actor.TokenID,
		Action:       event.Action,
		ResourceType: event.ResourceType,
		ResourceID:   event.ResourceID,
		Metadata:     metadata,
		UserAgent:    event.Actor.UserAgent,
	}
	if event.Actor.IP.IsValid() {
		addr := event.Actor.IP.Unmap()
		params.IpAddress = &addr
	}
	return params, nil
}

// Close stops the recorder, flushing everything already queued. It is
// idempotent and safe to call from a shutdown path that may run twice.
func (r *AuditRecorder) Close() {
	r.closeOnce.Do(func() {
		close(r.events)
		close(r.done)
	})
	r.wg.Wait()
}

// --- Reading the log -------------------------------------------------------

// AuditFilter narrows an audit query. Every field is optional.
type AuditFilter struct {
	Action       string
	ActorUserID  *uuid.UUID
	ResourceType string
	ResourceID   *uuid.UUID
	// Cursor fields for keyset pagination, taken from the last row of the
	// previous page.
	BeforeCreatedAt *time.Time
	BeforeID        *uuid.UUID
	Limit           int32
}

// AuditPage is one page of audit entries plus the cursor for the next page.
type AuditPage struct {
	Entries []domain.AuditEntry `json:"entries"`
	// NextCursor is empty when there are no further pages.
	NextCursor string `json:"nextCursor,omitempty"`
}

const (
	defaultAuditLimit = 50
	maxAuditLimit     = 200
)

// AuditService reads the audit log.
type AuditService struct {
	store *Store
	authz *Authorizer
}

// NewAuditService builds an AuditService.
func NewAuditService(store *Store, authz *Authorizer) *AuditService {
	return &AuditService{store: store, authz: authz}
}

// List returns a page of audit entries for a workspace. Any member may read
// the log: knowing who changed what is exactly the transparency the log is
// for, and entries never contain secret values.
func (s *AuditService) List(ctx context.Context, userID, workspaceID uuid.UUID, filter AuditFilter) (*AuditPage, error) {
	if _, err := s.authz.RequireWorkspaceRole(ctx, userID, workspaceID, domain.RoleViewer); err != nil {
		return nil, err
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = defaultAuditLimit
	}
	if limit > maxAuditLimit {
		limit = maxAuditLimit
	}

	params := sqlcgen.ListAuditLogsParams{
		WorkspaceID: workspaceID,
		// One extra row tells us whether another page exists without a
		// separate count query.
		Limit:       limit + 1,
		ActorUserID: filter.ActorUserID,
		ResourceID:  filter.ResourceID,
		BeforeID:    filter.BeforeID,
	}
	if filter.Action != "" {
		params.Action = &filter.Action
	}
	if filter.ResourceType != "" {
		params.ResourceType = &filter.ResourceType
	}
	if filter.BeforeCreatedAt != nil {
		params.BeforeCreatedAt = filter.BeforeCreatedAt
	}

	rows, err := s.store.Queries().ListAuditLogs(ctx, params)
	if err != nil {
		return nil, translateDBError(err, "list audit logs")
	}

	page := &AuditPage{Entries: make([]domain.AuditEntry, 0, limit)}

	hasMore := int32(len(rows)) > limit
	if hasMore {
		rows = rows[:limit]
	}

	for _, row := range rows {
		entry := domain.AuditEntry{
			ID:           row.ID,
			WorkspaceID:  row.WorkspaceID,
			ActorUserID:  row.ActorUserID,
			ActorEmail:   row.ActorEmail,
			ActorTokenID: row.ActorTokenID,
			ActorTokenNm: row.ActorTokenName,
			Action:       row.Action,
			ResourceType: row.ResourceType,
			ResourceID:   row.ResourceID,
			IPAddress:    row.IpAddress,
			UserAgent:    row.UserAgent,
			CreatedAt:    row.CreatedAt,
		}
		if len(row.Metadata) > 0 {
			var metadata map[string]any
			if err := json.Unmarshal(row.Metadata, &metadata); err == nil {
				entry.Metadata = metadata
			}
		}
		page.Entries = append(page.Entries, entry)
	}

	if hasMore && len(page.Entries) > 0 {
		last := page.Entries[len(page.Entries)-1]
		page.NextCursor = EncodeAuditCursor(last.CreatedAt, last.ID)
	}

	return page, nil
}

// Actions lists the distinct actions recorded in a workspace, for populating
// the activity feed's filter without hardcoding the set.
func (s *AuditService) Actions(ctx context.Context, userID, workspaceID uuid.UUID) ([]string, error) {
	if _, err := s.authz.RequireWorkspaceRole(ctx, userID, workspaceID, domain.RoleViewer); err != nil {
		return nil, err
	}
	actions, err := s.store.Queries().ListAuditActions(ctx, workspaceID)
	if err != nil {
		return nil, translateDBError(err, "list audit actions")
	}
	return actions, nil
}

// auditCursor is the opaque pagination cursor handed to clients.
type auditCursor struct {
	CreatedAt time.Time `json:"t"`
	ID        uuid.UUID `json:"i"`
}

// EncodeAuditCursor packs a page boundary into an opaque string.
func EncodeAuditCursor(createdAt time.Time, id uuid.UUID) string {
	encoded, err := json.Marshal(auditCursor{CreatedAt: createdAt, ID: id})
	if err != nil {
		return ""
	}
	return base64Encode(encoded)
}

// DecodeAuditCursor unpacks a cursor produced by EncodeAuditCursor. A cursor
// that does not decode is reported as a validation error rather than being
// ignored, so a client bug surfaces instead of silently paging from the start.
func DecodeAuditCursor(cursor string) (*time.Time, *uuid.UUID, error) {
	if cursor == "" {
		return nil, nil, nil
	}
	raw, err := base64Decode(cursor)
	if err != nil {
		return nil, nil, domain.NewValidationError("cursor", "is not a valid pagination cursor")
	}
	var decoded auditCursor
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, nil, domain.NewValidationError("cursor", "is not a valid pagination cursor")
	}
	return &decoded.CreatedAt, &decoded.ID, nil
}
