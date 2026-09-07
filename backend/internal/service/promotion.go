package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"vaultly/backend/internal/crypto"
	"vaultly/backend/internal/db/sqlcgen"
	"vaultly/backend/internal/domain"
)

// PromotionService copies secret values along a project's promotion path.
type PromotionService struct {
	store    *Store
	authz    *Authorizer
	secrets  *SecretService
	projects *ProjectService
	keyring  *crypto.Keyring
	audit    *AuditRecorder
}

// NewPromotionService builds a PromotionService.
func NewPromotionService(store *Store, authz *Authorizer, secrets *SecretService, projects *ProjectService, keyring *crypto.Keyring, audit *AuditRecorder) *PromotionService {
	return &PromotionService{
		store:    store,
		authz:    authz,
		secrets:  secrets,
		projects: projects,
		keyring:  keyring,
		audit:    audit,
	}
}

// PromoteInput is the payload for a promotion.
type PromoteInput struct {
	ProjectID     uuid.UUID
	SourceEnvID   uuid.UUID
	TargetEnvID   uuid.UUID
	DryRun        bool
	IncludeValues bool
	// Keys optionally restricts the promotion to a subset. Empty promotes
	// every key in the source environment.
	Keys  []string
	Actor Actor
}

// Promote copies values from one environment to another.
//
// With DryRun it computes the plan and changes nothing, which is what the UI
// shows before asking for confirmation. Without it, the same plan is applied
// in a single transaction, so a promotion is all-or-nothing: a target
// environment is never left half-updated.
func (s *PromotionService) Promote(ctx context.Context, userID uuid.UUID, in PromoteInput) (*domain.PromotionPlan, error) {
	// A dry run reveals which values differ, so it needs the same authority as
	// applying one.
	scope, err := s.authz.RequireProjectRole(ctx, userID, in.ProjectID, domain.RoleMember)
	if err != nil {
		return nil, err
	}

	if in.SourceEnvID == in.TargetEnvID {
		return nil, domain.NewValidationError("targetEnvironmentId", "must differ from the source environment")
	}

	source, err := s.projects.resolveEnvironment(ctx, in.ProjectID, in.SourceEnvID)
	if err != nil {
		return nil, err
	}
	target, err := s.projects.resolveEnvironment(ctx, in.ProjectID, in.TargetEnvID)
	if err != nil {
		return nil, err
	}

	// Promotion is directional. Copying production values back down to
	// development would be a plausible mistake with real consequences, so the
	// rank ordering is enforced rather than merely suggested.
	if target.Rank <= source.Rank {
		return nil, domain.NewValidationError("targetEnvironmentId",
			fmt.Sprintf("%q does not come after %q in the promotion path", target.Name, source.Name))
	}

	sourceValues, err := s.secrets.resolveEnvironmentValues(ctx, in.ProjectID, in.SourceEnvID)
	if err != nil {
		return nil, err
	}
	targetValues, err := s.secrets.resolveEnvironmentValues(ctx, in.ProjectID, in.TargetEnvID)
	if err != nil {
		return nil, err
	}

	targetByKey := make(map[string]resolvedSecret, len(targetValues))
	for _, secret := range targetValues {
		targetByKey[secret.Key] = secret
	}

	wanted := keySet(in.Keys)

	plan := &domain.PromotionPlan{
		SourceEnvironmentID: in.SourceEnvID,
		TargetEnvironmentID: in.TargetEnvID,
		SourceName:          source.Name,
		TargetName:          target.Name,
		DryRun:              in.DryRun,
		Changes:             make([]domain.PromotionChange, 0, len(sourceValues)),
	}

	// toApply holds only the entries that actually change something, so an
	// unchanged key never gets a pointless new version.
	type pending struct {
		source resolvedSecret
		target *resolvedSecret
	}
	toApply := make([]pending, 0, len(sourceValues))

	for _, srcSecret := range sourceValues {
		if wanted != nil && !wanted[srcSecret.Key] {
			continue
		}

		change := domain.PromotionChange{Key: srcSecret.Key, Masked: !in.IncludeValues}

		existing, found := targetByKey[srcSecret.Key]
		switch {
		case !found:
			change.Type = domain.PromotionAdded
		case existing.Value == srcSecret.Value:
			change.Type = domain.PromotionUnchanged
		default:
			change.Type = domain.PromotionChanged
		}

		if in.IncludeValues {
			value := srcSecret.Value
			change.SourceValue = &value
			if found {
				existingValue := existing.Value
				change.TargetValue = &existingValue
			}
		}

		plan.Changes = append(plan.Changes, change)

		if change.Type != domain.PromotionUnchanged {
			entry := pending{source: srcSecret}
			if found {
				entry.target = &existing
			}
			toApply = append(toApply, entry)
		}
	}

	if in.DryRun {
		return plan, nil
	}

	// Values are re-encrypted rather than copied, because the associated data
	// binds a ciphertext to its environment: the source ciphertext simply
	// would not decrypt in the target.
	type sealedEntry struct {
		pending
		sealed *crypto.Sealed
	}
	sealedEntries := make([]sealedEntry, 0, len(toApply))
	for _, entry := range toApply {
		sealed, err := s.keyring.Encrypt(
			[]byte(entry.source.Value),
			crypto.SecretAAD(in.ProjectID.String(), in.TargetEnvID.String(), entry.source.Key),
		)
		if err != nil {
			return nil, fmt.Errorf("encrypt %q for promotion: %w", entry.source.Key, err)
		}
		sealedEntries = append(sealedEntries, sealedEntry{pending: entry, sealed: sealed})
	}

	comment := fmt.Sprintf("promoted from %s", source.Name)

	err = s.store.InTx(ctx, func(q *sqlcgen.Queries) error {
		for _, entry := range sealedEntries {
			secretID := uuid.Nil
			if entry.target != nil {
				secretID = entry.target.SecretID
			} else {
				created, err := q.CreateSecret(ctx, sqlcgen.CreateSecretParams{
					ProjectID:     in.ProjectID,
					EnvironmentID: in.TargetEnvID,
					Key:           entry.source.Key,
					Description:   "",
					UpdatedBy:     &userID,
				})
				if err != nil {
					return translateDBError(err, "create promoted secret")
				}
				secretID = created.ID
			}

			version, err := q.BumpSecretVersionUnchecked(ctx, sqlcgen.BumpSecretVersionUncheckedParams{
				ID:        secretID,
				UpdatedBy: &userID,
			})
			if err != nil {
				return translateDBError(err, "bump promoted secret version")
			}

			if _, err := q.CreateSecretVersion(ctx, sqlcgen.CreateSecretVersionParams{
				SecretID:   secretID,
				Version:    version,
				WrappedDek: entry.sealed.WrappedDEK,
				Nonce:      entry.sealed.Nonce,
				Ciphertext: entry.sealed.Ciphertext,
				Comment:    comment,
				CreatedBy:  &userID,
			}); err != nil {
				return translateDBError(err, "create promoted version")
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	plan.Applied = len(sealedEntries)

	// The keys are recorded but never the values: the audit log must stay safe
	// to read for anyone who can see the activity feed.
	s.audit.Record(Event{
		WorkspaceID:  scope.WorkspaceID,
		Actor:        in.Actor,
		Action:       domain.ActionSecretsPromoted,
		ResourceType: "environment",
		ResourceID:   &in.TargetEnvID,
		Metadata: map[string]any{
			"source":  source.Name,
			"target":  target.Name,
			"applied": plan.Applied,
			"keys":    changedKeys(plan.Changes),
		},
	})

	return plan, nil
}

// keySet turns an optional key filter into a lookup, returning nil when no
// filter was given so that "no filter" and "empty filter" stay distinguishable.
func keySet(keys []string) map[string]bool {
	if len(keys) == 0 {
		return nil
	}
	set := make(map[string]bool, len(keys))
	for _, key := range keys {
		set[key] = true
	}
	return set
}

// changedKeys lists the keys a plan actually writes.
func changedKeys(changes []domain.PromotionChange) []string {
	keys := make([]string, 0, len(changes))
	for _, change := range changes {
		if change.Type != domain.PromotionUnchanged {
			keys = append(keys, change.Key)
		}
	}
	return keys
}
