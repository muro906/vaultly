package service

import (
	"context"
	"fmt"
	"runtime"
	"sort"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"

	"vaultly/backend/internal/crypto"
	"vaultly/backend/internal/db/sqlcgen"
	"vaultly/backend/internal/domain"
)

// decryptConcurrency bounds how many values are decrypted in parallel.
//
// Decryption is CPU-bound, so the useful ceiling is the number of cores;
// beyond that, goroutines only add scheduling overhead and memory holding
// plaintext. The bound also caps how much plaintext exists at once.
var decryptConcurrency = max(2, runtime.NumCPU())

// SecretService manages secrets, their values and their history.
type SecretService struct {
	store   *Store
	authz   *Authorizer
	keyring *crypto.Keyring
	audit   *AuditRecorder
}

// NewSecretService builds a SecretService.
func NewSecretService(store *Store, authz *Authorizer, keyring *crypto.Keyring, audit *AuditRecorder) *SecretService {
	return &SecretService{store: store, authz: authz, keyring: keyring, audit: audit}
}

// List returns the secrets in an environment as metadata only.
//
// Values are deliberately excluded. Revealing one is a separate request that
// is individually authorised and individually audited, which is what makes
// "who accessed what" answerable at all.
func (s *SecretService) List(ctx context.Context, userID, environmentID uuid.UUID) ([]domain.Secret, error) {
	if _, err := s.authz.RequireEnvironmentRole(ctx, userID, environmentID, domain.RoleViewer); err != nil {
		return nil, err
	}

	rows, err := s.store.Queries().ListSecrets(ctx, environmentID)
	if err != nil {
		return nil, translateDBError(err, "list secrets")
	}

	secrets := make([]domain.Secret, 0, len(rows))
	for _, row := range rows {
		secrets = append(secrets, domain.Secret{
			ID:             row.ID,
			ProjectID:      row.ProjectID,
			EnvironmentID:  row.EnvironmentID,
			Key:            row.Key,
			Description:    row.Description,
			CurrentVersion: row.CurrentVersion,
			CreatedAt:      row.CreatedAt,
			UpdatedAt:      row.UpdatedAt,
			UpdatedBy:      row.UpdatedBy,
		})
	}
	return secrets, nil
}

// Reveal returns a secret's current value.
//
// This is the one path that hands back plaintext to a human, so it requires
// member and is always audited, including the key that was read.
func (s *SecretService) Reveal(ctx context.Context, userID, secretID uuid.UUID, actor Actor) (*domain.Secret, error) {
	scope, err := s.authz.RequireSecretRole(ctx, userID, secretID, domain.RoleMember)
	if err != nil {
		return nil, err
	}

	secret, err := s.getSecret(ctx, secretID)
	if err != nil {
		return nil, err
	}

	version, err := s.store.Queries().GetCurrentSecretVersion(ctx, secretID)
	if err != nil {
		if isNoRows(err) {
			return nil, fmt.Errorf("secret has no versions: %w", domain.ErrNotFound)
		}
		return nil, translateDBError(err, "get current version")
	}

	plaintext, err := s.decrypt(secret, version.WrappedDek, version.Nonce, version.Ciphertext)
	if err != nil {
		return nil, err
	}

	s.audit.Record(Event{
		WorkspaceID:  scope.WorkspaceID,
		Actor:        actor,
		Action:       domain.ActionSecretRead,
		ResourceType: "secret",
		ResourceID:   &secretID,
		Metadata:     map[string]any{"key": secret.Key, "version": version.Version},
	})

	secret.Value = &plaintext
	return secret, nil
}

// Get returns a secret's metadata without its value. Viewers may call it,
// since it reveals nothing that the environment listing does not already show.
func (s *SecretService) Get(ctx context.Context, userID, secretID uuid.UUID) (*domain.Secret, error) {
	if _, err := s.authz.RequireSecretRole(ctx, userID, secretID, domain.RoleViewer); err != nil {
		return nil, err
	}
	return s.getSecret(ctx, secretID)
}

// CreateSecretInput is the payload for creating a secret.
type CreateSecretInput struct {
	EnvironmentID uuid.UUID
	Key           string
	Value         string
	Description   string
	Actor         Actor
}

// Create stores a new secret and its first version.
func (s *SecretService) Create(ctx context.Context, userID uuid.UUID, in CreateSecretInput) (*domain.Secret, error) {
	scope, err := s.authz.RequireEnvironmentRole(ctx, userID, in.EnvironmentID, domain.RoleMember)
	if err != nil {
		return nil, err
	}

	v := &domain.ValidationError{}
	key := validateSecretKey(v, in.Key)
	validateSecretValue(v, in.Value)
	description := validateDescription(v, "description", in.Description)
	if err := v.ErrorOrNil(); err != nil {
		return nil, err
	}

	exists, err := s.store.Queries().SecretKeyExists(ctx, sqlcgen.SecretKeyExistsParams{
		EnvironmentID: in.EnvironmentID,
		Key:           key,
	})
	if err != nil {
		return nil, translateDBError(err, "check secret key")
	}
	if exists {
		return nil, domain.NewValidationError("key", "already exists in this environment")
	}

	// Encrypting under the identity of the secret means the ciphertext is
	// bound to this project, environment and key from the moment it is written.
	sealed, err := s.keyring.Encrypt(
		[]byte(in.Value),
		crypto.SecretAAD(scope.ProjectID.String(), in.EnvironmentID.String(), key),
	)
	if err != nil {
		return nil, fmt.Errorf("encrypt secret: %w", err)
	}

	var secret domain.Secret
	err = s.store.InTx(ctx, func(q *sqlcgen.Queries) error {
		created, err := q.CreateSecret(ctx, sqlcgen.CreateSecretParams{
			ProjectID:     scope.ProjectID,
			EnvironmentID: in.EnvironmentID,
			Key:           key,
			Description:   description,
			UpdatedBy:     &userID,
		})
		if err != nil {
			return translateDBError(err, "create secret")
		}

		secret = domain.Secret{
			ID:             created.ID,
			ProjectID:      created.ProjectID,
			EnvironmentID:  created.EnvironmentID,
			Key:            created.Key,
			Description:    created.Description,
			CurrentVersion: 1,
			CreatedAt:      created.CreatedAt,
			UpdatedAt:      created.UpdatedAt,
			UpdatedBy:      created.UpdatedBy,
		}

		if _, err := q.CreateSecretVersion(ctx, sqlcgen.CreateSecretVersionParams{
			SecretID:   created.ID,
			Version:    1,
			WrappedDek: sealed.WrappedDEK,
			Nonce:      sealed.Nonce,
			Ciphertext: sealed.Ciphertext,
			Comment:    "created",
			CreatedBy:  &userID,
		}); err != nil {
			return translateDBError(err, "create secret version")
		}

		if _, err := q.BumpSecretVersionUnchecked(ctx, sqlcgen.BumpSecretVersionUncheckedParams{
			ID:        created.ID,
			UpdatedBy: &userID,
		}); err != nil {
			return translateDBError(err, "set current version")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	s.audit.Record(Event{
		WorkspaceID:  scope.WorkspaceID,
		Actor:        in.Actor,
		Action:       domain.ActionSecretCreated,
		ResourceType: "secret",
		ResourceID:   &secret.ID,
		Metadata:     map[string]any{"key": key, "environment_id": in.EnvironmentID},
	})

	return &secret, nil
}

// UpdateSecretInput is the payload for changing a secret's value.
type UpdateSecretInput struct {
	SecretID uuid.UUID
	Value    string
	Comment  string
	// ExpectedVersion enables optimistic concurrency. When non-zero, the write
	// only lands if it is still the current version, so two people editing the
	// same secret cannot silently overwrite each other.
	ExpectedVersion int32
	Actor           Actor
}

// Update appends a new version holding the new value.
//
// The previous version is left untouched: history is append-only, which is
// what makes rollback and the diff view possible.
func (s *SecretService) Update(ctx context.Context, userID uuid.UUID, in UpdateSecretInput) (*domain.Secret, error) {
	scope, err := s.authz.RequireSecretRole(ctx, userID, in.SecretID, domain.RoleMember)
	if err != nil {
		return nil, err
	}

	v := &domain.ValidationError{}
	validateSecretValue(v, in.Value)
	comment := in.Comment
	if len(comment) > maxCommentLen {
		v.Add("comment", "is too long")
	}
	if err := v.ErrorOrNil(); err != nil {
		return nil, err
	}

	secret, err := s.getSecret(ctx, in.SecretID)
	if err != nil {
		return nil, err
	}

	sealed, err := s.keyring.Encrypt(
		[]byte(in.Value),
		crypto.SecretAAD(secret.ProjectID.String(), secret.EnvironmentID.String(), secret.Key),
	)
	if err != nil {
		return nil, fmt.Errorf("encrypt secret: %w", err)
	}

	if comment == "" {
		comment = "updated"
	}

	var newVersion int32
	err = s.store.InTx(ctx, func(q *sqlcgen.Queries) error {
		// Bumping first takes the row lock, which serialises concurrent writers
		// and makes the expected-version check meaningful.
		var err error
		if in.ExpectedVersion > 0 {
			newVersion, err = q.BumpSecretVersion(ctx, sqlcgen.BumpSecretVersionParams{
				ID:             in.SecretID,
				CurrentVersion: in.ExpectedVersion,
				UpdatedBy:      &userID,
			})
			if isNoRows(err) {
				return fmt.Errorf("secret has changed since version %d: %w",
					in.ExpectedVersion, domain.ErrVersionMismatch)
			}
		} else {
			newVersion, err = q.BumpSecretVersionUnchecked(ctx, sqlcgen.BumpSecretVersionUncheckedParams{
				ID:        in.SecretID,
				UpdatedBy: &userID,
			})
			if isNoRows(err) {
				return domain.ErrNotFound
			}
		}
		if err != nil {
			return translateDBError(err, "bump secret version")
		}

		if _, err := q.CreateSecretVersion(ctx, sqlcgen.CreateSecretVersionParams{
			SecretID:   in.SecretID,
			Version:    newVersion,
			WrappedDek: sealed.WrappedDEK,
			Nonce:      sealed.Nonce,
			Ciphertext: sealed.Ciphertext,
			Comment:    comment,
			CreatedBy:  &userID,
		}); err != nil {
			return translateDBError(err, "create secret version")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	s.audit.Record(Event{
		WorkspaceID:  scope.WorkspaceID,
		Actor:        in.Actor,
		Action:       domain.ActionSecretUpdated,
		ResourceType: "secret",
		ResourceID:   &in.SecretID,
		Metadata:     map[string]any{"key": secret.Key, "version": newVersion},
	})

	secret.CurrentVersion = newVersion
	return secret, nil
}

// UpdateDescription changes a secret's description without touching its value,
// so it does not create a version.
func (s *SecretService) UpdateDescription(ctx context.Context, userID, secretID uuid.UUID, description string) error {
	if _, err := s.authz.RequireSecretRole(ctx, userID, secretID, domain.RoleMember); err != nil {
		return err
	}

	v := &domain.ValidationError{}
	description = validateDescription(v, "description", description)
	if err := v.ErrorOrNil(); err != nil {
		return err
	}

	return translateDBError(s.store.Queries().UpdateSecretDescription(ctx,
		sqlcgen.UpdateSecretDescriptionParams{ID: secretID, Description: description}),
		"update description")
}

// Delete soft-deletes a secret, leaving its history intact.
func (s *SecretService) Delete(ctx context.Context, userID, secretID uuid.UUID, actor Actor) error {
	scope, err := s.authz.RequireSecretRole(ctx, userID, secretID, domain.RoleMember)
	if err != nil {
		return err
	}

	secret, err := s.getSecret(ctx, secretID)
	if err != nil {
		return err
	}

	if err := s.store.Queries().SoftDeleteSecret(ctx, sqlcgen.SoftDeleteSecretParams{
		ID:        secretID,
		UpdatedBy: &userID,
	}); err != nil {
		return translateDBError(err, "delete secret")
	}

	s.audit.Record(Event{
		WorkspaceID:  scope.WorkspaceID,
		Actor:        actor,
		Action:       domain.ActionSecretDeleted,
		ResourceType: "secret",
		ResourceID:   &secretID,
		Metadata:     map[string]any{"key": secret.Key},
	})
	return nil
}

// ListVersions returns a secret's history as metadata only. Viewers may see
// that a secret changed and who changed it without seeing any value.
func (s *SecretService) ListVersions(ctx context.Context, userID, secretID uuid.UUID) ([]domain.SecretVersion, error) {
	if _, err := s.authz.RequireSecretRole(ctx, userID, secretID, domain.RoleViewer); err != nil {
		return nil, err
	}

	rows, err := s.store.Queries().ListSecretVersions(ctx, secretID)
	if err != nil {
		return nil, translateDBError(err, "list versions")
	}

	versions := make([]domain.SecretVersion, 0, len(rows))
	for _, row := range rows {
		versions = append(versions, domain.SecretVersion{
			ID:             row.ID,
			SecretID:       row.SecretID,
			Version:        row.Version,
			Comment:        row.Comment,
			CreatedAt:      row.CreatedAt,
			CreatedBy:      row.CreatedBy,
			CreatedByEmail: row.CreatedByEmail,
		})
	}
	return versions, nil
}

// RevealVersion returns the value stored at a specific version, which is what
// the diff view compares.
func (s *SecretService) RevealVersion(ctx context.Context, userID, secretID uuid.UUID, version int32, actor Actor) (*domain.SecretVersion, error) {
	scope, err := s.authz.RequireSecretRole(ctx, userID, secretID, domain.RoleMember)
	if err != nil {
		return nil, err
	}

	secret, err := s.getSecret(ctx, secretID)
	if err != nil {
		return nil, err
	}

	row, err := s.store.Queries().GetSecretVersion(ctx, sqlcgen.GetSecretVersionParams{
		SecretID: secretID,
		Version:  version,
	})
	if err != nil {
		if isNoRows(err) {
			return nil, domain.ErrNotFound
		}
		return nil, translateDBError(err, "get version")
	}

	plaintext, err := s.decrypt(secret, row.WrappedDek, row.Nonce, row.Ciphertext)
	if err != nil {
		return nil, err
	}

	s.audit.Record(Event{
		WorkspaceID:  scope.WorkspaceID,
		Actor:        actor,
		Action:       domain.ActionSecretRead,
		ResourceType: "secret",
		ResourceID:   &secretID,
		Metadata:     map[string]any{"key": secret.Key, "version": version},
	})

	return &domain.SecretVersion{
		ID:        row.ID,
		SecretID:  row.SecretID,
		Version:   row.Version,
		Comment:   row.Comment,
		CreatedAt: row.CreatedAt,
		CreatedBy: row.CreatedBy,
		Value:     &plaintext,
	}, nil
}

// Rollback restores an earlier version's value.
//
// It appends the old value as a new version rather than moving the pointer
// backwards, so the rollback itself appears in the history and can in turn be
// rolled back.
func (s *SecretService) Rollback(ctx context.Context, userID, secretID uuid.UUID, targetVersion int32, actor Actor) (*domain.Secret, error) {
	scope, err := s.authz.RequireSecretRole(ctx, userID, secretID, domain.RoleMember)
	if err != nil {
		return nil, err
	}

	secret, err := s.getSecret(ctx, secretID)
	if err != nil {
		return nil, err
	}
	if targetVersion == secret.CurrentVersion {
		return nil, domain.NewValidationError("version", "is already the current version")
	}

	target, err := s.store.Queries().GetSecretVersion(ctx, sqlcgen.GetSecretVersionParams{
		SecretID: secretID,
		Version:  targetVersion,
	})
	if err != nil {
		if isNoRows(err) {
			return nil, domain.ErrNotFound
		}
		return nil, translateDBError(err, "get target version")
	}

	// The ciphertext is copied verbatim: it is already sealed under this
	// secret's identity, so there is no need to decrypt and re-encrypt, and
	// not doing so keeps the plaintext out of this process entirely.
	var newVersion int32
	err = s.store.InTx(ctx, func(q *sqlcgen.Queries) error {
		var err error
		newVersion, err = q.BumpSecretVersionUnchecked(ctx, sqlcgen.BumpSecretVersionUncheckedParams{
			ID:        secretID,
			UpdatedBy: &userID,
		})
		if isNoRows(err) {
			return domain.ErrNotFound
		}
		if err != nil {
			return translateDBError(err, "bump secret version")
		}

		_, err = q.CreateSecretVersion(ctx, sqlcgen.CreateSecretVersionParams{
			SecretID:   secretID,
			Version:    newVersion,
			WrappedDek: target.WrappedDek,
			Nonce:      target.Nonce,
			Ciphertext: target.Ciphertext,
			Comment:    fmt.Sprintf("rolled back to version %d", targetVersion),
			CreatedBy:  &userID,
		})
		return translateDBError(err, "create secret version")
	})
	if err != nil {
		return nil, err
	}

	s.audit.Record(Event{
		WorkspaceID:  scope.WorkspaceID,
		Actor:        actor,
		Action:       domain.ActionSecretRolledBack,
		ResourceType: "secret",
		ResourceID:   &secretID,
		Metadata: map[string]any{
			"key":             secret.Key,
			"from_version":    secret.CurrentVersion,
			"to_version":      targetVersion,
			"created_version": newVersion,
		},
	})

	secret.CurrentVersion = newVersion
	return secret, nil
}

// resolvedSecret is one decrypted key/value pair.
type resolvedSecret struct {
	SecretID uuid.UUID
	Key      string
	Value    string
	Version  int32
}

// resolveEnvironmentValues decrypts every current value in an environment.
//
// The decryptions are independent and CPU-bound, so they run across a bounded
// worker pool rather than one after another. errgroup propagates the first
// failure and cancels the rest, so one corrupt row does not leave the others
// grinding away.
func (s *SecretService) resolveEnvironmentValues(ctx context.Context, projectID, environmentID uuid.UUID) ([]resolvedSecret, error) {
	rows, err := s.store.Queries().ListCurrentSecretValues(ctx, environmentID)
	if err != nil {
		return nil, translateDBError(err, "list secret values")
	}
	if len(rows) == 0 {
		return nil, nil
	}

	resolved := make([]resolvedSecret, len(rows))

	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(decryptConcurrency)

	for i, row := range rows {
		group.Go(func() error {
			// Cancellation is checked before doing the work, so a failure
			// elsewhere stops the remaining decryptions promptly.
			if err := groupCtx.Err(); err != nil {
				return err
			}

			plaintext, err := s.keyring.Decrypt(
				&crypto.Sealed{
					WrappedDEK: row.WrappedDek,
					Nonce:      row.Nonce,
					Ciphertext: row.Ciphertext,
				},
				crypto.SecretAAD(projectID.String(), environmentID.String(), row.Key),
			)
			if err != nil {
				return fmt.Errorf("decrypt %q: %w", row.Key, err)
			}

			// Each goroutine owns exactly one slot, so no synchronisation is
			// needed around the shared slice.
			resolved[i] = resolvedSecret{
				SecretID: row.SecretID,
				Key:      row.Key,
				Value:    string(plaintext),
				Version:  row.Version,
			}
			crypto.Zero(plaintext)
			return nil
		})
	}

	if err := group.Wait(); err != nil {
		return nil, err
	}

	sort.Slice(resolved, func(i, j int) bool { return resolved[i].Key < resolved[j].Key })
	return resolved, nil
}

// getSecret loads a secret's metadata.
func (s *SecretService) getSecret(ctx context.Context, secretID uuid.UUID) (*domain.Secret, error) {
	row, err := s.store.Queries().GetSecret(ctx, secretID)
	if err != nil {
		if isNoRows(err) {
			return nil, domain.ErrNotFound
		}
		return nil, translateDBError(err, "get secret")
	}
	return &domain.Secret{
		ID:             row.ID,
		ProjectID:      row.ProjectID,
		EnvironmentID:  row.EnvironmentID,
		Key:            row.Key,
		Description:    row.Description,
		CurrentVersion: row.CurrentVersion,
		CreatedAt:      row.CreatedAt,
		UpdatedAt:      row.UpdatedAt,
		UpdatedBy:      row.UpdatedBy,
	}, nil
}

// decrypt opens one stored version under the secret's identity.
func (s *SecretService) decrypt(secret *domain.Secret, wrappedDEK, nonce, ciphertext []byte) (string, error) {
	plaintext, err := s.keyring.Decrypt(
		&crypto.Sealed{WrappedDEK: wrappedDEK, Nonce: nonce, Ciphertext: ciphertext},
		crypto.SecretAAD(secret.ProjectID.String(), secret.EnvironmentID.String(), secret.Key),
	)
	if err != nil {
		// A decryption failure here means the master key does not match the
		// data, or a row has been tampered with. Both are operational faults
		// rather than anything the caller did wrong.
		return "", fmt.Errorf("decrypt secret %q: %w", secret.Key, err)
	}
	defer crypto.Zero(plaintext)
	return string(plaintext), nil
}
