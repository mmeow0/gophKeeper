package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ajgultumerkina/gophkeeper/internal/protocol"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // Регистрирует pgx-драйвер для database/sql.
)

// Postgres хранит пользователей, хэши токенов и непрозрачные зашифрованные
// конверты в PostgreSQL.
type Postgres struct {
	db *sql.DB
}

// OpenPostgres открывает и проверяет подключение к PostgreSQL-хранилищу.
func OpenPostgres(ctx context.Context, dataSourceName string) (*Postgres, error) {
	db, err := sql.Open("pgx", dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &Postgres{db: db}, nil
}

// Close освобождает ресурсы PostgreSQL-подключения.
func (p *Postgres) Close() error {
	return p.db.Close()
}

// CreateUser в транзакции сохраняет аккаунт и начальный курсор ревизий.
func (p *Postgres) CreateUser(ctx context.Context, user User) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO users
			(id, username, auth_salt, kdf_time, kdf_memory, kdf_parallelism, kdf_key_length,
			 auth_verifier, wrapped_vault_key, wrap_nonce, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		user.ID, user.Username, user.AuthSalt, user.KDF.Time, user.KDF.Memory,
		user.KDF.Parallelism, user.KDF.KeyLength, user.AuthVerifier,
		user.WrappedVaultKey, user.WrapNonce, user.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrAlreadyExists
		}
		return fmt.Errorf("insert user: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO vaults (user_id, current_revision) VALUES ($1, 0)`, user.ID); err != nil {
		return fmt.Errorf("insert vault: %w", err)
	}
	return tx.Commit()
}

// UserByUsername получает данные аутентификации и материал для открытия
// хранилища.
func (p *Postgres) UserByUsername(ctx context.Context, username string) (User, error) {
	var user User
	err := p.db.QueryRowContext(ctx, `
		SELECT id, username, auth_salt, kdf_time, kdf_memory, kdf_parallelism,
		       kdf_key_length, auth_verifier, wrapped_vault_key, wrap_nonce, created_at
		FROM users WHERE username=$1`, username).Scan(
		&user.ID, &user.Username, &user.AuthSalt, &user.KDF.Time, &user.KDF.Memory,
		&user.KDF.Parallelism, &user.KDF.KeyLength, &user.AuthVerifier,
		&user.WrappedVaultKey, &user.WrapNonce, &user.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("find user: %w", err)
	}
	return user, nil
}

// CreateSession сохраняет только хэши токенов, а не открытые bearer-токены.
func (p *Postgres) CreateSession(ctx context.Context, session Session) error {
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO sessions
			(id, user_id, access_token_hash, refresh_token_hash, access_expires_at,
			 refresh_expires_at, device_name, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		session.ID, session.UserID, session.AccessTokenHash, session.RefreshTokenHash,
		session.AccessExpiresAt, session.RefreshExpiresAt, session.DeviceName, session.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return nil
}

// SessionByAccessHash получает сессию по хэшу access-токена.
func (p *Postgres) SessionByAccessHash(ctx context.Context, hash []byte) (Session, error) {
	return p.sessionByHash(ctx, "access_token_hash", hash)
}

// SessionByRefreshHash получает сессию по хэшу refresh-токена.
func (p *Postgres) SessionByRefreshHash(ctx context.Context, hash []byte) (Session, error) {
	return p.sessionByHash(ctx, "refresh_token_hash", hash)
}

// RevokeSession запрещает дальнейшее использование токенов этой сессии.
func (p *Postgres) RevokeSession(ctx context.Context, id string, now time.Time) error {
	result, err := p.db.ExecContext(ctx, `UPDATE sessions SET revoked_at=$2 WHERE id=$1 AND revoked_at IS NULL`, id, now)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

// GetItem получает текущий зашифрованный конверт по владельцу и идентификатору.
func (p *Postgres) GetItem(ctx context.Context, userID, itemID string) (protocol.EncryptedItem, error) {
	var item protocol.EncryptedItem
	err := p.db.QueryRowContext(ctx, `
		SELECT item_id, item_version, revision, crypto_version, nonce, ciphertext, deleted, updated_at
		FROM items WHERE user_id=$1 AND item_id=$2`, userID, itemID).Scan(
		&item.ID, &item.Version, &item.Revision, &item.CryptoVersion, &item.Nonce,
		&item.Ciphertext, &item.Deleted, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return protocol.EncryptedItem{}, ErrNotFound
	}
	if err != nil {
		return protocol.EncryptedItem{}, fmt.Errorf("get item: %w", err)
	}
	return item, nil
}

// PutItem записывает конверт и продвигает ревизию синхронизации владельца.
func (p *Postgres) PutItem(ctx context.Context, userID, itemID string, baseVersion int64, incoming protocol.EncryptedItem, now time.Time) (protocol.EncryptedItem, error) {
	tx, revision, err := p.beginRevision(ctx, userID)
	if err != nil {
		return protocol.EncryptedItem{}, err
	}
	defer tx.Rollback()
	var current int64
	err = tx.QueryRowContext(ctx, `SELECT item_version FROM items WHERE user_id=$1 AND item_id=$2`, userID, itemID).Scan(&current)
	switch {
	case errors.Is(err, sql.ErrNoRows) && baseVersion != 0:
		return protocol.EncryptedItem{}, ErrConflict
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return protocol.EncryptedItem{}, fmt.Errorf("read item version: %w", err)
	case current != baseVersion:
		return protocol.EncryptedItem{}, ErrConflict
	}
	incoming.ID = itemID
	incoming.Version = baseVersion + 1
	incoming.Revision = revision
	incoming.UpdatedAt = now
	_, err = tx.ExecContext(ctx, `
		INSERT INTO items
			(user_id,item_id,item_version,revision,crypto_version,nonce,ciphertext,deleted,updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,false,$8)
		ON CONFLICT (user_id,item_id) DO UPDATE SET
			item_version=EXCLUDED.item_version, revision=EXCLUDED.revision,
			crypto_version=EXCLUDED.crypto_version, nonce=EXCLUDED.nonce,
			ciphertext=EXCLUDED.ciphertext, deleted=false, updated_at=EXCLUDED.updated_at`,
		userID, itemID, incoming.Version, incoming.Revision, incoming.CryptoVersion,
		incoming.Nonce, incoming.Ciphertext, now)
	if err != nil {
		return protocol.EncryptedItem{}, fmt.Errorf("put item: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return protocol.EncryptedItem{}, err
	}
	return incoming, nil
}

// DeleteItem очищает зашифрованное содержимое и сохраняет синхронизируемую
// метку удаления.
func (p *Postgres) DeleteItem(ctx context.Context, userID, itemID string, baseVersion int64, now time.Time) (protocol.EncryptedItem, error) {
	tx, revision, err := p.beginRevision(ctx, userID)
	if err != nil {
		return protocol.EncryptedItem{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
		UPDATE items SET item_version=item_version+1, revision=$4, crypto_version=0,
		       nonce=NULL, ciphertext=NULL, deleted=true, updated_at=$5
		WHERE user_id=$1 AND item_id=$2 AND item_version=$3 AND deleted=false`,
		userID, itemID, baseVersion, revision, now)
	if err != nil {
		return protocol.EncryptedItem{}, fmt.Errorf("delete item: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		var exists bool
		err := tx.QueryRowContext(ctx, `SELECT true FROM items WHERE user_id=$1 AND item_id=$2 AND deleted=false`, userID, itemID).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			return protocol.EncryptedItem{}, ErrNotFound
		}
		return protocol.EncryptedItem{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return protocol.EncryptedItem{}, err
	}
	return protocol.EncryptedItem{ID: itemID, Version: baseVersion + 1, Revision: revision, Deleted: true, UpdatedAt: now}, nil
}

// Sync возвращает последние состояния записей, изменившихся после клиентского
// курсора.
func (p *Postgres) Sync(ctx context.Context, userID string, after int64, limit int) (protocol.SyncResponse, error) {
	var latest int64
	if err := p.db.QueryRowContext(ctx, `SELECT current_revision FROM vaults WHERE user_id=$1`, userID).Scan(&latest); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return protocol.SyncResponse{}, ErrNotFound
		}
		return protocol.SyncResponse{}, fmt.Errorf("read revision: %w", err)
	}
	rows, err := p.db.QueryContext(ctx, `
		SELECT item_id,item_version,revision,crypto_version,nonce,ciphertext,deleted,updated_at
		FROM items WHERE user_id=$1 AND revision>$2 ORDER BY revision LIMIT $3`, userID, after, limit)
	if err != nil {
		return protocol.SyncResponse{}, fmt.Errorf("sync query: %w", err)
	}
	defer rows.Close()
	response := protocol.SyncResponse{CurrentRevision: latest}
	for rows.Next() {
		var item protocol.EncryptedItem
		if err := rows.Scan(&item.ID, &item.Version, &item.Revision, &item.CryptoVersion, &item.Nonce, &item.Ciphertext, &item.Deleted, &item.UpdatedAt); err != nil {
			return protocol.SyncResponse{}, fmt.Errorf("scan sync item: %w", err)
		}
		response.Items = append(response.Items, item)
	}
	if err := rows.Err(); err != nil {
		return protocol.SyncResponse{}, err
	}
	if len(response.Items) == limit {
		response.CurrentRevision = response.Items[len(response.Items)-1].Revision
	}
	return response, nil
}

func (p *Postgres) sessionByHash(ctx context.Context, column string, hash []byte) (Session, error) {
	var session Session
	query := `SELECT id,user_id,access_token_hash,refresh_token_hash,access_expires_at,
	          refresh_expires_at,device_name,revoked_at,created_at FROM sessions WHERE ` + column + `=$1`
	err := p.db.QueryRowContext(ctx, query, hash).Scan(
		&session.ID, &session.UserID, &session.AccessTokenHash, &session.RefreshTokenHash,
		&session.AccessExpiresAt, &session.RefreshExpiresAt, &session.DeviceName,
		&session.RevokedAt, &session.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("find session: %w", err)
	}
	return session, nil
}

func (p *Postgres) beginRevision(ctx context.Context, userID string) (*sql.Tx, int64, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, 0, err
	}
	var revision int64
	err = tx.QueryRowContext(ctx, `
		UPDATE vaults SET current_revision=current_revision+1
		WHERE user_id=$1 RETURNING current_revision`, userID).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		tx.Rollback()
		return nil, 0, ErrNotFound
	}
	if err != nil {
		tx.Rollback()
		return nil, 0, fmt.Errorf("advance revision: %w", err)
	}
	return tx, revision, nil
}
