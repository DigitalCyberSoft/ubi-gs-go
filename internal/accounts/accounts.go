// Package accounts stores player accounts, login sessions, friends, ladder stats and profile data in
// SQLite. The schema is the reference implementation's, so an existing ubigs.db keeps working.
//
// The first login with a name creates the account. A taken name with a different password gets the next
// free name of its family (name-1, name-2, ...), so nobody is locked out and nobody can use someone
// else's account without its password. Passwords are stored as salted scrypt hashes only.
package accounts

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/scrypt"
	"modernc.org/sqlite" // pure-Go SQLite driver
	sqlite3 "modernc.org/sqlite/lib"
)

// Memory is the database path that keeps everything in memory only.
const Memory = ":memory:"

// NameSize is the longest account name in bytes, suffix included: the game's PLAYERINFO name buffer is
// 12 bytes (0x0042a990).
const NameSize = 11

// SchemaVersion is the database schema this server writes.
const SchemaVersion = 1

// scrypt cost parameters (the reference's: N=2^14, r=8, p=1, 32 bytes).
const (
	scryptN      = 1 << 14
	scryptR      = 8
	scryptP      = 1
	scryptKeyLen = 32
	saltLen      = 16
)

// LoginError is a refused login with the reason the game is sent, from the game's table (0x00b03490).
type LoginError struct {
	Reason uint32
	Name   string
}

func (e *LoginError) Error() string { return e.Name }

// Refusal reasons.
var (
	ErrUsernameMalformed = &LoginError{2, "USERNAME_MALFORMED"}
	ErrPasswordMalformed = &LoginError{11, "PASSWORD_MALFORMED"}
	ErrInvalidPassword   = &LoginError{15, "INVALID_PASSWORD"}
	ErrDatabaseFailed    = &LoginError{100, "DATABASE_FAILED"}
)

// Account is a player account.
type Account struct {
	ID   int64
	Name string
}

// Store is an open accounts database.
type Store struct {
	mu   sync.Mutex
	db   *sql.DB
	path string
	// Logf receives notices such as a corrupt database moved aside.
	Logf func(format string, args ...any)
}

// Open opens (and creates or migrates) the database at path, or an in-memory one for Memory. A file that
// isn't a database, or is damaged, is moved aside (`<path>.corrupt-<time>`) and a new one started. Any other
// failure is returned and the file left alone: one the server may not open, or with a newer schema, would
// otherwise be swapped for an empty database.
func Open(path string, logf func(string, ...any)) (*Store, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	s := &Store{path: path, Logf: logf}
	db, err := openDB(path)
	if err != nil {
		if path == Memory || !damaged(err) {
			return nil, err
		}
		aside := fmt.Sprintf("%s.corrupt-%d", path, time.Now().Unix())
		logf("Accounts database %s is damaged (%v), moved to %s; starting a new one", path, err, aside)
		for _, suffix := range []string{"", "-wal", "-shm"} {
			if _, statErr := os.Stat(path + suffix); statErr == nil {
				if mvErr := os.Rename(path+suffix, aside+suffix); mvErr != nil {
					return nil, fmt.Errorf("moving the unreadable database aside: %w", mvErr)
				}
			}
		}
		if db, err = openDB(path); err != nil {
			return nil, err
		}
	}
	s.db = db
	return s, nil
}

// damaged reports whether SQLite found the file isn't a database or is corrupt, the only failures that
// moving it aside fixes.
func damaged(err error) bool {
	var e *sqlite.Error
	if !errors.As(err, &e) {
		return false
	}
	code := e.Code() & 0xff // the primary code of an extended one
	return code == sqlite3.SQLITE_CORRUPT || code == sqlite3.SQLITE_NOTADB
}

func openDB(path string) (*sql.DB, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(30000)&_pragma=foreign_keys(1)"
	if path == Memory {
		dsn = "file::memory:?_pragma=foreign_keys(1)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// one connection: a memory database lives in its connection, and writes are serialised anyway
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if err := setup(db, path); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func setup(db *sql.DB, path string) error {
	if path != Memory {
		if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
			return err
		}
	}
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > SchemaVersion {
		return fmt.Errorf("database schema %d is newer than this server (%d)", version, SchemaVersion)
	}
	if version < 1 {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		for _, stmt := range schemaV1 {
			if _, err := tx.Exec(stmt); err != nil {
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	// additions the reference implementation ignores, so the schema version stays 1
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS lobby_logins (
        account INTEGER PRIMARY KEY REFERENCES accounts(id),
        last INTEGER NOT NULL
      )`,
		`CREATE TABLE IF NOT EXISTS verifiers (
        account INTEGER PRIMARY KEY REFERENCES accounts(id),
        verifier BLOB NOT NULL
      )`,
		`CREATE TABLE IF NOT EXISTS server (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      )`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

// ServerID returns the server's identity, a random 128-bit value in hex, created on first use and kept
// in the database (an in-memory database gets a new one per run).
func (s *Store) ServerID() (string, error) {
	var id string
	err := s.tx(func(conn *sql.Conn) error {
		ctx := context.Background()
		err := conn.QueryRowContext(ctx, "SELECT value FROM server WHERE key = 'server_id'").Scan(&id)
		if err == nil {
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		id = hex.EncodeToString(b)
		_, err = conn.ExecContext(ctx, "INSERT INTO server (key, value) VALUES ('server_id', ?)", id)
		return err
	})
	return id, err
}

var schemaV1 = []string{
	`CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE COLLATE NOCASE,
        hash BLOB NOT NULL,
        salt BLOB NOT NULL,
        created INTEGER NOT NULL
      )`,
	`CREATE TABLE IF NOT EXISTS sessions (
        typed TEXT NOT NULL COLLATE NOCASE,
        ip TEXT NOT NULL,
        account INTEGER NOT NULL REFERENCES accounts(id),
        updated INTEGER NOT NULL,
        PRIMARY KEY (typed, ip)
      )`,
	`CREATE TABLE IF NOT EXISTS friends (
        account INTEGER NOT NULL REFERENCES accounts(id),
        friend INTEGER NOT NULL REFERENCES accounts(id),
        PRIMARY KEY (account, friend)
      )`,
	`CREATE TABLE IF NOT EXISTS ladder (
        account INTEGER NOT NULL REFERENCES accounts(id),
        game TEXT NOT NULL,
        field TEXT NOT NULL,
        value INTEGER NOT NULL,
        PRIMARY KEY (account, game, field)
      )`,
	`CREATE TABLE IF NOT EXISTS profiles (
        account INTEGER NOT NULL REFERENCES accounts(id),
        game TEXT NOT NULL,
        data BLOB NOT NULL,
        PRIMARY KEY (account, game)
      )`,
	`PRAGMA user_version = 1`,
}

// Path returns the database path.
func (s *Store) Path() string { return s.path }

// Close closes the database (a WAL file is checkpointed).
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// SchemaVersion returns the database's schema version.
func (s *Store) SchemaVersion() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var v int
	err := s.db.QueryRow("PRAGMA user_version").Scan(&v)
	return v, err
}

// tx runs fn in an immediate write transaction (exclusive against other processes on the file).
func (s *Store) tx(fn func(*sql.Conn) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return errors.New("accounts database closed")
	}
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	if err := fn(conn); err != nil {
		conn.ExecContext(ctx, "ROLLBACK")
		return err
	}
	_, err = conn.ExecContext(ctx, "COMMIT")
	if err != nil {
		conn.ExecContext(ctx, "ROLLBACK")
	}
	return err
}

func (s *Store) query(fn func(*sql.DB) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return errors.New("accounts database closed")
	}
	return fn(s.db)
}

// Cut cuts text to at most size bytes, on a UTF-8 character boundary when the text is UTF-8.
func Cut(text string, size int) string {
	if len(text) <= size {
		return text
	}
	cut := text[:size]
	if utf8.ValidString(text) {
		for len(cut) > 0 && !utf8.ValidString(cut) {
			cut = cut[:len(cut)-1]
		}
	}
	return cut
}

// ValidName reports whether a name may be used: not empty, no spaces or control characters.
func ValidName(name string) bool {
	if name == "" {
		return false
	}
	if !utf8.ValidString(name) {
		// the game's own code page: refuse control bytes and spaces, accept the rest
		for i := 0; i < len(name); i++ {
			if c := name[i]; c <= 0x20 || c == 0x7f {
				return false
			}
		}
		return true
	}
	for _, r := range name {
		if !unicode.IsPrint(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// FamilyName returns the k-th name of name's family: name-k, the base cut so the whole fits NameSize.
func FamilyName(name string, k int) string {
	suffix := "-" + strconv.Itoa(k)
	return Cut(name, NameSize-len(suffix)) + suffix
}

// hashInput is the password as the reference implementation hashed it: it read the game's bytes as
// Latin-1 characters and hashed their UTF-8 encoding. Using the same input keeps its accounts working.
func hashInput(password string) []byte {
	out := make([]byte, 0, len(password))
	for i := 0; i < len(password); i++ {
		out = utf8.AppendRune(out, rune(password[i]))
	}
	return out
}

func hashPassword(password string, salt []byte) ([]byte, error) {
	return scrypt.Key(hashInput(password), salt, scryptN, scryptR, scryptP, scryptKeyLen)
}

type row struct {
	id    int64
	name  string
	hash  []byte
	salt  []byte
	token bool // a token account (HommaRe's login challenge)
}

const rowQuery = `SELECT accounts.id, accounts.name, accounts.hash, accounts.salt, verifiers.account IS NOT NULL
  FROM accounts LEFT JOIN verifiers ON verifiers.account = accounts.id WHERE accounts.name = ?`

func getRow(conn *sql.Conn, name string) (*row, error) {
	r := &row{}
	err := conn.QueryRowContext(context.Background(), rowQuery, name).Scan(&r.id, &r.name, &r.hash, &r.salt, &r.token)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return r, err
}

// Login logs in to, or creates, the account for a name and password:
//  1. the account `name` with this password;
//  2. else the first of name-1, name-2, ... with this password;
//  3. else a new account: name if free, else the lowest free name-k.
//
// Names are case-insensitive (ASCII) and at most NameSize bytes.
func (s *Store) Login(name, password string) (Account, error) {
	res, err := s.LoginWith(name, password, LoginOptions{})
	return res.Account, err
}

// LoginOptions hook the server's abuse limits into a login.
type LoginOptions struct {
	// AllowCreate is asked before a new account is created, with the number of stored accounts; an
	// error refuses the login.
	AllowCreate func(stored int64) error
	// Hash runs a password hash; it bounds how many run at once. Nil runs it directly.
	Hash func(fn func())
	// Verifier, if set, makes this a token login (HommaRe's registration): only token accounts match,
	// and a new account is a token account with this verifier. Without it only plain accounts match.
	// The two kinds never convert: a name of the other kind is a collision (name-k).
	Verifier []byte
}

// LoginResult is the outcome of a login.
type LoginResult struct {
	Account Account
	// Created is set for a new account.
	Created bool
	// Taken is set when the typed name belonged to someone else (the password matched no account of
	// the name's family), which is also what a password guess looks like.
	Taken bool
}

func (o LoginOptions) hash(password string, salt []byte) ([]byte, error) {
	var out []byte
	var err error
	run := func() { out, err = hashPassword(password, salt) }
	if o.Hash != nil {
		o.Hash(run)
	} else {
		run()
	}
	return out, err
}

// LoginWith is Login with abuse limits. Passwords are hashed outside the database lock, so logins run
// in parallel up to the Hash bound.
func (s *Store) LoginWith(name, password string, opt LoginOptions) (LoginResult, error) {
	name = Cut(strings.TrimSpace(name), NameSize)
	if !ValidName(name) {
		return LoginResult{}, ErrUsernameMalformed
	}
	if password == "" {
		return LoginResult{}, ErrPasswordMalformed
	}
	fail := func(err error) (LoginResult, error) {
		var le *LoginError
		if errors.As(err, &le) {
			return LoginResult{}, le
		}
		s.Logf("Accounts database error: %v", err)
		return LoginResult{}, ErrDatabaseFailed
	}
	// the existing accounts of the family, without holding the database
	candidate := name
	k := 1
	for ; ; k++ {
		r, err := s.lookup(candidate)
		if err != nil {
			return fail(err)
		}
		if r == nil {
			break
		}
		if r.token == (opt.Verifier != nil) {
			hash, err := opt.hash(password, r.salt)
			if err != nil {
				return fail(err)
			}
			if subtle.ConstantTimeCompare(hash, r.hash) == 1 {
				if opt.Verifier != nil {
					if err := s.SetVerifier(Account{r.id, r.name}, opt.Verifier); err != nil {
						return fail(err)
					}
				}
				return LoginResult{Account: Account{r.id, r.name}}, nil
			}
		}
		candidate = FamilyName(name, k)
	}
	taken := candidate != name
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return fail(err)
	}
	newHash, err := opt.hash(password, salt)
	if err != nil {
		return fail(err)
	}
	var res LoginResult
	err = s.tx(func(conn *sql.Conn) error {
		// another login may have taken the name meanwhile (or created this very account)
		for ; ; k++ {
			r, err := getRow(conn, candidate)
			if err != nil {
				return err
			}
			if r == nil {
				break
			}
			if r.token == (opt.Verifier != nil) {
				hash, err := hashPassword(password, r.salt)
				if err != nil {
					return err
				}
				if subtle.ConstantTimeCompare(hash, r.hash) == 1 {
					res = LoginResult{Account: Account{r.id, r.name}}
					return nil
				}
			}
			candidate = FamilyName(name, k)
			taken = true
		}
		if opt.AllowCreate != nil {
			var stored int64
			if err := conn.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM accounts").Scan(&stored); err != nil {
				return err
			}
			if err := opt.AllowCreate(stored); err != nil {
				return err
			}
		}
		out, err := conn.ExecContext(context.Background(),
			"INSERT INTO accounts (name, hash, salt, created) VALUES (?, ?, ?, ?)", candidate, newHash, salt, time.Now().Unix())
		if err != nil {
			return err
		}
		id, err := out.LastInsertId()
		if err != nil {
			return err
		}
		if opt.Verifier != nil {
			if _, err := conn.ExecContext(context.Background(),
				"INSERT INTO verifiers (account, verifier) VALUES (?, ?)", id, opt.Verifier); err != nil {
				return err
			}
		}
		res = LoginResult{Account: Account{id, candidate}, Created: true, Taken: taken}
		return nil
	})
	if err != nil {
		return fail(err)
	}
	return res, nil
}

func (s *Store) lookup(name string) (*row, error) {
	var out *row
	err := s.query(func(db *sql.DB) error {
		r := &row{}
		err := db.QueryRow(rowQuery, name).Scan(&r.id, &r.name, &r.hash, &r.salt, &r.token)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err == nil {
			out = r
		}
		return err
	})
	return out, err
}

// RecordLobbyLogin notes that the account reached the lobby; accounts that never do can be pruned.
// The table is an addition the reference implementation ignores.
func (s *Store) RecordLobbyLogin(account Account) error {
	return s.tx(func(conn *sql.Conn) error {
		_, err := conn.ExecContext(context.Background(),
			"INSERT OR REPLACE INTO lobby_logins (account, last) VALUES (?, ?)", account.ID, time.Now().Unix())
		return err
	})
}

// PruneUnused deletes accounts created before cutoff that never reached the lobby, with their data.
// It returns how many went.
func (s *Store) PruneUnused(cutoff time.Time) (int64, error) {
	var n int64
	err := s.tx(func(conn *sql.Conn) error {
		ctx := context.Background()
		where := "SELECT id FROM accounts WHERE created < ? AND id NOT IN (SELECT account FROM lobby_logins)"
		for _, table := range []string{"sessions", "ladder", "profiles", "verifiers"} {
			if _, err := conn.ExecContext(ctx, "DELETE FROM "+table+" WHERE account IN ("+where+")", cutoff.Unix()); err != nil {
				return err
			}
		}
		if _, err := conn.ExecContext(ctx, "DELETE FROM friends WHERE account IN ("+where+") OR friend IN ("+where+")",
			cutoff.Unix(), cutoff.Unix()); err != nil {
			return err
		}
		res, err := conn.ExecContext(ctx, "DELETE FROM accounts WHERE created < ? AND id NOT IN (SELECT account FROM lobby_logins)", cutoff.Unix())
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	return n, err
}

// SetVerifier makes the account a token account with the challenge verifier.
func (s *Store) SetVerifier(account Account, verifier []byte) error {
	return s.tx(func(conn *sql.Conn) error {
		_, err := conn.ExecContext(context.Background(),
			"INSERT OR REPLACE INTO verifiers (account, verifier) VALUES (?, ?)", account.ID, verifier)
		return err
	})
}

// TokenAccount is an account with its challenge verifier.
type TokenAccount struct {
	Account
	Verifier []byte
}

// FamilyVerifiers returns the token accounts of a typed name's family (name, name-1, ...), in order.
func (s *Store) FamilyVerifiers(name string) ([]TokenAccount, error) {
	name = Cut(strings.TrimSpace(name), NameSize)
	if !ValidName(name) {
		return nil, ErrUsernameMalformed
	}
	var out []TokenAccount
	err := s.query(func(db *sql.DB) error {
		candidate := name
		for k := 1; ; k++ {
			var t TokenAccount
			var v []byte
			err := db.QueryRow(`SELECT accounts.id, accounts.name, verifiers.verifier FROM accounts
        LEFT JOIN verifiers ON verifiers.account = accounts.id WHERE accounts.name = ?`, candidate).Scan(&t.ID, &t.Name, &v)
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			if v != nil {
				t.Verifier = v
				out = append(out, t)
			}
			candidate = FamilyName(name, k)
		}
	})
	return out, err
}

// Count returns the number of stored accounts.
func (s *Store) Count() (int64, error) {
	var n int64
	err := s.query(func(db *sql.DB) error { return db.QueryRow("SELECT COUNT(*) FROM accounts").Scan(&n) })
	return n, err
}

func (s *Store) accounts(query string, args ...any) ([]Account, error) {
	var out []Account
	err := s.query(func(db *sql.DB) error {
		rows, err := db.Query(query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a Account
			if err := rows.Scan(&a.ID, &a.Name); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

func (s *Store) one(query string, args ...any) (*Account, error) {
	list, err := s.accounts(query, args...)
	if err != nil || len(list) == 0 {
		return nil, err
	}
	return &list[0], nil
}

// Find returns the account of that name (any case), or nil.
func (s *Store) Find(name string) (*Account, error) {
	return s.one("SELECT id, name FROM accounts WHERE name = ?", name)
}

// BindSession records that the game at ip that logged in as typed uses the account. The game keeps the
// typed name in its later connections (proxies, lobby), which find the account with it.
func (s *Store) BindSession(typed, ip string, account Account) error {
	return s.tx(func(conn *sql.Conn) error {
		_, err := conn.ExecContext(context.Background(),
			"INSERT OR REPLACE INTO sessions (typed, ip, account, updated) VALUES (?, ?, ?, ?)",
			typed, ip, account.ID, time.Now().Unix())
		return err
	})
}

// Session returns the account of the game at ip that logged in as typed, or nil.
func (s *Store) Session(typed, ip string) (*Account, error) {
	return s.one(`SELECT accounts.id, accounts.name FROM sessions JOIN accounts ON accounts.id = sessions.account
    WHERE sessions.typed = ? AND sessions.ip = ?`, typed, ip)
}

// AccountName returns the account name of the game at ip that logged in as typed; typed if there's none.
func (s *Store) AccountName(typed, ip string) string {
	a, err := s.Session(typed, ip)
	if err != nil || a == nil {
		return typed
	}
	return a.Name
}

// AddFriend adds friend to the account's friends.
func (s *Store) AddFriend(account, friend Account) error {
	return s.tx(func(conn *sql.Conn) error {
		_, err := conn.ExecContext(context.Background(),
			"INSERT OR IGNORE INTO friends (account, friend) VALUES (?, ?)", account.ID, friend.ID)
		return err
	})
}

// RemoveFriend removes friend from the account's friends.
func (s *Store) RemoveFriend(account, friend Account) error {
	return s.tx(func(conn *sql.Conn) error {
		_, err := conn.ExecContext(context.Background(),
			"DELETE FROM friends WHERE account = ? AND friend = ?", account.ID, friend.ID)
		return err
	})
}

// Friends returns the account's friends, by name.
func (s *Store) Friends(account Account) ([]Account, error) {
	return s.accounts(`SELECT accounts.id, accounts.name FROM friends JOIN accounts ON accounts.id = friends.friend
    WHERE friends.account = ? ORDER BY accounts.name`, account.ID)
}

// FriendOf returns the accounts that have this one as a friend.
func (s *Store) FriendOf(account Account) ([]Account, error) {
	return s.accounts(`SELECT accounts.id, accounts.name FROM friends JOIN accounts ON accounts.id = friends.account
    WHERE friends.friend = ?`, account.ID)
}

// LadderStats returns the account's stored ladder fields.
func (s *Store) LadderStats(account Account, ladder string) (map[string]int64, error) {
	out := map[string]int64{}
	err := s.query(func(db *sql.DB) error {
		rows, err := db.Query("SELECT field, value FROM ladder WHERE account = ? AND game = ?", account.ID, ladder)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var field string
			var value int64
			if err := rows.Scan(&field, &value); err != nil {
				return err
			}
			out[field] = value
		}
		return rows.Err()
	})
	return out, err
}

// SetLadderStats stores ladder fields of the account.
func (s *Store) SetLadderStats(account Account, ladder string, stats map[string]int64) error {
	return s.tx(func(conn *sql.Conn) error {
		for field, value := range stats {
			if _, err := conn.ExecContext(context.Background(),
				"INSERT OR REPLACE INTO ladder (account, game, field, value) VALUES (?, ?, ?, ?)",
				account.ID, ladder, field, value); err != nil {
				return err
			}
		}
		return nil
	})
}

// UpdateLadder reads the stored fields of several accounts and writes back what update returns, in one
// transaction, so concurrent results can't interleave.
func (s *Store) UpdateLadder(ladder string, ids []int64, update func(stats map[int64]map[string]int64) map[int64]map[string]int64) error {
	return s.tx(func(conn *sql.Conn) error {
		ctx := context.Background()
		current := map[int64]map[string]int64{}
		for _, id := range ids {
			current[id] = map[string]int64{}
			rows, err := conn.QueryContext(ctx, "SELECT field, value FROM ladder WHERE account = ? AND game = ?", id, ladder)
			if err != nil {
				return err
			}
			for rows.Next() {
				var field string
				var value int64
				if err := rows.Scan(&field, &value); err != nil {
					rows.Close()
					return err
				}
				current[id][field] = value
			}
			rows.Close()
		}
		for id, stats := range update(current) {
			for field, value := range stats {
				if _, err := conn.ExecContext(ctx,
					"INSERT OR REPLACE INTO ladder (account, game, field, value) VALUES (?, ?, ?, ?)",
					id, ladder, field, value); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// Profile returns the account's stored profile data for a game, or nil if there is none.
func (s *Store) Profile(account Account, game string) ([]byte, error) {
	var data []byte
	found := false
	err := s.query(func(db *sql.DB) error {
		err := db.QueryRow("SELECT data FROM profiles WHERE account = ? AND game = ?", account.ID, game).Scan(&data)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		found = err == nil
		return err
	})
	if err != nil || !found {
		return nil, err
	}
	if data == nil {
		data = []byte{}
	}
	return data, nil
}

// SetProfile stores the account's profile data for a game.
func (s *Store) SetProfile(account Account, game string, data []byte) error {
	return s.tx(func(conn *sql.Conn) error {
		_, err := conn.ExecContext(context.Background(),
			"INSERT OR REPLACE INTO profiles (account, game, data) VALUES (?, ?, ?)", account.ID, game, data)
		return err
	})
}
