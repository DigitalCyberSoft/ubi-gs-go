package accounts

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/testvec"
)

func open(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ubigs.db")
	s, err := Open(path, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func name(t *testing.T, s *Store, n, pw string) string {
	t.Helper()
	a, err := s.Login(n, pw)
	if err != nil {
		t.Fatalf("Login(%q): %v", n, err)
	}
	return a.Name
}

// refused checks that a login is refused as a wrong password.
func refused(t *testing.T, s *Store, n, pw string) {
	t.Helper()
	if a, err := s.Login(n, pw); err != ErrInvalidPassword {
		t.Fatalf("Login(%q, %q) = %v, %v; want INVALID_PASSWORD", n, pw, a, err)
	}
}

// noFamily checks that no name-k account exists for any of the names.
func noFamily(t *testing.T, s *Store, names ...string) {
	t.Helper()
	for _, n := range names {
		for k := 1; k <= 3; k++ {
			if a, _ := s.Find(FamilyName(n, k)); a != nil {
				t.Fatalf("%s was created", a.Name)
			}
		}
	}
}

func TestFirstLoginCreatesWrongPasswordRefused(t *testing.T) {
	s, path := open(t)
	// a new name registers on its first login, and the same password logs in again
	if name(t, s, "alice", "one") != "alice" || name(t, s, "alice", "one") != "alice" {
		t.Fatal("first login")
	}
	// a taken name with another password is a wrong password, every time
	refused(t, s, "alice", "two")
	refused(t, s, "alice", "two")
	refused(t, s, "ALICE", "three")
	if name(t, s, "ALICE", "one") != "alice" {
		t.Fatal("returning player")
	}
	noFamily(t, s, "alice")
	if n, _ := s.Count(); n != 1 {
		t.Fatalf("%d accounts, want 1", n)
	}
	name(t, s, "carol", "three")
	// only hashes are stored
	s.Close()
	matches, _ := filepath.Glob(path + "*")
	for _, m := range matches {
		b, _ := os.ReadFile(m)
		if bytes.Contains(b, []byte("three")) {
			t.Fatalf("password in %s", m)
		}
	}
}

func TestNameRules(t *testing.T) {
	s, _ := open(t)
	if name(t, s, "abcdefghijklmno", "one") != "abcdefghijk" || name(t, s, "abcdefghijk", "one") != "abcdefghijk" {
		t.Fatal("length")
	}
	refused(t, s, "abcdefghijklmnop", "two")
	if name(t, s, "éééééééé", "one") != "ééééé" {
		t.Fatal("multibyte")
	}
	refused(t, s, "ééééé", "two")
	noFamily(t, s, "abcdefghijk", "ééééé")
	for _, n := range []string{"", "   ", "a b", "a\tb", "a\x01"} {
		if _, err := s.Login(n, "pw"); err != ErrUsernameMalformed {
			t.Errorf("Login(%q): %v", n, err)
		}
	}
	if _, err := s.Login("alice", ""); err != ErrPasswordMalformed {
		t.Errorf("empty password: %v", err)
	}
}

func TestFamilyVectors(t *testing.T) {
	var vs []struct {
		Name, Family string
		K            int
	}
	testvec.Get(t, testvec.Load(t), "family", &vs)
	for _, v := range vs {
		if got := FamilyName(v.Name, v.K); got != v.Family {
			t.Errorf("FamilyName(%q, %d) = %q, want %q", v.Name, v.K, got, v.Family)
		}
	}
}

func TestPersistenceAndCorruptFile(t *testing.T) {
	s, path := open(t)
	alice, _ := s.Login("alice", "one")
	s.Close()
	s, err := Open(path, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := s.Login("alice", "one"); a != alice {
		t.Fatal("not kept")
	}
	if v, _ := s.SchemaVersion(); v != SchemaVersion {
		t.Fatalf("schema %d", v)
	}
	s.Close()
	os.WriteFile(path, bytes.Repeat([]byte("this is not a database"), 100), 0o600)
	os.Remove(path + "-wal")
	os.Remove(path + "-shm")
	s, err = Open(path, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if name(t, s, "alice", "two") != "alice" {
		t.Fatal("new database")
	}
	refused(t, s, "alice", "one")
	if aside, _ := filepath.Glob(path + ".corrupt-*"); len(aside) == 0 {
		t.Fatal("not moved aside")
	}
}

func TestUnopenableFileLeftAlone(t *testing.T) {
	// a directory in the database's place can't be opened, by root too (unlike a file without permissions)
	path := filepath.Join(t.TempDir(), "ubigs.db")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(path, t.Logf); err == nil {
		s.Close()
		t.Fatal("opened")
	}
	if fi, err := os.Stat(path); err != nil || !fi.IsDir() {
		t.Fatal("moved")
	}
	if aside, _ := filepath.Glob(path + ".corrupt-*"); len(aside) != 0 {
		t.Fatal("moved aside")
	}
}

func TestNewerSchemaLeftAlone(t *testing.T) {
	s, path := open(t)
	alice, _ := s.Login("alice", "one")
	if _, err := s.db.Exec(fmt.Sprintf("PRAGMA user_version = %d", SchemaVersion+1)); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if s, err := Open(path, t.Logf); err == nil {
		s.Close()
		t.Fatal("opened a newer schema")
	}
	if aside, _ := filepath.Glob(path + ".corrupt-*"); len(aside) != 0 {
		t.Fatal("moved aside")
	}
	// the accounts are all there once the version is set back
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(fmt.Sprintf("PRAGMA user_version = %d", SchemaVersion))
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	s, err = Open(path, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if a, _ := s.Login("alice", "one"); a != alice {
		t.Fatal("not kept")
	}
}

func TestPythonDatabase(t *testing.T) {
	// a database written by the reference implementation, with a non-ASCII password
	src := filepath.Join("testdata", "python.db")
	if _, err := os.Stat(src); err != nil {
		t.Skip("no reference database")
	}
	dst := filepath.Join(t.TempDir(), "ubigs.db")
	b, _ := os.ReadFile(src)
	os.WriteFile(dst, b, 0o600)
	s, err := Open(dst, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var want map[string]string
	j, _ := os.ReadFile(filepath.Join("testdata", "python.json"))
	json.Unmarshal(j, &want)
	for hexPW, acct := range want {
		pw := string(testvec.Hex(t, hexPW))
		if got := name(t, s, "alice", pw); got != acct {
			t.Errorf("password %q: %s, want %s", pw, got, acct)
		}
	}
}

func TestConcurrentLogins(t *testing.T) {
	s, _ := open(t)
	var mu sync.Mutex
	var names []string
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			a, err := s.Login("bob", "pw"+string(rune('0'+i)))
			mu.Lock()
			if err == nil {
				names = append(names, a.Name)
			} else if err != ErrInvalidPassword {
				names = append(names, err.Error())
			}
			mu.Unlock()
		}(i)
		go func() {
			defer wg.Done()
			s.Login("carol", "same")
		}()
	}
	wg.Wait()
	sort.Strings(names)
	// the first one creates bob, the others are wrong passwords
	if strings.Join(names, " ") != "bob" {
		t.Fatalf("names %v", names)
	}
	if n, _ := s.Count(); n != 2 {
		t.Fatalf("%d accounts, want 2 (one bob, one carol)", n)
	}
}

func TestSessionsFriendsLadderProfile(t *testing.T) {
	s, _ := open(t)
	alice, _ := s.Login("alice", "one")
	second, _ := s.Login("alice-1", "two")
	bob, _ := s.Login("bob", "pw")
	s.BindSession("alice", "10.0.0.3", second)
	if s.AccountName("ALICE", "10.0.0.3") != "alice-1" || s.AccountName("alice", "10.0.0.9") != "alice" {
		t.Fatal("sessions")
	}
	s.AddFriend(alice, bob)
	s.AddFriend(alice, bob)
	if f, _ := s.Friends(alice); len(f) != 1 || f[0] != bob {
		t.Fatalf("friends %v", f)
	}
	if f, _ := s.FriendOf(bob); len(f) != 1 || f[0] != alice {
		t.Fatalf("friend of %v", f)
	}
	s.RemoveFriend(alice, bob)
	if f, _ := s.Friends(alice); len(f) != 0 {
		t.Fatal("not removed")
	}
	s.SetLadderStats(alice, "G/1", map[string]int64{"RATING": 1600})
	if st, _ := s.LadderStats(alice, "G/1"); st["RATING"] != 1600 {
		t.Fatal("ladder")
	}
	if p, _ := s.Profile(alice, "G"); p != nil {
		t.Fatal("profile before any")
	}
	s.SetProfile(alice, "G", []byte{})
	if p, _ := s.Profile(alice, "G"); p == nil || len(p) != 0 {
		t.Fatal("empty profile")
	}
}

func TestMemory(t *testing.T) {
	s, err := Open(Memory, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if name(t, s, "alice", "one") != "alice" {
		t.Fatal("memory")
	}
	refused(t, s, "alice", "two")
	s.Close()
	s, _ = Open(Memory, t.Logf)
	defer s.Close()
	if a, _ := s.Find("alice"); a != nil {
		t.Fatal("kept after closing")
	}
}

func TestPrune(t *testing.T) {
	s, _ := open(t)
	old, _ := s.Login("old", "pw")
	played, _ := s.Login("played", "pw")
	s.AddFriend(played, old)
	s.RecordLobbyLogin(played)
	if n, _ := s.PruneUnused(time.Now().Add(-time.Hour)); n != 0 {
		t.Fatal("pruned new accounts")
	}
	if n, err := s.PruneUnused(time.Now().Add(time.Hour)); n != 1 || err != nil {
		t.Fatalf("pruned %d: %v", n, err)
	}
	if a, _ := s.Find("old"); a != nil {
		t.Fatal("not pruned")
	}
	if a, _ := s.Find("played"); a == nil {
		t.Fatal("pruned an account that played")
	}
}

func TestLoginWithLimits(t *testing.T) {
	s, _ := open(t)
	refuse := &LoginError{Reason: 3, Name: "limit"}
	_, err := s.LoginWith("alice", "pw", LoginOptions{AllowCreate: func(int64) error { return refuse }})
	if err != refuse {
		t.Fatalf("creation not refused: %v", err)
	}
	s.Login("alice", "pw")
	res, err := s.LoginWith("alice", "pw", LoginOptions{AllowCreate: func(int64) error { return refuse }})
	if err != nil || res.Created {
		t.Fatal("an existing account needs no creation")
	}
	// a wrong password creates nothing, so it never asks
	asked := false
	res, err = s.LoginWith("alice", "other", LoginOptions{AllowCreate: func(int64) error { asked = true; return nil }})
	if err != ErrInvalidPassword || res.Created || asked {
		t.Fatalf("%+v %v asked=%v", res, err, asked)
	}
}

func TestExistingFamilyAccountsKept(t *testing.T) {
	// name-k accounts from before wrong passwords were refused (here created under their own names) keep
	// logging in with the typed name and their password
	s, _ := open(t)
	alice, _ := s.Login("alice", "one")
	first, _ := s.Login("alice-1", "two")
	second, _ := s.Login("alice-2", "three")
	if a, err := s.Login("alice", "two"); err != nil || a != first {
		t.Fatalf("alice-1: %v %v", a, err)
	}
	if a, err := s.Login("Alice", "three"); err != nil || a != second {
		t.Fatalf("alice-2: %v %v", a, err)
	}
	if a, err := s.Login("alice", "one"); err != nil || a != alice {
		t.Fatalf("alice: %v %v", a, err)
	}
	// a password of none of them is refused, and alice-3 isn't created
	refused(t, s, "alice", "four")
	if a, _ := s.Find("alice-3"); a != nil {
		t.Fatal("alice-3 created")
	}
	if n, _ := s.Count(); n != 3 {
		t.Fatalf("%d accounts, want 3", n)
	}
}
