package accounts

import (
	"bytes"
	"encoding/json"
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

func TestFirstLoginCreatesAndSuffixes(t *testing.T) {
	s, path := open(t)
	if name(t, s, "alice", "one") != "alice" || name(t, s, "alice", "one") != "alice" {
		t.Fatal("first login")
	}
	if name(t, s, "alice", "two") != "alice-1" || name(t, s, "alice", "three") != "alice-2" {
		t.Fatal("suffixes")
	}
	if name(t, s, "alice", "two") != "alice-1" || name(t, s, "ALICE", "one") != "alice" {
		t.Fatal("returning player")
	}
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
	if name(t, s, "abcdefghijklmno", "one") != "abcdefghijk" || name(t, s, "abcdefghijk", "two") != "abcdefghi-1" {
		t.Fatal("length")
	}
	if name(t, s, "éééééééé", "one") != "ééééé" || name(t, s, "ééééé", "two") != "éééé-1" {
		t.Fatal("multibyte")
	}
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
	if aside, _ := filepath.Glob(path + ".corrupt-*"); len(aside) == 0 {
		t.Fatal("not moved aside")
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
			a, _ := s.Login("bob", "pw"+string(rune('0'+i)))
			mu.Lock()
			names = append(names, a.Name)
			mu.Unlock()
		}(i)
		go func() {
			defer wg.Done()
			s.Login("carol", "same")
		}()
	}
	wg.Wait()
	sort.Strings(names)
	if strings.Join(names, " ") != "bob bob-1 bob-2 bob-3" {
		t.Fatalf("names %v", names)
	}
	if n, _ := s.Count(); n != 5 {
		t.Fatalf("%d accounts, want 5 (one carol)", n)
	}
}

func TestSessionsFriendsLadderProfile(t *testing.T) {
	s, _ := open(t)
	alice, _ := s.Login("alice", "one")
	second, _ := s.Login("alice", "two")
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
	if name(t, s, "alice", "one") != "alice" || name(t, s, "alice", "two") != "alice-1" {
		t.Fatal("memory")
	}
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
	res, _ = s.LoginWith("alice", "other", LoginOptions{})
	if !res.Created || !res.Taken || res.Account.Name != "alice-1" {
		t.Fatalf("%+v", res)
	}
}
