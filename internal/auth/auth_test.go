package auth

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func openTestStore(t *testing.T) *Store {
	t.Helper()

	store, err := Open(filepath.Join(t.TempDir(), "test.db"), testLogger())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	t.Cleanup(func() {
		_ = store.Close()
	})

	return store
}

func issueTestToken(t *testing.T, store *Store, user, name string, patterns Patterns) *IssuedToken {
	t.Helper()

	issued, err := store.IssueToken(user, name, patterns, nil, false)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	return issued
}

func TestUserLifecycle(t *testing.T) {
	store := openTestStore(t)

	if _, err := store.CreateUser("root", "Root", true); err != nil {
		t.Fatalf("create root: %v", err)
	}
	if _, err := store.CreateUser("alice", "Alice", true); err != nil {
		t.Fatalf("create user: %v", err)
	}

	if _, err := store.CreateUser("alice", "Dupe", false); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate create = %v, want ErrExists", err)
	}

	user, err := store.GetUser("alice")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}

	if !user.IsAdmin || !user.Active || user.DisplayName != "Alice" {
		t.Fatalf("unexpected user: %+v", user)
	}

	updated, err := store.UpdateUser("alice", "Alice A", false, true)
	if err != nil {
		t.Fatalf("update user: %v", err)
	}

	if updated.IsAdmin || updated.DisplayName != "Alice A" {
		t.Fatalf("unexpected updated user: %+v", updated)
	}

	if err := store.DeleteUser("alice"); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	if _, err := store.GetUser("alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get deleted = %v, want ErrNotFound", err)
	}
}

func TestValidateMethodIsolation(t *testing.T) {
	store := openTestStore(t)

	if _, err := store.CreateUser("alice", "", false); err != nil {
		t.Fatal(err)
	}

	issued := issueTestToken(t, store, "alice", "mixed", Patterns{
		GET:  []string{"/a/*"},
		POST: []string{"/b/*"},
	})

	valid, _, token, err := store.Validate("alice", issued.Plaintext, "GET", "/a/1", false)
	if err != nil || !valid || token == nil {
		t.Fatalf("GET /a/1 valid=%v err=%v", valid, err)
	}

	if valid, reason, _, _ := store.Validate("alice", issued.Plaintext, "GET", "/b/1", false); valid {
		t.Fatalf("GET /b/1 unexpectedly valid (POST patterns must not grant GET)")
	} else if reason != "token does not match patterns" {
		t.Fatalf("GET /b/1 reason = %q", reason)
	}

	if valid, _, _, err := store.Validate("alice", issued.Plaintext, "POST", "/b/1", false); err != nil || !valid {
		t.Fatalf("POST /b/1 valid=%v err=%v", valid, err)
	}

	if valid, reason, _, _ := store.Validate("alice", issued.Plaintext, "DELETE", "/b/1", false); valid || reason != "no patterns found" {
		t.Fatalf("DELETE valid=%v reason=%q", valid, reason)
	}

	if valid, reason, _, _ := store.Validate("alice", "wrong", "GET", "/a/1", false); valid || reason != "token not found" {
		t.Fatalf("wrong bearer valid=%v reason=%q", valid, reason)
	}

	if valid, reason, _, _ := store.Validate("nobody", issued.Plaintext, "GET", "/a/1", false); valid || reason != "unknown user" {
		t.Fatalf("unknown user valid=%v reason=%q", valid, reason)
	}
}

func TestValidateExpiryRevocationAdminHuProxy(t *testing.T) {
	store := openTestStore(t)

	if _, err := store.CreateUser("alice", "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateUser("root", "", false); err != nil {
		t.Fatal(err)
	}

	past := time.Now().Add(-time.Hour)
	expired, err := store.IssueToken("alice", "old", Patterns{GET: []string{"/*"}}, &past, false)
	if err != nil {
		t.Fatal(err)
	}

	if valid, reason, _, _ := store.Validate("alice", expired.Plaintext, "GET", "/x", false); valid || reason != "token expired" {
		t.Fatalf("expired valid=%v reason=%q", valid, reason)
	}

	admin, err := store.IssueToken("root", "admin", Patterns{}, nil, true)
	if err != nil {
		t.Fatal(err)
	}

	if valid, _, token, err := store.Validate("root", admin.Plaintext, "ADMIN", "/", false); err != nil || !valid || !token.IsAdmin {
		t.Fatalf("ADMIN valid=%v err=%v", valid, err)
	}

	plain, err := store.IssueToken("alice", "plain", Patterns{GET: []string{"/*"}}, nil, false)
	if err != nil {
		t.Fatal(err)
	}

	if valid, _, _, _ := store.Validate("alice", plain.Plaintext, "ADMIN", "/", false); valid {
		t.Fatal("non-admin token passed ADMIN check")
	}

	tunnel, err := store.IssueToken("alice", "tun", Patterns{HuProxy: []string{"git.internal:22"}}, nil, false)
	if err != nil {
		t.Fatal(err)
	}

	if valid, _, _, err := store.Validate("alice", tunnel.Plaintext, "anything", "git.internal:22", true); err != nil || !valid {
		t.Fatalf("huproxy valid=%v err=%v", valid, err)
	}

	if valid, reason, _, _ := store.Validate("alice", tunnel.Plaintext, "anything", "other:22", true); valid || reason == "" {
		t.Fatalf("huproxy mismatch valid=%v reason=%q", valid, reason)
	}

	if err := store.RevokeToken("alice", plain.Token.ID); err != nil {
		t.Fatal(err)
	}

	if valid, reason, _, _ := store.Validate("alice", plain.Plaintext, "GET", "/x", false); valid || reason != "token not found" {
		t.Fatalf("revoked valid=%v reason=%q", valid, reason)
	}
}

func TestRotateToken(t *testing.T) {
	store := openTestStore(t)

	if _, err := store.CreateUser("alice", "", false); err != nil {
		t.Fatal(err)
	}

	issued := issueTestToken(t, store, "alice", "rot", Patterns{POST: []string{"/hooks/*"}})

	rotated, err := store.RotateToken("alice", issued.Token.ID)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}

	if rotated.Plaintext == issued.Plaintext {
		t.Fatal("rotated token identical to original")
	}

	if valid, _, _, _ := store.Validate("alice", issued.Plaintext, "POST", "/hooks/1", false); valid {
		t.Fatal("old token still valid after rotation")
	}

	if valid, _, _, err := store.Validate("alice", rotated.Plaintext, "POST", "/hooks/1", false); err != nil || !valid {
		t.Fatalf("rotated token valid=%v err=%v", valid, err)
	}

	if _, err := store.RotateToken("alice", "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rotate missing = %v, want ErrNotFound", err)
	}
}

func TestInvalidPatternRejectedAtIssuance(t *testing.T) {
	store := openTestStore(t)

	if _, err := store.CreateUser("alice", "", false); err != nil {
		t.Fatal(err)
	}

	// Empty patterns are rejected by the pattern compiler.
	if _, err := store.IssueToken("alice", "bad", Patterns{GET: []string{""}}, nil, false); err == nil {
		t.Fatal("expected pattern validation error")
	}
}

func TestNtfySessionsAudit(t *testing.T) {
	store := openTestStore(t)

	if _, err := store.CreateUser("alice", "", false); err != nil {
		t.Fatal(err)
	}

	if _, err := store.GetNtfy("alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get ntfy = %v, want ErrNotFound", err)
	}

	if err := store.SetNtfy("alice", "matrix", map[string]any{"room_id": "!x:y"}); err != nil {
		t.Fatal(err)
	}

	backend, err := store.GetNtfy("alice")
	if err != nil {
		t.Fatal(err)
	}

	if backend.Type != "matrix" || backend.Config["room_id"] != "!x:y" {
		t.Fatalf("unexpected backend: %+v", backend)
	}

	session, err := store.CreateSession("alice", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.GetSession(session.ID); err != nil {
		t.Fatalf("get session: %v", err)
	}

	if err := store.DeleteSession(session.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := store.GetSession(session.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get deleted session = %v", err)
	}

	expired, err := store.CreateSession("alice", -time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.GetSession(expired.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get expired session = %v", err)
	}

	if err := store.RecordAudit("admin", "token.issue", "alice/t1", "ok", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}

	events, err := store.ListAudit(10, 0)
	if err != nil {
		t.Fatal(err)
	}

	if len(events) != 1 || events[0].Action != "token.issue" {
		t.Fatalf("unexpected audit: %+v", events)
	}
}

func TestGroups(t *testing.T) {
	store := openTestStore(t)

	if _, err := store.CreateUser("alice", "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateUser("bob", "", false); err != nil {
		t.Fatal(err)
	}

	group, err := store.UpsertGroup("eng", "Engineering", "ext-eng")
	if err != nil {
		t.Fatal(err)
	}

	if group.SCIMID != "ext-eng" {
		t.Fatalf("scim id = %q", group.SCIMID)
	}

	if err := store.SetGroupMembers("eng", []string{"alice", "bob"}); err != nil {
		t.Fatal(err)
	}

	fetched, err := store.GetGroup("eng")
	if err != nil {
		t.Fatal(err)
	}

	if len(fetched.Members) != 2 {
		t.Fatalf("members = %v", fetched.Members)
	}

	if err := store.SetGroupMembers("eng", []string{"alice", "ghost"}); err == nil {
		t.Fatal("expected error for unknown member")
	}

	fetched, err = store.GetGroup("eng")
	if err != nil {
		t.Fatal(err)
	}
	if len(fetched.Members) != 2 {
		t.Fatalf("failed membership replacement changed group: %v", fetched.Members)
	}

	found, err := store.FindGroupBySCIMID("ext-eng")
	if err != nil || found.ID != "eng" {
		t.Fatalf("find by scim = %+v, %v", found, err)
	}
}

func TestUpsertGroupWithMembersRollsBack(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.CreateUser("alice", "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertGroupWithMembers("eng", "Engineering", "ext-eng", []string{"alice"}); err != nil {
		t.Fatal(err)
	}

	if _, err := store.UpsertGroupWithMembers("eng", "Changed", "ext-changed", []string{"ghost"}); err == nil {
		t.Fatal("expected unknown member to fail")
	}
	group, err := store.GetGroup("eng")
	if err != nil {
		t.Fatal(err)
	}
	if group.DisplayName != "Engineering" || group.SCIMID != "ext-eng" || len(group.Members) != 1 || group.Members[0] != "alice" {
		t.Fatalf("failed replacement persisted partially: %+v", group)
	}

	if _, err := store.UpsertGroupWithMembers("new", "New", "ext-new", []string{"ghost"}); err == nil {
		t.Fatal("expected unknown member to fail")
	}
	if _, err := store.GetGroup("new"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed create left group behind: %v", err)
	}
}

func TestConcurrentGroupMemberPatchesDoNotLoseUpdates(t *testing.T) {
	store := openTestStore(t)
	for _, id := range []string{"alice", "bob"} {
		if _, err := store.CreateUser(id, "", false); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.UpsertGroup("eng", "Engineering", ""); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	errorsByUser := make(chan error, 2)
	var wait sync.WaitGroup
	for _, id := range []string{"alice", "bob"} {
		wait.Add(1)
		go func(id string) {
			defer wait.Done()
			<-start
			_, err := store.PatchGroupMembers("eng", []GroupMemberMutation{{UserID: id}})
			errorsByUser <- err
		}(id)
	}
	close(start)
	wait.Wait()
	close(errorsByUser)
	for err := range errorsByUser {
		if err != nil {
			t.Fatal(err)
		}
	}

	group, err := store.GetGroup("eng")
	if err != nil {
		t.Fatal(err)
	}
	if len(group.Members) != 2 || group.Members[0] != "alice" || group.Members[1] != "bob" {
		t.Fatalf("concurrent patches lost an update: %v", group.Members)
	}
}

func TestListUpdateDeleteUsers(t *testing.T) {
	store := openTestStore(t)

	if _, err := store.CreateUser("bad/id", "", false); err == nil {
		t.Fatal("expected invalid user id to fail")
	}

	if _, err := store.CreateUser("alice", "A", false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateUser("bob", "B", true); err != nil {
		t.Fatal(err)
	}

	users, err := store.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || users[0].ID != "alice" || users[1].ID != "bob" {
		t.Fatalf("unexpected users: %+v", users)
	}

	if _, err := store.UpdateUser("ghost", "", false, true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update ghost = %v", err)
	}
	if err := store.DeleteUser("ghost"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete ghost = %v", err)
	}

	if err := store.DeleteUser("bob"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("delete sole admin = %v, want ErrLastAdmin", err)
	}
	if _, err := store.UpdateUser("alice", "A", true, true); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteUser("bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetUser("bob"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get deleted = %v", err)
	}
}

func TestOIDCAndSCIMLinkage(t *testing.T) {
	store := openTestStore(t)

	if _, err := store.CreateUser("alice", "", false); err != nil {
		t.Fatal(err)
	}

	if _, err := store.LinkOIDCSub("alice", "sub-1"); err != nil {
		t.Fatal(err)
	}

	found, err := store.FindUserByOIDCSub("sub-1")
	if err != nil || found.ID != "alice" {
		t.Fatalf("find by sub = %+v, %v", found, err)
	}

	if _, err := store.FindUserByOIDCSub("sub-missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("find missing sub = %v", err)
	}

	if _, err := store.LinkOIDCSub("alice", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FindUserByOIDCSub("sub-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cleared link still resolves")
	}

	if _, err := store.UpdateUserSCIMID("alice", "ext-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateUserSCIMID("ghost", "ext-x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("scim link ghost = %v", err)
	}

	scimFound, err := store.FindUserBySCIMID("ext-1")
	if err != nil || scimFound.ID != "alice" {
		t.Fatalf("find by scim = %+v, %v", scimFound, err)
	}
	if _, err := store.FindUserBySCIMID("ext-missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("find missing scim = %v", err)
	}
}

func TestListTokensAndRecordUse(t *testing.T) {
	store := openTestStore(t)

	if _, err := store.CreateUser("alice", "", false); err != nil {
		t.Fatal(err)
	}

	if _, err := store.IssueToken("alice", "one", Patterns{GET: []string{"/a"}}, nil, false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.IssueToken("alice", "two", Patterns{POST: []string{"/b"}}, nil, false); err != nil {
		t.Fatal(err)
	}

	tokens, err := store.ListTokens("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 2 || tokens[0].Name != "one" || tokens[1].Name != "two" {
		t.Fatalf("unexpected tokens: %+v", tokens)
	}
	if tokens[0].Patterns.GET[0] != "/a" {
		t.Fatalf("patterns not round-tripped: %+v", tokens[0].Patterns)
	}

	if err := store.RecordTokenUse(tokens[0].ID); err != nil {
		t.Fatalf("record use: %v", err)
	}

	if err := store.RevokeToken("alice", tokens[0].ID); err != nil {
		t.Fatal(err)
	}

	remaining, err := store.ListTokens("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 || remaining[0].Name != "two" {
		t.Fatalf("unexpected remaining: %+v", remaining)
	}

	if err := store.RevokeToken("alice", tokens[0].ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double revoke = %v", err)
	}
}

func TestListSessionsPrunesExpired(t *testing.T) {
	store := openTestStore(t)

	if _, err := store.CreateUser("alice", "", false); err != nil {
		t.Fatal(err)
	}

	live, err := store.CreateSession("alice", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSession("alice", -time.Hour); err != nil {
		t.Fatal(err)
	}

	sessions, err := store.ListSessions("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].ID != live.ID {
		t.Fatalf("sessions = %+v", sessions)
	}
}

func TestListAndDeleteGroups(t *testing.T) {
	store := openTestStore(t)

	if _, err := store.UpsertGroup("g1", "One", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertGroup("g2", "Two", "ext-2"); err != nil {
		t.Fatal(err)
	}

	groups, err := store.ListGroups()
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 {
		t.Fatalf("groups = %+v", groups)
	}

	if err := store.DeleteGroup("g1"); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteGroup("g1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double delete = %v", err)
	}
	if _, err := store.GetGroup("g1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get deleted = %v", err)
	}
}

func TestOpenBadPath(t *testing.T) {
	if _, err := Open(t.TempDir()+"/missing-dir/test.db", testLogger()); err == nil {
		t.Fatal("expected open with bad path to fail")
	}
}

func TestSetNtfyUnknownUser(t *testing.T) {
	store := openTestStore(t)

	if err := store.SetNtfy("ghost", "matrix", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("set ntfy ghost = %v", err)
	}
}

func TestValidateUnsupportedMethod(t *testing.T) {
	store := openTestStore(t)

	if _, err := store.CreateUser("alice", "", false); err != nil {
		t.Fatal(err)
	}
	issued := issueTestToken(t, store, "alice", "t", Patterns{GET: []string{"/*"}})

	if valid, reason, _, _ := store.Validate("alice", issued.Plaintext, "BREW", "/", false); valid || reason != "unsupported method" {
		t.Fatalf("valid=%v reason=%q", valid, reason)
	}
}

func TestSQLiteOpenConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth store.db")
	fileURI := (&url.URL{Scheme: "file", Path: path}).String()

	tests := []struct {
		name     string
		input    string
		wantFile string
	}{
		{name: "plain path", input: path + "?_fk=off&_timeout=1", wantFile: path},
		{name: "file URI", input: fileURI + "?_foreign_keys=off&_busy_timeout=1", wantFile: path},
		{name: "memory", input: ":memory:", wantFile: ""},
		{name: "shared memory URI", input: "file:shared?mode=memory&cache=shared", wantFile: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dsn, filePath, err := sqliteOpenConfig(test.input)
			if err != nil {
				t.Fatal(err)
			}
			if filePath != test.wantFile {
				t.Fatalf("file path = %q, want %q", filePath, test.wantFile)
			}

			_, rawQuery, ok := strings.Cut(dsn, "?")
			if !ok {
				t.Fatalf("DSN has no query: %q", dsn)
			}
			query, err := url.ParseQuery(rawQuery)
			if err != nil {
				t.Fatal(err)
			}
			if query.Get("_foreign_keys") != "on" || query.Get("_busy_timeout") != "5000" || query.Get("_txlock") != "immediate" {
				t.Fatalf("unsafe connection options: %v", query)
			}
			if query.Has("_fk") || query.Has("_timeout") {
				t.Fatalf("unsafe aliases survived: %v", query)
			}
		})
	}

	if _, _, err := sqliteOpenConfig("file://remotehost/database.db"); err == nil {
		t.Fatal("expected remote file URI host to fail")
	}
	if _, _, err := sqliteOpenConfig(path + "?_pragma=busy_timeout%280%29"); err == nil {
		t.Fatal("expected raw pragma option to fail")
	}
	if _, _, err := sqliteOpenConfig("   "); err == nil {
		t.Fatal("expected empty path to fail")
	}
}

func TestSecureSQLiteFilesTightensSidecarsAndRejectsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes and symlinks are not enforced on Windows")
	}

	path := filepath.Join(t.TempDir(), "auth.db")
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if err := os.WriteFile(path+suffix, nil, 0o666); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path+suffix, 0o666); err != nil {
			t.Fatal(err)
		}
	}
	if err := secureSQLiteFiles(path); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		info, err := os.Stat(path + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("%s mode = %04o, want 0600", suffix, got)
		}
	}

	symlinkDB := filepath.Join(t.TempDir(), "symlink.db")
	if err := os.WriteFile(symlinkDB, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, symlinkDB+"-wal"); err != nil {
		t.Fatal(err)
	}
	if err := secureSQLiteFiles(symlinkDB); err == nil {
		t.Fatal("expected SQLite sidecar symlink to fail")
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o666 {
		t.Fatalf("symlink target mode = %04o, want unchanged 0666", got)
	}
}

func TestOpenSecuresDatabaseAndEveryConnection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not enforced on Windows")
	}

	path := filepath.Join(t.TempDir(), "auth.db")
	if err := os.WriteFile(path, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}

	store, err := Open(path, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("database mode = %04o, want 0600", got)
	}

	ctx := context.Background()
	for range 8 {
		conn, err := store.db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })

		var foreignKeys, busyTimeout int
		if err := conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
			t.Fatal(err)
		}
		if err := conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
			t.Fatal(err)
		}
		if foreignKeys != 1 || busyTimeout != 5000 {
			t.Fatalf("connection settings foreign_keys=%d busy_timeout=%d", foreignKeys, busyTimeout)
		}
	}

	for _, suffix := range []string{"-wal", "-shm"} {
		info, err := os.Stat(path + suffix)
		if err != nil {
			t.Fatalf("stat SQLite sidecar %s: %v", suffix, err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("SQLite sidecar %s mode = %04o, want 0600", suffix, got)
		}
	}
}

func TestDeleteCascadeOnLastPoolConnection(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.CreateUser("alice", "", false); err != nil {
		t.Fatal(err)
	}
	issued := issueTestToken(t, store, "alice", "old", Patterns{GET: []string{"/*"}})
	session, err := store.CreateSession("alice", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetNtfy("alice", "matrix", map[string]any{"access_token": "secret"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertGroup("eng", "Engineering", ""); err != nil {
		t.Fatal(err)
	}
	if err := store.SetGroupMembers("eng", []string{"alice"}); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	held := make([]interface{ Close() error }, 0, 7)
	for range 7 {
		conn, err := store.db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, conn)
	}
	defer func() {
		for _, conn := range held {
			_ = conn.Close()
		}
	}()

	if err := store.DeleteUser("alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateUser("alice", "Replacement", false); err != nil {
		t.Fatal(err)
	}

	if valid, _, _, err := store.Validate("alice", issued.Plaintext, "GET", "/x", false); err != nil || valid {
		t.Fatalf("old token valid=%v err=%v", valid, err)
	}
	if _, err := store.GetSession(session.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old session = %v, want ErrNotFound", err)
	}
	if _, err := store.GetNtfy("alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old ntfy config = %v, want ErrNotFound", err)
	}
	group, err := store.GetGroup("eng")
	if err != nil {
		t.Fatal(err)
	}
	if len(group.Members) != 0 {
		t.Fatalf("old group membership survived: %v", group.Members)
	}
}

func TestNamedPublicTokenAuthorizesMissingBearer(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.CreateUser("alice", "", false); err != nil {
		t.Fatal(err)
	}
	issued := issueTestToken(t, store, "alice", "public", Patterns{GET: []string{"/shared/*"}})

	valid, _, token, err := store.Validate("alice", "", "GET", "/shared/item", false)
	if err != nil || !valid || token == nil || token.ID != issued.Token.ID {
		t.Fatalf("anonymous validation valid=%v token=%+v err=%v", valid, token, err)
	}
	if valid, _, _, err := store.Validate("alice", "", "POST", "/shared/item", false); err != nil || valid {
		t.Fatalf("anonymous POST valid=%v err=%v", valid, err)
	}
	if _, err := store.IssueToken("alice", "public", Patterns{GET: []string{"/*"}}, nil, false); err == nil {
		t.Fatal("expected a second live public token to be rejected")
	}
	if err := store.RevokeToken("alice", issued.Token.ID); err != nil {
		t.Fatal(err)
	}
	if valid, _, _, err := store.Validate("alice", "", "GET", "/shared/item", false); err != nil || valid {
		t.Fatalf("revoked anonymous token valid=%v err=%v", valid, err)
	}
}

func TestOpenRevokesAmbiguousLegacyPublicTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	store, err := Open(path, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateUser("alice", "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`DROP INDEX idx_tokens_public`); err != nil {
		t.Fatal(err)
	}
	first := issueTestToken(t, store, "alice", "public", Patterns{GET: []string{"/narrow"}})
	second := issueTestToken(t, store, "alice", "public", Patterns{GET: []string{"/*"}})
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = Open(path, testLogger())
	if err != nil {
		t.Fatalf("reopen legacy store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	for _, bearer := range []string{first.Plaintext, second.Plaintext} {
		if valid, _, _, err := store.Validate("alice", bearer, "GET", "/narrow", false); err != nil || valid {
			t.Fatalf("ambiguous legacy token valid=%v err=%v", valid, err)
		}
	}
	if valid, _, _, err := store.Validate("alice", "", "GET", "/narrow", false); err != nil || valid {
		t.Fatalf("ambiguous anonymous access valid=%v err=%v", valid, err)
	}
	if _, err := store.IssueToken("alice", "public", Patterns{GET: []string{"/safe"}}, nil, false); err != nil {
		t.Fatalf("issue replacement public token: %v", err)
	}
}

func TestPatchUserRollsBackIdentityConflict(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.CreateUserWithIdentity("alice", "Alice", false, true, "sub-alice", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateUserWithIdentity("bob", "Bob", false, true, "sub-bob", ""); err != nil {
		t.Fatal(err)
	}

	displayName := "Changed"
	duplicateSub := "sub-bob"
	if _, err := store.PatchUser("alice", UserPatch{
		DisplayName: &displayName,
		OIDCSub:     &duplicateSub,
	}); err == nil {
		t.Fatal("expected duplicate OIDC subject to fail")
	}

	alice, err := store.GetUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	if alice.DisplayName != "Alice" || alice.OIDCSub != "sub-alice" {
		t.Fatalf("partial update persisted: %+v", alice)
	}
}

func TestConcurrentMutationsPreserveOneActiveAdmin(t *testing.T) {
	store := openTestStore(t)
	for _, id := range []string{"one", "two"} {
		if _, err := store.CreateUser(id, id, true); err != nil {
			t.Fatal(err)
		}
	}

	start := make(chan struct{})
	errorsByUser := make(chan error, 2)
	var group sync.WaitGroup
	for _, id := range []string{"one", "two"} {
		group.Add(1)
		go func(id string) {
			defer group.Done()
			<-start
			_, err := store.UpdateUser(id, id, false, true)
			errorsByUser <- err
		}(id)
	}
	close(start)
	group.Wait()
	close(errorsByUser)

	var succeeded, protected int
	for err := range errorsByUser {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrLastAdmin):
			protected++
		default:
			t.Fatalf("unexpected mutation error: %v", err)
		}
	}
	if succeeded != 1 || protected != 1 {
		t.Fatalf("succeeded=%d protected=%d, want one each", succeeded, protected)
	}

	users, err := store.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	activeAdmins := 0
	for _, user := range users {
		if user.Active && user.IsAdmin {
			activeAdmins++
		}
	}
	if activeAdmins != 1 {
		t.Fatalf("active admins = %d, want 1", activeAdmins)
	}
}
