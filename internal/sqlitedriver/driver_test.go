package sqlitedriver

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestConnectFailsWhenRequiredCompileOptionMissing(t *testing.T) {
	clearDriverEnv(t)
	resetDriverStateForTest()

	t.Setenv("PATCHWORK_SQLITE_REQUIRED_COMPILE_OPTIONS", "PATCHWORK_TEST_FAKE_OPTION")

	err := pingTempDB(t)
	if err == nil {
		t.Fatalf("expected missing compile option error, got nil")
	}
	if !strings.Contains(err.Error(), "sqlite missing required compile options") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(err.Error(), "PATCHWORK_TEST_FAKE_OPTION") {
		t.Fatalf("missing required option name in error: %v", err)
	}
}

func TestConnectFailsWhenRequiredExtensionPathMissing(t *testing.T) {
	clearDriverEnv(t)
	resetDriverStateForTest()

	t.Setenv("PATCHWORK_SQLITE_EXTENSION_CRSQLITE", filepath.Join(t.TempDir(), "does-not-exist", "crsqlite"))

	err := pingTempDB(t)
	if err == nil {
		t.Fatalf("expected required extension load error, got nil")
	}
	if !strings.Contains(err.Error(), `load sqlite extension "crsqlite" failed`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConnectSucceedsWithNoExplicitExtensions(t *testing.T) {
	clearDriverEnv(t)
	resetDriverStateForTest()

	db, err := openTempDB(t)
	if err != nil {
		t.Fatalf("open temp db: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Fatalf("ping temp db: %v", err)
	}
}

func TestCRSQLiteExtensionLoadAndFunctionality(t *testing.T) {
	path := strings.TrimSpace(os.Getenv("PATCHWORK_SQLITE_TEST_CRSQLITE_PATH"))
	if path == "" {
		t.Skip("set PATCHWORK_SQLITE_TEST_CRSQLITE_PATH to run this extension integration test")
	}

	clearDriverEnv(t)
	resetDriverStateForTest()

	t.Setenv("PATCHWORK_SQLITE_EXTENSION_CRSQLITE", path)
	if ep := strings.TrimSpace(os.Getenv("PATCHWORK_SQLITE_TEST_CRSQLITE_ENTRYPOINT")); ep != "" {
		t.Setenv("PATCHWORK_SQLITE_EXTENSION_CRSQLITE_ENTRYPOINT", ep)
	}

	db, err := openTempDB(t)
	if err != nil {
		t.Fatalf("open temp db: %v", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatalf("ping temp db: %v", err)
	}

	if _, err := db.Exec(`CREATE TABLE foo(id INTEGER PRIMARY KEY, val TEXT);`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.Exec(`SELECT crsql_as_crr('foo');`); err != nil {
		t.Fatalf("crsql_as_crr failed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO foo(id, val) VALUES (1, 'a');`); err != nil {
		t.Fatalf("insert into crr table: %v", err)
	}

	var changeCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM crsql_changes`).Scan(&changeCount); err != nil {
		t.Fatalf("query crsql_changes: %v", err)
	}
}

func TestSQLiteVecExtensionLoadAndFunctionality(t *testing.T) {
	path := strings.TrimSpace(os.Getenv("PATCHWORK_SQLITE_TEST_VEC_PATH"))
	if path == "" {
		t.Skip("set PATCHWORK_SQLITE_TEST_VEC_PATH to run this extension integration test")
	}

	clearDriverEnv(t)
	resetDriverStateForTest()

	t.Setenv("PATCHWORK_SQLITE_EXTENSION_VEC", path)
	if ep := strings.TrimSpace(os.Getenv("PATCHWORK_SQLITE_TEST_VEC_ENTRYPOINT")); ep != "" {
		t.Setenv("PATCHWORK_SQLITE_EXTENSION_VEC_ENTRYPOINT", ep)
	}

	db, err := openTempDB(t)
	if err != nil {
		t.Fatalf("open temp db: %v", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatalf("ping temp db: %v", err)
	}

	var version string
	if err := db.QueryRow(`SELECT vec_version()`).Scan(&version); err != nil {
		t.Fatalf("vec_version failed: %v", err)
	}
	if strings.TrimSpace(version) == "" {
		t.Fatalf("vec_version returned empty string")
	}

	if _, err := db.Exec(`CREATE VIRTUAL TABLE vec_items USING vec0(embedding float[3]);`); err != nil {
		t.Fatalf("create vec0 table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO vec_items(rowid, embedding) VALUES (1, '[1.0,2.0,3.0]');`); err != nil {
		t.Fatalf("insert vec row: %v", err)
	}
}

func TestSqleanExtensionLoadAndFunctionality(t *testing.T) {
	path := strings.TrimSpace(os.Getenv("PATCHWORK_SQLITE_TEST_SQLEAN_PATH"))
	if path == "" {
		t.Skip("set PATCHWORK_SQLITE_TEST_SQLEAN_PATH to run this extension integration test")
	}

	clearDriverEnv(t)
	resetDriverStateForTest()

	t.Setenv("PATCHWORK_SQLITE_EXTENSION_SQLEAN", path)
	if ep := strings.TrimSpace(os.Getenv("PATCHWORK_SQLITE_TEST_SQLEAN_ENTRYPOINT")); ep != "" {
		t.Setenv("PATCHWORK_SQLITE_EXTENSION_SQLEAN_ENTRYPOINT", ep)
	}

	db, err := openTempDB(t)
	if err != nil {
		t.Fatalf("open temp db: %v", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatalf("ping temp db: %v", err)
	}

	var uuid string
	if err := db.QueryRow(`SELECT uuid4()`).Scan(&uuid); err != nil {
		t.Fatalf("uuid4 probe failed: %v", err)
	}
	if len(strings.TrimSpace(uuid)) != 36 {
		t.Fatalf("unexpected uuid4 output: %q", uuid)
	}
}

func TestSqleanModuleDirLoadAndFunctionality(t *testing.T) {
	dir := strings.TrimSpace(os.Getenv("PATCHWORK_SQLITE_TEST_SQLEAN_DIR"))
	if dir == "" {
		t.Skip("set PATCHWORK_SQLITE_TEST_SQLEAN_DIR to run this extension integration test")
	}

	clearDriverEnv(t)
	resetDriverStateForTest()

	t.Setenv("PATCHWORK_SQLITE_EXTENSION_SQLEAN_DIR", dir)

	db, err := openTempDB(t)
	if err != nil {
		t.Fatalf("open temp db: %v", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatalf("ping temp db: %v", err)
	}

	var uuid string
	if err := db.QueryRow(`SELECT uuid4()`).Scan(&uuid); err != nil {
		t.Fatalf("uuid4 probe failed: %v", err)
	}
	if len(strings.TrimSpace(uuid)) != 36 {
		t.Fatalf("unexpected uuid4 output: %q", uuid)
	}

	var matched int
	if err := db.QueryRow(`SELECT regexp_like('patchwork', '^patch')`).Scan(&matched); err != nil {
		t.Fatalf("regexp_like probe failed: %v", err)
	}
	if matched != 1 {
		t.Fatalf("unexpected regexp_like output: %d", matched)
	}
}

func openTempDB(t *testing.T) (*sql.DB, error) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "test.sqlite3")
	return sql.Open(DriverName, path)
}

func pingTempDB(t *testing.T) error {
	t.Helper()

	db, err := openTempDB(t)
	if err != nil {
		return err
	}
	defer db.Close()

	return db.Ping()
}

func clearDriverEnv(t *testing.T) {
	t.Helper()

	for _, key := range []string{
		"PATCHWORK_SQLITE_REQUIRED_COMPILE_OPTIONS",
		"PATCHWORK_SQLITE_WARN_MISSING_COMPILE_OPTIONS",
		"PATCHWORK_SQLITE_RECOMMENDED_COMPILE_OPTIONS",
		"PATCHWORK_SQLITE_EXTENSION_CRSQLITE",
		"PATCHWORK_SQLITE_EXTENSION_CRSQLITE_ENTRYPOINT",
		"PATCHWORK_SQLITE_EXTENSION_VEC",
		"PATCHWORK_SQLITE_EXTENSION_VEC_ENTRYPOINT",
		"PATCHWORK_SQLITE_EXTENSION_SQLEAN",
		"PATCHWORK_SQLITE_EXTENSION_SQLEAN_ENTRYPOINT",
		"PATCHWORK_SQLITE_EXTENSION_SQLEAN_DIR",
		"PATCHWORK_SQLITE_EXTENSIONS",
	} {
		t.Setenv(key, "")
	}
}

func resetDriverStateForTest() {
	compileCheckOnce = sync.Once{}
	compileCheckErr = nil
	extensionLogOnce = sync.Map{}
}
