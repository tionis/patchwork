package sqlitedriver

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	sqlite3 "github.com/mattn/go-sqlite3"
)

const DriverName = "sqlite"

var (
	registerOnce     sync.Once
	registerErr      error
	compileCheckOnce sync.Once
	compileCheckErr  error
	extensionLogOnce sync.Map
)

var recommendedCompileOptions = []string{
	"ENABLE_FTS5",
	"ENABLE_SESSION",
	"ENABLE_PREUPDATE_HOOK",
	"ENABLE_SNAPSHOT",
	"ENABLE_RBU",
	"ENABLE_ICU",
	"ENABLE_RTREE",
	"ENABLE_GEOPOLY",
}

type extensionGroup struct {
	label             string
	entrypoint        string
	defaultEntrypoint string
	candidates        []string
	required          bool
}

func init() {
	_ = Register()
}

func Register() error {
	registerOnce.Do(func() {
		defer func() {
			if r := recover(); r != nil {
				registerErr = fmt.Errorf("register sqlite driver %q: %v", DriverName, r)
			}
		}()

		sql.Register(DriverName, &sqlite3.SQLiteDriver{
			ConnectHook: connectHook,
		})
	})
	return registerErr
}

func connectHook(conn *sqlite3.SQLiteConn) error {
	if err := verifyCompileOptions(conn); err != nil {
		return err
	}
	return loadConfiguredExtensions(conn)
}

func verifyCompileOptions(conn *sqlite3.SQLiteConn) error {
	compileCheckOnce.Do(func() {
		options, err := readCompileOptions(conn)
		if err != nil {
			compileCheckErr = err
			return
		}

		required := parseCSVEnv("PATCHWORK_SQLITE_REQUIRED_COMPILE_OPTIONS")
		missingRequired := missingCompileOptions(options, required)
		if len(missingRequired) > 0 {
			compileCheckErr = fmt.Errorf(
				"sqlite missing required compile options: %s",
				strings.Join(missingRequired, ", "),
			)
			return
		}

		if !envBoolDefault("PATCHWORK_SQLITE_WARN_MISSING_COMPILE_OPTIONS", true) {
			return
		}

		recommended := recommendedCompileOptions
		if override := parseCSVEnv("PATCHWORK_SQLITE_RECOMMENDED_COMPILE_OPTIONS"); len(override) > 0 {
			recommended = override
		}
		missingRecommended := missingCompileOptions(options, recommended)
		if len(missingRecommended) > 0 {
			log.Printf("patchwork: sqlite compile options missing (recommended): %s", strings.Join(missingRecommended, ", "))
		}
	})
	return compileCheckErr
}

func readCompileOptions(conn *sqlite3.SQLiteConn) (map[string]struct{}, error) {
	rows, err := conn.Query("PRAGMA compile_options;", nil)
	if err != nil {
		return nil, fmt.Errorf("query sqlite compile options: %w", err)
	}
	defer rows.Close()

	options := make(map[string]struct{}, 32)
	dest := make([]driver.Value, 1)

	for {
		for i := range dest {
			dest[i] = nil
		}

		err := rows.Next(dest)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("iterate sqlite compile options: %w", err)
		}

		value := strings.TrimSpace(stringifyDriverValue(dest[0]))
		if value != "" {
			options[strings.ToUpper(value)] = struct{}{}
		}
	}

	return options, nil
}

func missingCompileOptions(actual map[string]struct{}, expected []string) []string {
	if len(expected) == 0 {
		return nil
	}

	missing := make([]string, 0, len(expected))
	for _, option := range expected {
		option = strings.TrimSpace(strings.ToUpper(option))
		if option == "" {
			continue
		}
		if _, ok := actual[option]; !ok {
			missing = append(missing, option)
		}
	}
	return missing
}

func loadConfiguredExtensions(conn *sqlite3.SQLiteConn) error {
	for _, group := range extensionGroupsFromEnv() {
		if err := loadExtensionGroup(conn, group); err != nil {
			return err
		}
	}
	return nil
}

func extensionGroupsFromEnv() []extensionGroup {
	groups := make([]extensionGroup, 0, 8)

	groups = append(groups, extensionGroup{
		label:             "crsqlite",
		entrypoint:        strings.TrimSpace(os.Getenv("PATCHWORK_SQLITE_EXTENSION_CRSQLITE_ENTRYPOINT")),
		defaultEntrypoint: "sqlite3_crsqlite_init",
		candidates: explicitOrDefaultCandidates(
			strings.TrimSpace(os.Getenv("PATCHWORK_SQLITE_EXTENSION_CRSQLITE")),
			"crsqlite",
			"crsqlite0",
		),
		required: strings.TrimSpace(os.Getenv("PATCHWORK_SQLITE_EXTENSION_CRSQLITE")) != "",
	})

	groups = append(groups, extensionGroup{
		label:             "sqlite-vec",
		entrypoint:        strings.TrimSpace(os.Getenv("PATCHWORK_SQLITE_EXTENSION_VEC_ENTRYPOINT")),
		defaultEntrypoint: "sqlite3_vec_init",
		candidates: explicitOrDefaultCandidates(
			strings.TrimSpace(os.Getenv("PATCHWORK_SQLITE_EXTENSION_VEC")),
			"vec0",
			"sqlite_vec",
		),
		required: strings.TrimSpace(os.Getenv("PATCHWORK_SQLITE_EXTENSION_VEC")) != "",
	})

	sqleanExplicit := strings.TrimSpace(os.Getenv("PATCHWORK_SQLITE_EXTENSION_SQLEAN"))
	groups = append(groups, extensionGroup{
		label:             "sqlean",
		entrypoint:        strings.TrimSpace(os.Getenv("PATCHWORK_SQLITE_EXTENSION_SQLEAN_ENTRYPOINT")),
		defaultEntrypoint: "sqlite3_sqlean_init",
		candidates:        explicitOrDefaultCandidates(sqleanExplicit, "sqlean"),
		required:          sqleanExplicit != "",
	})

	if sqleanDir := strings.TrimSpace(os.Getenv("PATCHWORK_SQLITE_EXTENSION_SQLEAN_DIR")); sqleanDir != "" {
		for _, module := range []string{"crypto", "math", "regexp", "stats", "text", "time", "unicode", "uuid"} {
			groups = append(groups, extensionGroup{
				label:             "sqlean-" + module,
				entrypoint:        "",
				defaultEntrypoint: "sqlite3_" + module + "_init",
				candidates:        moduleFileCandidates(filepath.Join(sqleanDir, module)),
				required:          true,
			})
		}
	}

	if extra := parseExtensionEnv("PATCHWORK_SQLITE_EXTENSIONS"); len(extra) > 0 {
		groups = append(groups, extra...)
	}

	return groups
}

func parseExtensionEnv(key string) []extensionGroup {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	groups := make([]extensionGroup, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		path := part
		entrypoint := ""
		if strings.Contains(part, "|") {
			tokens := strings.SplitN(part, "|", 2)
			path = strings.TrimSpace(tokens[0])
			entrypoint = strings.TrimSpace(tokens[1])
		}

		if path == "" {
			continue
		}

		groups = append(groups, extensionGroup{
			label:             "custom",
			entrypoint:        entrypoint,
			defaultEntrypoint: inferEntrypointFromPath(path),
			candidates:        moduleFileCandidates(path),
			required:          true,
		})
	}

	return groups
}

func loadExtensionGroup(conn *sqlite3.SQLiteConn, group extensionGroup) error {
	if len(group.candidates) == 0 {
		return nil
	}

	var (
		loadErr     error
		seen        = make(map[string]struct{}, len(group.candidates))
		triedUnique []string
	)

	for _, candidate := range group.candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		triedUnique = append(triedUnique, candidate)

		entrypoint := resolvedEntrypoint(group, candidate)
		if err := conn.LoadExtension(candidate, entrypoint); err != nil {
			if isMissingExtensionError(err) {
				continue
			}
			loadErr = err
			continue
		}

		return nil
	}

	if group.required {
		if loadErr != nil {
			return fmt.Errorf("load sqlite extension %q failed: %w", group.label, loadErr)
		}
		return fmt.Errorf("load sqlite extension %q failed: no candidate was loadable (%s)", group.label, strings.Join(triedUnique, ", "))
	}

	if loadErr != nil {
		logfOnce(
			"extension-load-failed:"+group.label,
			"patchwork: sqlite extension %q could not be loaded (%s): %v",
			group.label,
			strings.Join(triedUnique, ", "),
			loadErr,
		)
		return nil
	}

	logfOnce(
		"extension-not-found:"+group.label,
		"patchwork: sqlite extension %q not loaded (no loadable candidate from: %s)",
		group.label,
		strings.Join(triedUnique, ", "),
	)
	return nil
}

func explicitOrDefaultCandidates(explicit string, defaults ...string) []string {
	explicit = strings.TrimSpace(explicit)
	if explicit != "" {
		return moduleFileCandidates(explicit)
	}

	suffix := sharedLibrarySuffix()
	candidates := make([]string, 0, len(defaults)*4)
	for _, base := range defaults {
		base = strings.TrimSpace(base)
		if base == "" {
			continue
		}

		candidates = append(candidates, base)
		candidates = append(candidates, "lib"+base)
		if suffix != "" {
			candidates = append(candidates, base+suffix)
			candidates = append(candidates, "lib"+base+suffix)
		}
	}

	return candidates
}

func moduleFileCandidates(path string) []string {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}

	if ext := filepath.Ext(path); ext != "" {
		return []string{path}
	}

	suffix := sharedLibrarySuffix()
	if suffix == "" {
		return []string{path}
	}

	return []string{
		path,
		path + suffix,
	}
}

func resolvedEntrypoint(group extensionGroup, candidate string) string {
	if entrypoint := strings.TrimSpace(group.entrypoint); entrypoint != "" {
		return entrypoint
	}
	if entrypoint := strings.TrimSpace(group.defaultEntrypoint); entrypoint != "" {
		return entrypoint
	}
	if inferred := inferEntrypointFromPath(candidate); inferred != "" {
		return inferred
	}
	return "sqlite3_extension_init"
}

func inferEntrypointFromPath(path string) string {
	base := strings.TrimSpace(filepath.Base(path))
	if base == "" {
		return ""
	}
	base = strings.TrimSuffix(base, filepath.Ext(base))
	base = strings.TrimPrefix(base, "lib")
	base = strings.TrimSpace(base)
	if base == "" {
		return ""
	}

	base = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, base)
	return "sqlite3_" + base + "_init"
}

func sharedLibrarySuffix() string {
	switch runtime.GOOS {
	case "windows":
		return ".dll"
	case "darwin":
		return ".dylib"
	default:
		return ".so"
	}
}

func isMissingExtensionError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(msg, "no such file") ||
		strings.Contains(msg, "cannot open shared object file") ||
		strings.Contains(msg, "could not open extension") ||
		strings.Contains(msg, "the specified module could not be found") ||
		strings.Contains(msg, "image not found")
}

func parseCSVEnv(key string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		values = append(values, part)
	}
	return values
}

func envBoolDefault(key string, fallback bool) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if raw == "" {
		return fallback
	}

	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func stringifyDriverValue(v driver.Value) string {
	switch typed := v.(type) {
	case nil:
		return ""
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		return fmt.Sprintf("%v", typed)
	}
}

func logfOnce(key, format string, args ...any) {
	if _, loaded := extensionLogOnce.LoadOrStore(key, struct{}{}); loaded {
		return
	}
	log.Printf(format, args...)
}
