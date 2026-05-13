package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const patchworkScript = "assets/patchwork.sh"

func runPatchworkScript(t *testing.T, env []string, args ...string) (string, string, error) {
	t.Helper()

	cmd := exec.Command("bash", append([]string{patchworkScript}, args...)...)
	cmd.Env = append(os.Environ(), env...)

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func TestPatchworkScriptStaticValidation(t *testing.T) {
	if output, err := exec.Command("bash", "-n", patchworkScript).CombinedOutput(); err != nil {
		t.Fatalf("bash syntax validation failed: %v\n%s", err, output)
	}

	if _, err := exec.LookPath("shellcheck"); err != nil {
		t.Skip("shellcheck not installed")
	}

	if output, err := exec.Command("shellcheck", patchworkScript).CombinedOutput(); err != nil {
		t.Fatalf("shellcheck failed: %v\n%s", err, output)
	}
}

func TestPatchworkScriptHelpListsCoreCommands(t *testing.T) {
	stdout, stderr, err := runPatchworkScript(t, nil, "help")
	if err != nil {
		t.Fatalf("help failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	for _, want := range []string{"send", "receive", "listen", "share", "download"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("help output missing %q:\n%s", want, stdout)
		}
	}
}

func TestPatchworkScriptSendBuildsPostRequest(t *testing.T) {
	tempDir := t.TempDir()
	curlLog := filepath.Join(tempDir, "curl.log")
	curlPath := filepath.Join(tempDir, "curl")

	curlStub := `#!/usr/bin/env bash
{
  printf 'args:'
  for arg in "$@"; do printf '<%s>' "$arg"; done
  printf '\nstdin:'
  cat
  printf '\n'
} > "$PATCHWORK_CURL_LOG"
printf 'stub response'
`
	if err := os.WriteFile(curlPath, []byte(curlStub), 0o755); err != nil {
		t.Fatalf("failed to write curl stub: %v", err)
	}

	env := []string{
		"PATCHWORK_SERVER=http://patchwork.test",
		"PATCHWORK_CURL_LOG=" + curlLog,
		"PATH=" + tempDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	}

	stdout, stderr, err := runPatchworkScript(t, env, "send", "-n", "u", "-t", "token123", "alice/queue/jobs", "deploy complete")
	if err != nil {
		t.Fatalf("send failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	if stdout != "stub response" {
		t.Fatalf("unexpected stdout %q", stdout)
	}

	logData, err := os.ReadFile(curlLog)
	if err != nil {
		t.Fatalf("failed to read curl log: %v", err)
	}
	log := string(logData)

	for _, want := range []string{
		"args:<-s><-X><POST><--data-binary><@-><http://patchwork.test/u/alice/queue/jobs?token=token123>",
		"stdin:deploy complete",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("curl log missing %q:\n%s", want, log)
		}
	}
}

func TestPatchworkScriptReceiveBuildsGetRequestWithTimeout(t *testing.T) {
	tempDir := t.TempDir()
	curlLog := filepath.Join(tempDir, "curl.log")
	curlPath := filepath.Join(tempDir, "curl")

	curlStub := `#!/usr/bin/env bash
{
  printf 'args:'
  for arg in "$@"; do printf '<%s>' "$arg"; done
  printf '\n'
} > "$PATCHWORK_CURL_LOG"
printf 'received'
`
	if err := os.WriteFile(curlPath, []byte(curlStub), 0o755); err != nil {
		t.Fatalf("failed to write curl stub: %v", err)
	}

	env := []string{
		"PATCHWORK_SERVER=http://patchwork.test",
		"PATCHWORK_CURL_LOG=" + curlLog,
		"PATH=" + tempDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	}

	stdout, stderr, err := runPatchworkScript(t, env, "receive", "-n", "r", "-s", "secret123", "-T", "5", "reverse-channel")
	if err != nil {
		t.Fatalf("receive failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	if stdout != "received" {
		t.Fatalf("unexpected stdout %q", stdout)
	}

	logData, err := os.ReadFile(curlLog)
	if err != nil {
		t.Fatalf("failed to read curl log: %v", err)
	}
	want := "args:<-s><--max-time><5><http://patchwork.test/r/reverse-channel?secret=secret123>"
	if log := string(logData); !strings.Contains(log, want) {
		t.Fatalf("curl log missing %q:\n%s", want, log)
	}
}

func TestPatchworkScriptErrorsOnMissingChannel(t *testing.T) {
	stdout, stderr, err := runPatchworkScript(t, nil, "send")
	if err == nil {
		t.Fatalf("expected missing channel to fail\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(stdout, "Channel name required") {
		t.Fatalf("expected missing channel error, got stdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
}
