package auth

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/tionis/patchwork/internal/migrations"
)

func TestIssueAuthenticateRevoke(t *testing.T) {
	ctx := context.Background()
	baseDir := t.TempDir()
	serviceDBPath := baseDir + "/service.db"
	documentsDir := baseDir + "/documents"

	if err := migrations.BootstrapService(ctx, baseDir, documentsDir, serviceDBPath); err != nil {
		t.Fatalf("bootstrap service: %v", err)
	}

	svc, err := NewService(serviceDBPath, "bootstrap-secret", slog.Default())
	if err != nil {
		t.Fatalf("new auth service: %v", err)
	}
	defer svc.Close()

	bootstrap, err := svc.AuthenticateToken(ctx, "bootstrap-secret")
	if err != nil {
		t.Fatalf("authenticate bootstrap token: %v", err)
	}
	if !bootstrap.IsAdmin || !bootstrap.IsBootstrap {
		t.Fatalf("bootstrap principal mismatch: %+v", bootstrap)
	}

	expiresAt := time.Now().Add(30 * time.Minute).UTC()
	issued, err := svc.IssueToken(ctx, IssueTokenRequest{
		Label:   "worker-a",
		IsAdmin: false,
		Scopes: []Scope{
			{DBID: "public", Action: "query.read"},
			{DBID: "public", Action: "stream.write", ResourcePrefix: "jobs/"},
		},
		ExpiresAt: &expiresAt,
	})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	if issued.Token == "" || issued.ID == "" {
		t.Fatalf("issued token missing values: %+v", issued)
	}

	principal, err := svc.AuthenticateToken(ctx, issued.Token)
	if err != nil {
		t.Fatalf("authenticate issued token: %v", err)
	}

	if err := principal.Authorize("public", "query.read", ""); err != nil {
		t.Fatalf("expected query.read auth: %v", err)
	}
	if err := principal.Authorize("public", "stream.write", "jobs/123"); err != nil {
		t.Fatalf("expected scoped stream.write auth: %v", err)
	}
	if err := principal.Authorize("public", "stream.write", "other/123"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected forbidden for mismatched prefix, got: %v", err)
	}

	tokens, err := svc.ListTokens(ctx)
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(tokens))
	}

	if err := svc.RevokeToken(ctx, issued.ID); err != nil {
		t.Fatalf("revoke token: %v", err)
	}

	_, err = svc.AuthenticateToken(ctx, issued.Token)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected unauthorized after revoke, got: %v", err)
	}
}

func TestIssueTokenValidation(t *testing.T) {
	ctx := context.Background()
	baseDir := t.TempDir()
	serviceDBPath := baseDir + "/service.db"
	documentsDir := baseDir + "/documents"

	if err := migrations.BootstrapService(ctx, baseDir, documentsDir, serviceDBPath); err != nil {
		t.Fatalf("bootstrap service: %v", err)
	}

	svc, err := NewService(serviceDBPath, "", slog.Default())
	if err != nil {
		t.Fatalf("new auth service: %v", err)
	}
	defer svc.Close()

	_, err = svc.IssueToken(ctx, IssueTokenRequest{Label: "", IsAdmin: false})
	if err == nil {
		t.Fatal("expected validation error for empty label")
	}

	_, err = svc.IssueToken(ctx, IssueTokenRequest{Label: "no-scopes", IsAdmin: false})
	if err == nil {
		t.Fatal("expected validation error for missing scopes")
	}

	past := time.Now().Add(-1 * time.Minute)
	_, err = svc.IssueToken(ctx, IssueTokenRequest{Label: "past", IsAdmin: true, ExpiresAt: &past})
	if err == nil {
		t.Fatal("expected validation error for past expiry")
	}
}
