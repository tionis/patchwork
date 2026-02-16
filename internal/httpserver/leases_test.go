package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tionis/patchwork/internal/auth"
)

func TestLeaseAcquireRenewReleaseFlow(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "lease-full", []auth.Scope{
		{DBID: "leasedb", Action: "lease.acquire"},
		{DBID: "leasedb", Action: "lease.renew"},
		{DBID: "leasedb", Action: "lease.release"},
	})
	otherToken := env.issueTokenWithScopes(t, "lease-other", []auth.Scope{
		{DBID: "leasedb", Action: "lease.acquire"},
	})

	acquireRR := execLeaseRequest(
		t,
		env,
		token,
		"leasedb",
		"/api/v1/db/leasedb/leases/acquire",
		`{"resource":"jobs/worker","owner":"worker-a","ttl_seconds":30}`,
	)
	if acquireRR.Code != http.StatusOK {
		t.Fatalf("acquire expected %d, got %d: %s", http.StatusOK, acquireRR.Code, acquireRR.Body.String())
	}

	var acquirePayload struct {
		Fence int64  `json:"fence"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(acquireRR.Body.Bytes(), &acquirePayload); err != nil {
		t.Fatalf("decode acquire payload: %v", err)
	}
	if acquirePayload.Fence != 1 {
		t.Fatalf("expected fence=1, got %d", acquirePayload.Fence)
	}
	if acquirePayload.Token == "" {
		t.Fatal("expected lease token from acquire")
	}

	conflictAcquire := execLeaseRequest(
		t,
		env,
		otherToken,
		"leasedb",
		"/api/v1/db/leasedb/leases/acquire",
		`{"resource":"jobs/worker","owner":"worker-b","ttl_seconds":30}`,
	)
	if conflictAcquire.Code != http.StatusConflict {
		t.Fatalf("conflict acquire expected %d, got %d: %s", http.StatusConflict, conflictAcquire.Code, conflictAcquire.Body.String())
	}

	renewRR := execLeaseRequest(
		t,
		env,
		token,
		"leasedb",
		"/api/v1/db/leasedb/leases/renew",
		`{"resource":"jobs/worker","owner":"worker-a","token":"`+acquirePayload.Token+`","ttl_seconds":30}`,
	)
	if renewRR.Code != http.StatusOK {
		t.Fatalf("renew expected %d, got %d: %s", http.StatusOK, renewRR.Code, renewRR.Body.String())
	}

	var renewPayload struct {
		Fence int64 `json:"fence"`
	}
	if err := json.Unmarshal(renewRR.Body.Bytes(), &renewPayload); err != nil {
		t.Fatalf("decode renew payload: %v", err)
	}
	if renewPayload.Fence != 1 {
		t.Fatalf("expected fence to stay at 1 on renew, got %d", renewPayload.Fence)
	}

	unauthorizedRelease := execLeaseRequest(
		t,
		env,
		token,
		"leasedb",
		"/api/v1/db/leasedb/leases/release",
		`{"resource":"jobs/worker","owner":"worker-a","token":"invalid"}`,
	)
	if unauthorizedRelease.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized release expected %d, got %d: %s", http.StatusUnauthorized, unauthorizedRelease.Code, unauthorizedRelease.Body.String())
	}

	releaseRR := execLeaseRequest(
		t,
		env,
		token,
		"leasedb",
		"/api/v1/db/leasedb/leases/release",
		`{"resource":"jobs/worker","owner":"worker-a","token":"`+acquirePayload.Token+`"}`,
	)
	if releaseRR.Code != http.StatusOK {
		t.Fatalf("release expected %d, got %d: %s", http.StatusOK, releaseRR.Code, releaseRR.Body.String())
	}

	reacquireRR := execLeaseRequest(
		t,
		env,
		otherToken,
		"leasedb",
		"/api/v1/db/leasedb/leases/acquire",
		`{"resource":"jobs/worker","owner":"worker-b","ttl_seconds":30}`,
	)
	if reacquireRR.Code != http.StatusOK {
		t.Fatalf("reacquire expected %d, got %d: %s", http.StatusOK, reacquireRR.Code, reacquireRR.Body.String())
	}

	var reacquirePayload struct {
		Fence int64 `json:"fence"`
	}
	if err := json.Unmarshal(reacquireRR.Body.Bytes(), &reacquirePayload); err != nil {
		t.Fatalf("decode reacquire payload: %v", err)
	}
	if reacquirePayload.Fence != 2 {
		t.Fatalf("expected monotonic fence=2 after reacquire, got %d", reacquirePayload.Fence)
	}
}

func TestLeaseAcquireConcurrentContention(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "lease-contended", []auth.Scope{
		{DBID: "leasedb", Action: "lease.acquire"},
	})

	var wg sync.WaitGroup
	wg.Add(2)

	results := make(chan int, 2)
	acquire := func(owner string) {
		defer wg.Done()
		rr := execLeaseRequest(
			t,
			env,
			token,
			"leasedb",
			"/api/v1/db/leasedb/leases/acquire",
			`{"resource":"jobs/contended","owner":"`+owner+`","ttl_seconds":30}`,
		)
		results <- rr.Code
	}

	go acquire("owner-a")
	go acquire("owner-b")

	wg.Wait()
	close(results)

	var okCount, conflictCount int
	for code := range results {
		if code == http.StatusOK {
			okCount++
		}
		if code == http.StatusConflict {
			conflictCount++
		}
	}

	if okCount != 1 || conflictCount != 1 {
		t.Fatalf("expected one success and one conflict, got success=%d conflict=%d", okCount, conflictCount)
	}
}

func TestLeaseRenewExpiredLeaseReturnsNotFound(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "lease-expire", []auth.Scope{
		{DBID: "leasedb", Action: "lease.acquire"},
		{DBID: "leasedb", Action: "lease.renew"},
	})

	acquireRR := execLeaseRequest(
		t,
		env,
		token,
		"leasedb",
		"/api/v1/db/leasedb/leases/acquire",
		`{"resource":"jobs/short","owner":"worker-a","ttl_seconds":1}`,
	)
	if acquireRR.Code != http.StatusOK {
		t.Fatalf("acquire expected %d, got %d: %s", http.StatusOK, acquireRR.Code, acquireRR.Body.String())
	}

	var payload struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(acquireRR.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode acquire payload: %v", err)
	}

	time.Sleep(1100 * time.Millisecond)

	renewRR := execLeaseRequest(
		t,
		env,
		token,
		"leasedb",
		"/api/v1/db/leasedb/leases/renew",
		`{"resource":"jobs/short","owner":"worker-a","token":"`+payload.Token+`","ttl_seconds":30}`,
	)
	if renewRR.Code != http.StatusNotFound {
		t.Fatalf("expected %d, got %d: %s", http.StatusNotFound, renewRR.Code, renewRR.Body.String())
	}
}

func execLeaseRequest(t *testing.T, env *webhookTestEnv, token, _ string, path, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rr, req)
	return rr
}
