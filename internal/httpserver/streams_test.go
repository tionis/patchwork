package httpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tionis/patchwork/internal/auth"
)

func TestStreamQueueRoundTrip(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "stream-queue-client", []auth.Scope{
		{DBID: "ops", Action: "stream.read"},
		{DBID: "ops", Action: "stream.write"},
	})

	consumerResult := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/db/ops/streams/queue/jobs/next", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		env.server.Handler().ServeHTTP(rr, req)
		consumerResult <- rr
	}()

	time.Sleep(20 * time.Millisecond)

	producerReq := httptest.NewRequest(http.MethodPost, "/api/v1/db/ops/streams/queue/jobs", strings.NewReader("task-1"))
	producerReq.Header.Set("Authorization", "Bearer "+token)
	producerRR := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(producerRR, producerReq)

	if producerRR.Code != http.StatusOK {
		t.Fatalf("producer expected %d, got %d: %s", http.StatusOK, producerRR.Code, producerRR.Body.String())
	}

	select {
	case consumerRR := <-consumerResult:
		if consumerRR.Code != http.StatusOK {
			t.Fatalf("consumer expected %d, got %d: %s", http.StatusOK, consumerRR.Code, consumerRR.Body.String())
		}
		if got := consumerRR.Body.String(); got != "task-1" {
			t.Fatalf("unexpected consumer payload: %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for queue consumer")
	}
}

func TestStreamRequestResponderRoundTrip(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "stream-req-res", []auth.Scope{
		{DBID: "ops", Action: "stream.write"},
	})

	responderResult := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(
			http.MethodPost,
			"/api/v1/db/ops/streams/res/api/users",
			strings.NewReader(`{"id":123}`),
		)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Patch-Status", "201")
		req.Header.Set("Patch-H-X-Custom", "value-1")

		rr := httptest.NewRecorder()
		env.server.Handler().ServeHTTP(rr, req)
		responderResult <- rr
	}()

	time.Sleep(20 * time.Millisecond)

	requesterReq := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/db/ops/streams/req/api/users?trace=1",
		strings.NewReader(`{"name":"alice"}`),
	)
	requesterReq.Header.Set("Authorization", "Bearer "+token)
	requesterReq.Header.Set("Content-Type", "application/json")
	requesterReq.Header.Set("User-Agent", "patchwork-test")

	requesterRR := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(requesterRR, requesterReq)

	if requesterRR.Code != http.StatusCreated {
		t.Fatalf("requester expected %d, got %d: %s", http.StatusCreated, requesterRR.Code, requesterRR.Body.String())
	}
	if got := requesterRR.Body.String(); got != `{"id":123}` {
		t.Fatalf("unexpected requester payload: %q", got)
	}
	if got := requesterRR.Header().Get("X-Custom"); got != "value-1" {
		t.Fatalf("unexpected passthrough header: %q", got)
	}

	select {
	case responderRR := <-responderResult:
		if responderRR.Code != http.StatusOK {
			t.Fatalf("responder expected %d, got %d: %s", http.StatusOK, responderRR.Code, responderRR.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for responder completion")
	}
}

func TestStreamResponderSwitchMode(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "stream-switch", []auth.Scope{
		{DBID: "ops", Action: "stream.write"},
	})

	requesterResult := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(
			http.MethodPost,
			"/api/v1/db/ops/streams/req/myservice",
			strings.NewReader(`{"task":"process"}`),
		)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		env.server.Handler().ServeHTTP(rr, req)
		requesterResult <- rr
	}()

	time.Sleep(20 * time.Millisecond)

	switchReq := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/db/ops/streams/res/myservice?switch=true",
		strings.NewReader("worker-123"),
	)
	switchReq.Header.Set("Authorization", "Bearer "+token)
	switchRR := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(switchRR, switchReq)

	if switchRR.Code != http.StatusOK {
		t.Fatalf("switch responder expected %d, got %d: %s", http.StatusOK, switchRR.Code, switchRR.Body.String())
	}
	if got := switchRR.Body.String(); got != `{"task":"process"}` {
		t.Fatalf("unexpected switch request payload: %q", got)
	}

	workerReq := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/db/ops/streams/queue/worker-123",
		strings.NewReader(`{"result":"completed"}`),
	)
	workerReq.Header.Set("Authorization", "Bearer "+token)
	workerReq.Header.Set("Content-Type", "application/json")
	workerRR := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(workerRR, workerReq)

	if workerRR.Code != http.StatusOK {
		t.Fatalf("worker response expected %d, got %d: %s", http.StatusOK, workerRR.Code, workerRR.Body.String())
	}

	select {
	case requesterRR := <-requesterResult:
		if requesterRR.Code != http.StatusOK {
			t.Fatalf("requester expected %d, got %d: %s", http.StatusOK, requesterRR.Code, requesterRR.Body.String())
		}
		if got := requesterRR.Body.String(); got != `{"result":"completed"}` {
			t.Fatalf("unexpected requester switch response payload: %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for switched requester response")
	}
}
