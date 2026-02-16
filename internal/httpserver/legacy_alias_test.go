package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tionis/patchwork/internal/auth"
)

func TestLegacyPublicQueueAliasRoundTrip(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "legacy-public", []auth.Scope{
		{DBID: "public", Action: "stream.read"},
		{DBID: "public", Action: "stream.write"},
	})

	consumerDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(http.MethodGet, "/public/queue/jobs", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		env.server.Handler().ServeHTTP(rr, req)
		consumerDone <- rr
	}()

	time.Sleep(20 * time.Millisecond)

	producerReq := httptest.NewRequest(http.MethodPost, "/public/queue/jobs", strings.NewReader("job-1"))
	producerReq.Header.Set("Authorization", "Bearer "+token)
	producerRR := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(producerRR, producerReq)

	if producerRR.Code != http.StatusOK {
		t.Fatalf("producer expected %d, got %d: %s", http.StatusOK, producerRR.Code, producerRR.Body.String())
	}

	select {
	case consumerRR := <-consumerDone:
		if consumerRR.Code != http.StatusOK {
			t.Fatalf("consumer expected %d, got %d: %s", http.StatusOK, consumerRR.Code, consumerRR.Body.String())
		}
		if got := consumerRR.Body.String(); got != "job-1" {
			t.Fatalf("unexpected consumer body: %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for alias consumer response")
	}
}

func TestLegacyPublicPubsubAliasIsNonBlockingWithoutConsumers(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "legacy-pubsub", []auth.Scope{
		{DBID: "public", Action: "stream.write"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	req := httptest.NewRequest(http.MethodPost, "/p/pubsub/events", strings.NewReader("event-1")).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("pubsub alias expected %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}
}

func TestLegacyUserAliasRequestResponder(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "legacy-user-req-res", []auth.Scope{
		{DBID: "alice", Action: "stream.write"},
	})

	responderDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(
			http.MethodPost,
			"/u/alice/res/api/users",
			strings.NewReader(`{"ok":true}`),
		)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Patch-Status", "202")

		rr := httptest.NewRecorder()
		env.server.Handler().ServeHTTP(rr, req)
		responderDone <- rr
	}()

	time.Sleep(20 * time.Millisecond)

	requesterReq := httptest.NewRequest(
		http.MethodPost,
		"/u/alice/req/api/users",
		strings.NewReader(`{"name":"alice"}`),
	)
	requesterReq.Header.Set("Authorization", "Bearer "+token)
	requesterRR := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(requesterRR, requesterReq)

	if requesterRR.Code != http.StatusAccepted {
		t.Fatalf("requester expected %d, got %d: %s", http.StatusAccepted, requesterRR.Code, requesterRR.Body.String())
	}
	if got := requesterRR.Body.String(); got != `{"ok":true}` {
		t.Fatalf("unexpected requester body: %q", got)
	}

	select {
	case responderRR := <-responderDone:
		if responderRR.Code != http.StatusOK {
			t.Fatalf("responder expected %d, got %d: %s", http.StatusOK, responderRR.Code, responderRR.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for responder completion")
	}
}
