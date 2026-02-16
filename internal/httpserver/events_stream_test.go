package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tionis/patchwork/internal/auth"
)

func TestMessageStreamReplaySinceIDWithWildcardFilter(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "stream-replay", []auth.Scope{
		{DBID: "msgstream", Action: "pub.publish"},
		{DBID: "msgstream", Action: "pub.subscribe"},
	})

	firstID := publishMessageForTest(t, env, token, "msgstream", "alpha/one", `{"v":1}`)
	_ = publishMessageForTest(t, env, token, "msgstream", "alpha/two", `{"v":2}`)
	_ = publishMessageForTest(t, env, token, "msgstream", "beta/one", `{"v":3}`)

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	req := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/db/msgstream/events/stream?topic=alpha/%2B&since_id="+strconv.FormatInt(firstID, 10),
		nil,
	).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}

	body := rr.Body.String()
	if !strings.Contains(body, `"topic":"alpha/two"`) {
		t.Fatalf("expected alpha/two replay event, got body: %s", body)
	}
	if strings.Contains(body, `"topic":"beta/one"`) {
		t.Fatalf("did not expect beta/one event, got body: %s", body)
	}
}

func TestMessageStreamTailReplay(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "stream-tail", []auth.Scope{
		{DBID: "msgstream", Action: "pub.publish"},
		{DBID: "msgstream", Action: "pub.subscribe"},
	})

	_ = publishMessageForTest(t, env, token, "msgstream", "sensor/a", `{"v":1}`)
	_ = publishMessageForTest(t, env, token, "msgstream", "sensor/b", `{"v":2}`)
	_ = publishMessageForTest(t, env, token, "msgstream", "sensor/c", `{"v":3}`)

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	req := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/db/msgstream/events/stream?topic=sensor/%23&tail=2",
		nil,
	).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}

	body := rr.Body.String()
	if strings.Contains(body, `"topic":"sensor/a"`) {
		t.Fatalf("did not expect oldest message in tail replay, got body: %s", body)
	}
	if !strings.Contains(body, `"topic":"sensor/b"`) || !strings.Contains(body, `"topic":"sensor/c"`) {
		t.Fatalf("expected sensor/b and sensor/c in tail replay, got body: %s", body)
	}
}

func TestMessageStreamLiveDelivery(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "stream-live", []auth.Scope{
		{DBID: "msgstream", Action: "pub.publish"},
		{DBID: "msgstream", Action: "pub.subscribe"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(
			http.MethodGet,
			"/api/v1/db/msgstream/events/stream?topic=live/%23",
			nil,
		).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer "+token)

		rr := httptest.NewRecorder()
		env.server.Handler().ServeHTTP(rr, req)
		done <- rr
	}()

	time.Sleep(180 * time.Millisecond)
	_ = publishMessageForTest(t, env, token, "msgstream", "live/now", `{"ok":true}`)

	select {
	case rr := <-done:
		if rr.Code != http.StatusOK {
			t.Fatalf("expected %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), `"topic":"live/now"`) {
			t.Fatalf("expected live message event, got body: %s", rr.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for live stream response")
	}
}

func TestMessageStreamRejectsInvalidFilter(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "stream-invalid", []auth.Scope{
		{DBID: "msgstream", Action: "pub.subscribe"},
	})

	req := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/db/msgstream/events/stream?topic=a/%23/b",
		nil,
	)
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}
}

func publishMessageForTest(t *testing.T, env *webhookTestEnv, token, dbID, topic, payloadJSON string) int64 {
	t.Helper()

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/db/"+dbID+"/messages",
		strings.NewReader(`{"topic":"`+topic+`","payload":`+payloadJSON+`}`),
	)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("publish expected %d, got %d: %s", http.StatusCreated, rr.Code, rr.Body.String())
	}

	var payload struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("parse publish response: %v", err)
	}
	if payload.ID <= 0 {
		t.Fatalf("invalid message id in response: %d", payload.ID)
	}

	return payload.ID
}
