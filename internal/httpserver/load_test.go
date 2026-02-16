package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tionis/patchwork/internal/auth"
)

func TestLoadQueryWatchUnderWriteLoad(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	adminToken := env.issueTokenWithScopes(t, "load-query-admin", []auth.Scope{
		{DBID: "loaddb", Action: "query.admin"},
		{DBID: "loaddb", Action: "query.read"},
		{DBID: "loaddb", Action: "query.write"},
	})
	readToken := env.issueTokenWithScopes(t, "load-query-read", []auth.Scope{
		{DBID: "loaddb", Action: "query.read"},
	})
	writeToken := env.issueTokenWithScopes(t, "load-query-write", []auth.Scope{
		{DBID: "loaddb", Action: "query.write"},
	})

	createRR := execQuery(t, env, adminToken, "loaddb", `{"sql":"CREATE TABLE IF NOT EXISTS load_items (id INTEGER PRIMARY KEY, val TEXT NOT NULL)"}`)
	if createRR.Code != http.StatusOK {
		t.Fatalf("create table expected %d, got %d: %s", http.StatusOK, createRR.Code, createRR.Body.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(
			http.MethodPost,
			"/api/v1/db/loaddb/query/watch",
			strings.NewReader(`{"sql":"SELECT id, val FROM load_items ORDER BY id","options":{"heartbeat_seconds":1}}`),
		).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer "+readToken)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		env.server.Handler().ServeHTTP(rr, req)
		done <- rr
	}()

	for i := 0; i < 20; i++ {
		insertRR := execQuery(
			t,
			env,
			writeToken,
			"loaddb",
			`{"sql":"INSERT INTO load_items(val) VALUES (?)","args":["v-`+strconv.Itoa(i)+`"]}`,
		)
		if insertRR.Code != http.StatusOK {
			t.Fatalf("insert expected %d, got %d: %s", http.StatusOK, insertRR.Code, insertRR.Body.String())
		}
	}

	select {
	case rr := <-done:
		if rr.Code != http.StatusOK {
			t.Fatalf("watch expected %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "event: update") {
			t.Fatalf("expected watch update events under load, got body: %s", rr.Body.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for watch load test")
	}
}

func TestLoadMessageReplayFanout(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "load-message", []auth.Scope{
		{DBID: "msgload", Action: "pub.publish"},
		{DBID: "msgload", Action: "pub.subscribe"},
	})

	for i := 0; i < 40; i++ {
		_ = publishMessageForTest(t, env, token, "msgload", "load/events", `{"idx":`+strconv.Itoa(i)+`}`)
	}

	var wg sync.WaitGroup
	errCh := make(chan string, 3)

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
			defer cancel()

			req := httptest.NewRequest(
				http.MethodGet,
				"/api/v1/db/msgload/events/stream?topic=load/events&tail=40",
				nil,
			).WithContext(ctx)
			req.Header.Set("Authorization", "Bearer "+token)

			rr := httptest.NewRecorder()
			env.server.Handler().ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				errCh <- "unexpected status " + strconv.Itoa(rr.Code)
				return
			}
			count := strings.Count(rr.Body.String(), `"topic":"load/events"`)
			if count < 40 {
				errCh <- "expected at least 40 replay events, got " + strconv.Itoa(count)
			}
		}()
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}

func TestLoadHighConcurrencyStreams(t *testing.T) {
	env := newWebhookTestEnv(t)
	defer env.close()

	token := env.issueTokenWithScopes(t, "load-stream", []auth.Scope{
		{DBID: "streamload", Action: "stream.read"},
		{DBID: "streamload", Action: "stream.write"},
	})

	const workers = 20
	type result struct {
		err     string
		payload string
	}

	consumerResults := make(chan result, workers)
	for i := 0; i < workers; i++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/db/streamload/streams/queue/jobs/next", nil).WithContext(ctx)
			req.Header.Set("Authorization", "Bearer "+token)
			rr := httptest.NewRecorder()
			env.server.Handler().ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				consumerResults <- result{err: "consumer status " + strconv.Itoa(rr.Code)}
				return
			}
			consumerResults <- result{payload: rr.Body.String()}
		}()
	}

	time.Sleep(120 * time.Millisecond)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			payload := "job-" + strconv.Itoa(i)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/db/streamload/streams/queue/jobs", strings.NewReader(payload))
			req.Header.Set("Authorization", "Bearer "+token)
			rr := httptest.NewRecorder()
			env.server.Handler().ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("producer %d status %d: %s", i, rr.Code, rr.Body.String())
			}
		}(i)
	}
	wg.Wait()

	received := make(map[string]int)
	for i := 0; i < workers; i++ {
		select {
		case res := <-consumerResults:
			if res.err != "" {
				t.Fatalf("consumer error: %s", res.err)
			}
			received[res.payload]++
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for stream consumers")
		}
	}

	if len(received) != workers {
		t.Fatalf("expected %d unique stream payloads, got %d", workers, len(received))
	}
}
