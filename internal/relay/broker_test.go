package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestQueueStreamsBeforeProducerEOF(t *testing.T) {
	t.Parallel()

	broker := NewBroker()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	source, upload := io.Pipe()
	stream := NewStream(source, map[string]string{"Content-Type": "text/plain"}, -1)
	sendDone := make(chan error, 1)
	go func() { sendDone <- broker.Send(ctx, "stream", stream) }()

	received, err := broker.Receive(ctx, "stream")
	if err != nil {
		t.Fatalf("Receive failed: %v", err)
	}

	writeDone := make(chan error, 1)
	go func() {
		_, err := upload.Write([]byte("first"))
		writeDone <- err
	}()

	buffer := make([]byte, len("first"))
	if _, err := io.ReadFull(received.Body, buffer); err != nil {
		t.Fatalf("read first chunk: %v", err)
	}
	if got := string(buffer); got != "first" {
		t.Fatalf("got first chunk %q", got)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write first chunk: %v", err)
	}
	select {
	case err := <-sendDone:
		t.Fatalf("Send returned before the upload ended: %v", err)
	default:
	}

	go func() {
		_, err := upload.Write([]byte("-second"))
		if err == nil {
			err = upload.Close()
		}
		writeDone <- err
	}()
	rest, err := io.ReadAll(received.Body)
	if err != nil {
		t.Fatalf("read remaining stream: %v", err)
	}
	received.Complete(nil)
	if got := string(rest); got != "-second" {
		t.Fatalf("got remaining stream %q", got)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write remaining stream: %v", err)
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	if got := stream.BytesRead(); got != int64(len("first-second")) {
		t.Fatalf("counted %d streamed bytes", got)
	}
}

func TestQueuePairsConcurrentStreamsExactlyOnce(t *testing.T) {
	t.Parallel()

	const messages = 128
	broker := NewBroker()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	received := make(chan string, messages)
	errs := make(chan error, messages*2)
	var wg sync.WaitGroup
	for range messages {
		wg.Go(func() {
			stream, err := broker.Receive(ctx, "jobs")
			if err != nil {
				errs <- err
				return
			}
			body, err := io.ReadAll(stream.Body)
			stream.Complete(err)
			if err != nil {
				errs <- err
				return
			}
			received <- string(body)
		})
	}
	for i := range messages {
		wg.Go(func() {
			body := fmt.Sprintf("message-%03d", i)
			stream := NewStream(io.NopCloser(strings.NewReader(body)), nil, int64(len(body)))
			errs <- broker.Send(ctx, "jobs", stream)
		})
	}
	wg.Wait()
	close(errs)
	close(received)

	for err := range errs {
		if err != nil {
			t.Fatalf("queue operation failed: %v", err)
		}
	}
	seen := make(map[string]bool, messages)
	for body := range received {
		if seen[body] {
			t.Fatalf("stream delivered more than once: %q", body)
		}
		seen[body] = true
	}
	if len(seen) != messages {
		t.Fatalf("received %d unique streams, want %d", len(seen), messages)
	}
	if got := broker.ActiveChannels(); got != 0 {
		t.Fatalf("broker retained %d idle channels", got)
	}
}

func TestQueueCancellationAbortsInFlightStream(t *testing.T) {
	t.Parallel()

	broker := NewBroker()
	ctx, cancel := context.WithCancel(context.Background())
	source, _ := io.Pipe()
	stream := NewStream(source, nil, -1)
	sendDone := make(chan error, 1)
	go func() { sendDone <- broker.Send(ctx, "channel", stream) }()

	received, err := broker.Receive(context.Background(), "channel")
	if err != nil {
		t.Fatalf("Receive failed: %v", err)
	}
	cancel()
	if err := <-sendDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("Send returned %v, want context.Canceled", err)
	}
	if _, err := received.Body.Read(make([]byte, 1)); err == nil {
		t.Fatal("aborted stream remained readable")
	}
	received.Complete(nil)
	if got := broker.ActiveChannels(); got != 0 {
		t.Fatalf("broker retained %d canceled channels", got)
	}
}

func TestBroadcastStreamsToSnapshotWithBackpressure(t *testing.T) {
	t.Parallel()

	const subscriberCount = 8
	broker := NewBroker()
	subscriptions := make([]*Subscription, subscriberCount)
	for i := range subscriptions {
		subscriptions[i] = broker.Subscribe("events")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	source, upload := io.Pipe()
	type result struct {
		subscribers int
		bytes       int64
		err         error
	}
	broadcastDone := make(chan result, 1)
	go func() {
		subscribers, bytes, err := broker.Broadcast(
			ctx,
			"events",
			source,
			map[string]string{"X-Event": "original"},
			-1,
		)
		broadcastDone <- result{subscribers: subscribers, bytes: bytes, err: err}
	}()

	streams := make([]*Stream, subscriberCount)
	for i, subscription := range subscriptions {
		stream, err := subscription.Receive(ctx)
		if err != nil {
			t.Fatalf("subscriber %d failed to receive stream: %v", i, err)
		}
		streams[i] = stream
	}

	writeDone := make(chan error, 1)
	type readResult struct {
		index int
		body  string
		err   error
	}
	readDone := make(chan readResult, subscriberCount)
	for i, stream := range streams {
		go func() {
			body := make([]byte, len("broadcast"))
			_, err := io.ReadFull(stream.Body, body)
			readDone <- readResult{index: i, body: string(body), err: err}
		}()
	}
	go func() {
		_, err := upload.Write([]byte("broadcast"))
		writeDone <- err
	}()

	for range streams {
		result := <-readDone
		if result.err != nil {
			t.Fatalf("subscriber %d read failed: %v", result.index, result.err)
		}
		if result.body != "broadcast" {
			t.Fatalf("subscriber %d got %q", result.index, result.body)
		}
		if got := streams[result.index].Headers["X-Event"]; got != "original" {
			t.Fatalf("subscriber %d got header %q", result.index, got)
		}
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("upload failed: %v", err)
	}
	select {
	case result := <-broadcastDone:
		t.Fatalf("Broadcast returned before source EOF: %+v", result)
	default:
	}
	if err := upload.Close(); err != nil {
		t.Fatalf("close upload: %v", err)
	}
	for _, stream := range streams {
		stream.Complete(nil)
	}

	gotResult := <-broadcastDone
	if gotResult.err != nil {
		t.Fatalf("Broadcast failed: %v", gotResult.err)
	}
	if gotResult.subscribers != subscriberCount || gotResult.bytes != int64(len("broadcast")) {
		t.Fatalf("unexpected Broadcast result: %+v", gotResult)
	}
	if got := broker.ActiveChannels(); got != 0 {
		t.Fatalf("broker retained %d idle channels", got)
	}
}

func TestSubscriptionCancellationAndCloseAreIdempotent(t *testing.T) {
	t.Parallel()

	broker := NewBroker()
	subscription := broker.Subscribe("events")
	subscription.Close()
	subscription.Close()

	subscribers, bytes, err := broker.Broadcast(
		context.Background(),
		"events",
		io.NopCloser(strings.NewReader("ignored")),
		nil,
		7,
	)
	if err != nil || subscribers != 0 || bytes != 0 {
		t.Fatalf("closed subscription received broadcast: subscribers=%d bytes=%d err=%v", subscribers, bytes, err)
	}
	if got := broker.ActiveChannels(); got != 0 {
		t.Fatalf("broker retained %d idle channels", got)
	}
}

func TestBroadcastContinuesAfterSubscriberDisconnects(t *testing.T) {
	t.Parallel()

	broker := NewBroker()
	disconnected := broker.Subscribe("events")
	connected := broker.Subscribe("events")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	type result struct {
		subscribers int
		bytes       int64
		err         error
	}
	done := make(chan result, 1)
	go func() {
		subscribers, bytes, err := broker.Broadcast(
			ctx,
			"events",
			io.NopCloser(strings.NewReader("complete payload")),
			nil,
			int64(len("complete payload")),
		)
		done <- result{subscribers, bytes, err}
	}()

	disconnectedStream, err := disconnected.Receive(ctx)
	if err != nil {
		t.Fatalf("receive disconnected stream: %v", err)
	}
	disconnectedStream.Complete(context.Canceled)

	connectedStream, err := connected.Receive(ctx)
	if err != nil {
		t.Fatalf("receive connected stream: %v", err)
	}
	body, err := io.ReadAll(connectedStream.Body)
	connectedStream.Complete(err)
	if err != nil {
		t.Fatalf("read connected stream: %v", err)
	}
	if got := string(body); got != "complete payload" {
		t.Fatalf("connected subscriber got %q", got)
	}

	broadcastResult := <-done
	if broadcastResult.err != nil || broadcastResult.subscribers != 2 || broadcastResult.bytes != int64(len("complete payload")) {
		t.Fatalf("unexpected Broadcast result: %+v", broadcastResult)
	}
}

func TestBroadcastCancellationUnblocksSlowSubscriber(t *testing.T) {
	t.Parallel()

	broker := NewBroker()
	subscription := broker.Subscribe("events")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, err := broker.Broadcast(
			ctx,
			"events",
			io.NopCloser(strings.NewReader(strings.Repeat("x", 64*1024))),
			nil,
			64*1024,
		)
		done <- err
	}()

	stream, err := subscription.Receive(context.Background())
	if err != nil {
		t.Fatalf("Receive failed: %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Broadcast returned %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Broadcast remained blocked on a slow subscriber after cancellation")
	}
	if _, err := stream.Body.Read(make([]byte, 1)); err == nil {
		t.Fatal("canceled broadcast left subscriber pipe open")
	}
	stream.Complete(nil)
}
