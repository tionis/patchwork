package relay

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQueuePairsConcurrentSendersAndReceiversExactlyOnce(t *testing.T) {
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
			message, err := broker.Receive(ctx, "jobs")
			if err != nil {
				errs <- err
				return
			}
			received <- string(message.Body)
		})
	}
	for i := range messages {
		wg.Go(func() {
			errs <- broker.Send(ctx, "jobs", Message{Body: []byte(fmt.Sprintf("message-%03d", i))})
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
			t.Fatalf("message delivered more than once: %q", body)
		}
		seen[body] = true
	}
	if len(seen) != messages {
		t.Fatalf("received %d unique messages, want %d", len(seen), messages)
	}
	if got := broker.ActiveChannels(); got != 0 {
		t.Fatalf("broker retained %d idle channels", got)
	}
}

func TestQueueCancellationDoesNotLeaveStaleOperations(t *testing.T) {
	t.Parallel()

	broker := NewBroker()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	if err := broker.Send(canceled, "channel", Message{Body: []byte("stale")}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Send returned %v, want context.Canceled", err)
	}
	if _, err := broker.Receive(canceled, "channel"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Receive returned %v, want context.Canceled", err)
	}
	if got := broker.ActiveChannels(); got != 0 {
		t.Fatalf("broker retained %d canceled channels", got)
	}

	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	received := make(chan Message, 1)
	go func() {
		message, _ := broker.Receive(ctx, "channel")
		received <- message
	}()
	if err := broker.Send(ctx, "channel", Message{Body: []byte("fresh")}); err != nil {
		t.Fatalf("fresh Send failed: %v", err)
	}
	if got := string((<-received).Body); got != "fresh" {
		t.Fatalf("received %q, want fresh message", got)
	}
}

func TestPubSubUsesAtomicOneShotSubscriptions(t *testing.T) {
	t.Parallel()

	const subscriberCount = 64
	broker := NewBroker()
	subscriptions := make([]*Subscription, subscriberCount)
	for i := range subscriptions {
		subscriptions[i] = broker.Subscribe("events")
	}

	original := Message{
		Body:    []byte("payload"),
		Headers: map[string]string{"X-Event": "original"},
	}
	if got := broker.Publish("events", original); got != subscriberCount {
		t.Fatalf("delivered to %d subscribers, want %d", got, subscriberCount)
	}
	if got := broker.Publish("events", Message{Body: []byte("duplicate")}); got != 0 {
		t.Fatalf("second publication reached %d one-shot subscribers", got)
	}

	original.Body[0] = 'X'
	original.Headers["X-Event"] = "mutated"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for i, subscription := range subscriptions {
		message, err := subscription.Receive(ctx)
		if err != nil {
			t.Fatalf("subscriber %d failed: %v", i, err)
		}
		if got := string(message.Body); got != "payload" {
			t.Fatalf("subscriber %d received %q", i, got)
		}
		if got := message.Headers["X-Event"]; got != "original" {
			t.Fatalf("subscriber %d received header %q", i, got)
		}

		message.Body[0] = 'Y'
		message.Headers["X-Event"] = "subscriber mutation"
	}
	if got := broker.ActiveChannels(); got != 0 {
		t.Fatalf("broker retained %d idle pub/sub channels", got)
	}
}

func TestSubscriptionCancellationAndCloseAreIdempotent(t *testing.T) {
	t.Parallel()

	broker := NewBroker()
	subscription := broker.Subscribe("events")
	subscription.Close()
	subscription.Close()

	if got := broker.Publish("events", Message{Body: []byte("ignored")}); got != 0 {
		t.Fatalf("closed subscription received a publication")
	}
	if got := broker.ActiveChannels(); got != 0 {
		t.Fatalf("broker retained %d idle channels", got)
	}

	canceledSubscription := broker.Subscribe("events")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := canceledSubscription.Receive(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("Receive returned %v, want context.Canceled", err)
	}
	if got := broker.ActiveChannels(); got != 0 {
		t.Fatalf("broker retained %d canceled subscriptions", got)
	}
}
