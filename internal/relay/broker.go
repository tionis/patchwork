// Package relay provides the in-memory message exchange used by Patchwork's
// HTTP endpoints.
package relay

import (
	"context"
	"net/http"
	"sync"
)

// Message is an immutable message handed from one HTTP request to another.
// Broker methods clone messages at ownership boundaries so callers may safely
// reuse or modify their input after publishing.
type Message struct {
	Body   []byte
	Header http.Header
}

// Broker coordinates queue and pub/sub exchanges by channel name.
type Broker struct {
	mu       sync.Mutex
	channels map[string]*channel
	nextID   uint64
}

type channel struct {
	queue         chan Message
	queueUsers    int
	subscriptions map[uint64]chan Message
}

// NewBroker constructs an empty Broker.
func NewBroker() *Broker {
	return &Broker{channels: make(map[string]*channel)}
}

// Send blocks until one receiver accepts the message or ctx is canceled.
func (b *Broker) Send(ctx context.Context, name string, message Message) error {
	ch := b.acquireQueue(name)
	defer b.releaseQueue(name, ch)

	select {
	case ch.queue <- cloneMessage(message):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Receive blocks until one sender hands off a message or ctx is canceled.
func (b *Broker) Receive(ctx context.Context, name string) (Message, error) {
	ch := b.acquireQueue(name)
	defer b.releaseQueue(name, ch)

	select {
	case message := <-ch.queue:
		return message, nil
	case <-ctx.Done():
		return Message{}, ctx.Err()
	}
}

// Subscribe registers a one-message pub/sub receiver. Registration is complete
// before Subscribe returns, so a subsequent Publish deterministically includes
// the subscription.
func (b *Broker) Subscribe(name string) *Subscription {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := b.channelLocked(name)
	b.nextID++
	id := b.nextID
	messages := make(chan Message, 1)
	ch.subscriptions[id] = messages

	return &Subscription{
		broker:   b,
		name:     name,
		id:       id,
		messages: messages,
	}
}

// Publish delivers one copy of message to every subscription that was active
// when Publish began. Subscriptions are one-shot and are claimed atomically by
// the publication. Publish never waits for subscribers to process the message.
func (b *Broker) Publish(name string, message Message) int {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch, ok := b.channels[name]
	if !ok {
		return 0
	}

	delivered := len(ch.subscriptions)
	for id, messages := range ch.subscriptions {
		messages <- cloneMessage(message)
		delete(ch.subscriptions, id)
	}
	b.deleteIfIdleLocked(name, ch)

	return delivered
}

// ActiveChannels returns the number of channels with active queue operations
// or pub/sub subscriptions.
func (b *Broker) ActiveChannels() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	return len(b.channels)
}

// Subscription is a one-message pub/sub registration.
type Subscription struct {
	broker   *Broker
	name     string
	id       uint64
	messages <-chan Message
	once     sync.Once
}

// Receive waits for the subscription's message or for ctx cancellation.
// The subscription is always released before Receive returns.
func (s *Subscription) Receive(ctx context.Context) (Message, error) {
	defer s.Close()

	select {
	case message := <-s.messages:
		return message, nil
	case <-ctx.Done():
		return Message{}, ctx.Err()
	}
}

// Close cancels a subscription that has not already been claimed by Publish.
// It is safe to call Close more than once.
func (s *Subscription) Close() {
	s.once.Do(func() {
		s.broker.removeSubscription(s.name, s.id)
	})
}

func (b *Broker) acquireQueue(name string) *channel {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := b.channelLocked(name)
	ch.queueUsers++
	return ch
}

func (b *Broker) releaseQueue(name string, ch *channel) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if current := b.channels[name]; current != ch {
		return
	}
	ch.queueUsers--
	b.deleteIfIdleLocked(name, ch)
}

func (b *Broker) removeSubscription(name string, id uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch, ok := b.channels[name]
	if !ok {
		return
	}
	delete(ch.subscriptions, id)
	b.deleteIfIdleLocked(name, ch)
}

func (b *Broker) channelLocked(name string) *channel {
	ch, ok := b.channels[name]
	if !ok {
		ch = &channel{
			queue:         make(chan Message),
			subscriptions: make(map[uint64]chan Message),
		}
		b.channels[name] = ch
	}
	return ch
}

func (b *Broker) deleteIfIdleLocked(name string, ch *channel) {
	if ch.queueUsers == 0 && len(ch.subscriptions) == 0 && b.channels[name] == ch {
		delete(b.channels, name)
	}
}

func cloneMessage(message Message) Message {
	return Message{
		Body:   append([]byte(nil), message.Body...),
		Header: message.Header.Clone(),
	}
}
