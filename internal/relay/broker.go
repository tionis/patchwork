// Package relay provides the in-memory streaming exchange used by Patchwork's
// HTTP endpoints.
package relay

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
)

var ErrNilStream = errors.New("relay stream is nil")

// Stream is an owned, one-shot byte stream handed from one HTTP request to
// another. The receiver must call Complete when copying finishes. The sender
// waits for that completion, which preserves end-to-end backpressure.
type Stream struct {
	Body          io.ReadCloser
	Headers       http.Header
	ContentLength int64

	once          sync.Once
	done          chan struct{}
	completionErr error
	bytesRead     atomic.Int64
}

// NewStream wraps body for transfer. Headers are copied at construction so the
// sender may safely reuse its metadata after handing the stream off.
func NewStream(body io.ReadCloser, headers http.Header, contentLength int64) *Stream {
	if body == nil {
		body = io.NopCloser(&emptyReader{})
	}

	stream := &Stream{
		Headers:       headers.Clone(),
		ContentLength: contentLength,
		done:          make(chan struct{}),
	}
	stream.Body = &countingReadCloser{ReadCloser: body, count: &stream.bytesRead}
	return stream
}

// Complete releases the source and reports the transfer result to every waiter.
// It is safe to call Complete more than once; the first result wins.
func (s *Stream) Complete(err error) {
	s.once.Do(func() {
		if closeErr := s.Body.Close(); err == nil {
			err = closeErr
		}
		s.completionErr = err
		close(s.done)
	})
}

// Wait blocks until the receiver completes the stream or ctx is canceled.
// Cancellation aborts the source so a receiver blocked in Read is released.
func (s *Stream) Wait(ctx context.Context) error {
	select {
	case <-s.done:
		return s.completionErr
	case <-ctx.Done():
		s.Complete(ctx.Err())
		<-s.done
		return s.completionErr
	}
}

// BytesRead reports how many source bytes a receiver has read.
func (s *Stream) BytesRead() int64 {
	return s.bytesRead.Load()
}

type countingReadCloser struct {
	io.ReadCloser
	count *atomic.Int64
}

func (r *countingReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	r.count.Add(int64(n))
	return n, err
}

type emptyReader struct{}

func (*emptyReader) Read([]byte) (int, error) { return 0, io.EOF }

// Broker coordinates queue and pub/sub exchanges by channel name.
type Broker struct {
	mu       sync.Mutex
	channels map[string]*channel
	nextID   uint64
}

type channel struct {
	queue         chan *Stream
	queueUsers    int
	subscriptions map[uint64]chan *Stream
}

// NewBroker constructs an empty Broker.
func NewBroker() *Broker {
	return &Broker{channels: make(map[string]*channel)}
}

// Send blocks until one receiver accepts and finishes consuming stream, or ctx
// is canceled. No payload bytes are buffered by the broker.
func (b *Broker) Send(ctx context.Context, name string, stream *Stream) error {
	if stream == nil {
		return ErrNilStream
	}
	if err := ctx.Err(); err != nil {
		stream.Complete(err)
		return err
	}

	ch := b.acquireQueue(name)
	defer b.releaseQueue(name, ch)

	select {
	case ch.queue <- stream:
		return stream.Wait(ctx)
	case <-ctx.Done():
		stream.Complete(ctx.Err())
		return ctx.Err()
	}
}

// Receive blocks until one sender hands off a stream or ctx is canceled. The
// caller owns the returned stream and must call Complete.
func (b *Broker) Receive(ctx context.Context, name string) (*Stream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	ch := b.acquireQueue(name)
	defer b.releaseQueue(name, ch)

	select {
	case stream := <-ch.queue:
		return stream, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Subscribe registers a one-stream pub/sub receiver. Registration is complete
// before Subscribe returns, so a subsequent Broadcast includes it.
func (b *Broker) Subscribe(name string) *Subscription {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := b.channelLocked(name)
	b.nextID++
	id := b.nextID
	streams := make(chan *Stream, 1)
	ch.subscriptions[id] = streams

	return &Subscription{broker: b, name: name, id: id, streams: streams}
}

// Broadcast streams source to every subscription active when Broadcast begins.
// Delivery is bounded-memory and therefore applies backpressure from the
// slowest connected receiver. Receivers that disconnect are removed without
// interrupting the remaining receivers.
func (b *Broker) Broadcast(
	ctx context.Context,
	name string,
	source io.ReadCloser,
	headers http.Header,
	contentLength int64,
) (subscribers int, bytesRead int64, err error) {
	if source == nil {
		source = io.NopCloser(&emptyReader{})
	}
	defer func() {
		if closeErr := source.Close(); err == nil {
			err = closeErr
		}
	}()

	writers := b.claimSubscriptions(name, headers, contentLength)
	if len(writers) == 0 {
		return 0, 0, nil
	}

	stopCancellation := context.AfterFunc(ctx, func() {
		_ = source.Close()
		for _, writer := range writers {
			_ = writer.CloseWithError(ctx.Err())
		}
	})
	defer stopCancellation()
	defer func() {
		for _, writer := range writers {
			_ = writer.CloseWithError(err)
		}
	}()

	active := append([]*io.PipeWriter(nil), writers...)
	buffer := make([]byte, 32*1024)
	for len(active) > 0 {
		n, readErr := source.Read(buffer)
		bytesRead += int64(n)
		if n > 0 {
			remaining := active[:0]
			for _, writer := range active {
				if _, writeErr := writer.Write(buffer[:n]); writeErr == nil {
					remaining = append(remaining, writer)
				} else {
					_ = writer.CloseWithError(writeErr)
				}
			}
			active = remaining
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return len(writers), bytesRead, nil
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				return len(writers), bytesRead, ctxErr
			}
			return len(writers), bytesRead, readErr
		}
	}

	if ctxErr := ctx.Err(); ctxErr != nil {
		return len(writers), bytesRead, ctxErr
	}
	return len(writers), bytesRead, nil
}

// ActiveChannels returns the number of channels with active queue operations
// or pub/sub subscriptions.
func (b *Broker) ActiveChannels() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.channels)
}

// Subscription is a one-stream pub/sub registration.
type Subscription struct {
	broker  *Broker
	name    string
	id      uint64
	streams <-chan *Stream
	once    sync.Once
}

// Receive waits for the subscription's stream or ctx cancellation. The caller
// owns a returned stream and must call Complete.
func (s *Subscription) Receive(ctx context.Context) (*Stream, error) {
	defer s.Close()

	select {
	case stream := <-s.streams:
		return stream, nil
	case <-ctx.Done():
		s.Close()
		return nil, ctx.Err()
	}
}

// Close cancels a subscription that has not been claimed. If Broadcast claimed
// it concurrently, Close aborts the delivered pipe so the broadcaster cannot
// remain blocked. It is safe to call Close more than once.
func (s *Subscription) Close() {
	s.once.Do(func() {
		s.broker.removeSubscription(s.name, s.id)
		select {
		case stream := <-s.streams:
			stream.Complete(context.Canceled)
		default:
		}
	})
}

func (b *Broker) claimSubscriptions(name string, headers http.Header, contentLength int64) []*io.PipeWriter {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch, ok := b.channels[name]
	if !ok {
		return nil
	}

	writers := make([]*io.PipeWriter, 0, len(ch.subscriptions))
	for id, streams := range ch.subscriptions {
		reader, writer := io.Pipe()
		streams <- NewStream(reader, headers, contentLength)
		writers = append(writers, writer)
		delete(ch.subscriptions, id)
	}
	b.deleteIfIdleLocked(name, ch)
	return writers
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
		ch = &channel{queue: make(chan *Stream), subscriptions: make(map[uint64]chan *Stream)}
		b.channels[name] = ch
	}
	return ch
}

func (b *Broker) deleteIfIdleLocked(name string, ch *channel) {
	if ch.queueUsers == 0 && len(ch.subscriptions) == 0 && b.channels[name] == ch {
		delete(b.channels, name)
	}
}
