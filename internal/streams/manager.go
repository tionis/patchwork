package streams

import (
	"context"
	"errors"
	"log/slog"
	"sync"
)

var ErrClosed = errors.New("stream manager closed")

type envelope struct {
	body    []byte
	headers map[string]string
	done    chan struct{}
}

type channel struct {
	data chan envelope
}

type Manager struct {
	mu       sync.Mutex
	channels map[string]*channel
	closed   bool
	logger   *slog.Logger
}

type Received struct {
	env  envelope
	once sync.Once
}

func NewManager(logger *slog.Logger) *Manager {
	return &Manager{
		channels: make(map[string]*channel),
		logger:   logger.With("component", "streams"),
	}
}

func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
}

func (m *Manager) Send(ctx context.Context, key string, body []byte, headers map[string]string) error {
	ch, err := m.getOrCreateChannel(key)
	if err != nil {
		return err
	}

	env := envelope{
		body:    cloneBytes(body),
		headers: cloneHeaders(headers),
		done:    make(chan struct{}),
	}

	select {
	case ch.data <- env:
	case <-ctx.Done():
		return ctx.Err()
	}

	select {
	case <-env.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) Broadcast(ctx context.Context, key string, body []byte, headers map[string]string) (int, error) {
	ch, err := m.getOrCreateChannel(key)
	if err != nil {
		return 0, err
	}

	delivered := 0
	for {
		env := envelope{
			body:    cloneBytes(body),
			headers: cloneHeaders(headers),
			done:    make(chan struct{}),
		}

		select {
		case ch.data <- env:
			select {
			case <-env.done:
				delivered++
			case <-ctx.Done():
				return delivered, ctx.Err()
			}
		default:
			return delivered, nil
		}
	}
}

func (m *Manager) Receive(ctx context.Context, key string) (Received, error) {
	ch, err := m.getOrCreateChannel(key)
	if err != nil {
		return Received{}, err
	}

	select {
	case env := <-ch.data:
		return Received{env: env}, nil
	case <-ctx.Done():
		return Received{}, ctx.Err()
	}
}

func (r *Received) Body() []byte {
	return cloneBytes(r.env.body)
}

func (r *Received) Headers() map[string]string {
	return cloneHeaders(r.env.headers)
}

func (r *Received) Ack() {
	r.once.Do(func() {
		close(r.env.done)
	})
}

func (m *Manager) getOrCreateChannel(key string) (*channel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, ErrClosed
	}

	ch, ok := m.channels[key]
	if ok {
		return ch, nil
	}

	ch = &channel{data: make(chan envelope)}
	m.channels[key] = ch
	m.logger.Debug("stream channel created", "key", key)
	return ch, nil
}

func cloneBytes(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}

	out := make([]byte, len(data))
	copy(out, data)
	return out
}

func cloneHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return map[string]string{}
	}

	cloned := make(map[string]string, len(headers))
	for key, value := range headers {
		cloned[key] = value
	}

	return cloned
}
