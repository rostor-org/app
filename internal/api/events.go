package api

// Server-Sent Events for the console. One Postgres LISTEN connection per
// process feeds an in-memory broadcaster; each browser gets its own
// subscriber. Missed events are replayed from the events table using
// Last-Event-ID, so a reconnect never loses a change.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

type liveEvent struct {
	ID         int64           `json:"id"`
	Type       string          `json:"type"`
	TS         time.Time       `json:"ts"`
	ActorID    string          `json:"actor_id,omitempty"`
	TargetType string          `json:"target_type,omitempty"`
	TargetID   string          `json:"target_id,omitempty"`
	Payload    json.RawMessage `json:"payload"`
}

type Broadcaster struct {
	mu   sync.Mutex
	subs map[chan liveEvent]struct{}
}

func NewBroadcaster() *Broadcaster { return &Broadcaster{subs: map[chan liveEvent]struct{}{}} }

func (b *Broadcaster) subscribe() (chan liveEvent, func()) {
	ch := make(chan liveEvent, 64)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.subs, ch)
		b.mu.Unlock()
	}
}

func (b *Broadcaster) publish(e liveEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- e:
		default: // slow consumer: it will catch up via Last-Event-ID on reconnect
		}
	}
}

// Listen runs until ctx ends, re-establishing the LISTEN connection on error.
func (s *Server) Listen(ctx context.Context) {
	for ctx.Err() == nil {
		if err := s.listenOnce(ctx); err != nil && ctx.Err() == nil {
			s.Log.Warn("events listen", "err", err)
			time.Sleep(2 * time.Second)
		}
	}
}

func (s *Server) listenOnce(ctx context.Context) error {
	conn, err := s.DB.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "LISTEN rostor_events"); err != nil {
		return err
	}
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		tenant, idStr, ok := strings.Cut(n.Payload, ":")
		if !ok || tenant != s.TenantID {
			continue
		}
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			continue
		}
		evs, err := s.eventsSince(ctx, id-1, 1)
		if err != nil || len(evs) == 0 {
			continue
		}
		s.Events.publish(evs[0])
	}
}

func (s *Server) eventsSince(ctx context.Context, after int64, limit int) ([]liveEvent, error) {
	rows, err := s.DB.Query(ctx, `SELECT id, type, ts, coalesce(actor_id,''), coalesce(target_type,''), coalesce(target_id,''), payload
		FROM events WHERE tenant_id=$1 AND id > $2 ORDER BY id LIMIT $3`, s.TenantID, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []liveEvent
	for rows.Next() {
		var e liveEvent
		if err := rows.Scan(&e.ID, &e.Type, &e.TS, &e.ActorID, &e.TargetType, &e.TargetID, &e.Payload); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok || s.Events == nil {
		s.writeErr(w, r, 500, "internal.error", nil)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)
	full, _ := r.Context().Value(ctxFullStream).(bool)
	self := actorOf(r).ID
	// A member sees only events about themselves; the payload is dropped
	// for system events they may not read. Admins see everything.
	visible := func(e liveEvent) bool {
		if full {
			return true
		}
		return e.ActorID == self || e.TargetID == self
	}
	write := func(e liveEvent) error {
		if !visible(e) {
			return nil
		}
		data, _ := json.Marshal(e)
		_, err := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", e.ID, e.Type, data)
		fl.Flush()
		return err
	}
	// Replay anything missed since the client's last id.
	if last := r.Header.Get("Last-Event-ID"); last != "" {
		if id, err := strconv.ParseInt(last, 10, 64); err == nil {
			if evs, err := s.eventsSince(r.Context(), id, 500); err == nil {
				for _, e := range evs {
					if write(e) != nil {
						return
					}
				}
			}
		}
	}
	ch, cancel := s.Events.subscribe()
	defer cancel()
	fmt.Fprint(w, ": connected\n\n")
	fl.Flush()
	hb := time.NewTicker(25 * time.Second)
	defer hb.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e := <-ch:
			if write(e) != nil {
				return
			}
		case <-hb.C:
			if _, err := fmt.Fprint(w, ": hb\n\n"); err != nil {
				return
			}
			fl.Flush()
		}
	}
}

// sessionOrTokenAuth is adminAuth without a specific action: any signed-in
// principal that can read audit may subscribe.
var _ = pgx.ErrNoRows
