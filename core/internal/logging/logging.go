// Package logging configures the daemon journal: JSON lines in a rotated file
// under <state-dir>/logs, plus a live feed for clients of /api/v1/logs/stream.
// Paths, permissions and rotation behave the same on Windows, Linux and macOS.
package logging

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// LevelTrace is below slog.LevelDebug. It carries raw tool output and probe details.
const LevelTrace = slog.Level(-8)

const (
	defaultMaxBytes = 5 * 1024 * 1024
	defaultKeep     = 5
	// FileName is the daemon journal, read by the extension command "Ouvrir le journal du démon".
	FileName = "daemon.log"
)

// Options configures Setup.
type Options struct {
	Dir      string     // <state-dir>/logs
	Level    slog.Level // minimum level written to the file
	MaxBytes int64      // rotation threshold, 5 MiB by default
	Keep     int        // rotated files kept, 5 by default
}

// ParseLevel reads trace, debug, info, warn or error. Anything else is debug:
// the file is the forensic trace of a failed start, and rotation bounds its size.
func ParseLevel(value string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "trace":
		return LevelTrace
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelDebug
	}
}

// LevelName maps a slog level to the names used by the VS Code LogOutputChannel.
func LevelName(level slog.Level) string {
	switch {
	case level < slog.LevelDebug:
		return "trace"
	case level < slog.LevelInfo:
		return "debug"
	case level < slog.LevelWarn:
		return "info"
	case level < slog.LevelError:
		return "warn"
	default:
		return "error"
	}
}

var defaultBroadcaster = NewBroadcaster()

// Stream is the process-wide live feed used by the daemon HTTP server.
func Stream() *Broadcaster { return defaultBroadcaster }

// Setup installs the journal as the default slog logger. The returned function
// flushes and closes the file. A file that cannot be opened is an error: the
// caller decides whether to continue with the default stderr logger.
func Setup(opts Options) (func(), error) {
	if opts.Dir == "" {
		return func() {}, errors.New("dossier de journal absent")
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = defaultMaxBytes
	}
	if opts.Keep <= 0 {
		opts.Keep = defaultKeep
	}
	file, err := OpenRotating(filepath.Join(opts.Dir, FileName), opts.MaxBytes, opts.Keep)
	if err != nil {
		return func() {}, err
	}
	fileHandler := slog.NewJSONHandler(file, &slog.HandlerOptions{
		Level: opts.Level,
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			if attr.Key == slog.LevelKey {
				if level, ok := attr.Value.Any().(slog.Level); ok {
					return slog.String(slog.LevelKey, LevelName(level))
				}
			}
			return attr
		},
	})
	slog.SetDefault(slog.New(&fanout{file: fileHandler, fileLevel: opts.Level, stream: defaultBroadcaster}))
	return func() { _ = file.Close() }, nil
}

// RotatingFile appends to path and rotates it to path.1 ... path.<keep> past maxBytes.
type RotatingFile struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	keep     int
	file     *os.File
	size     int64
}

// OpenRotating opens or creates the journal with owner-only permissions.
func OpenRotating(path string, maxBytes int64, keep int) (*RotatingFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("création du dossier de journal: %w", err)
	}
	r := &RotatingFile{path: path, maxBytes: maxBytes, keep: keep}
	if err := r.open(); err != nil {
		return nil, err
	}
	if r.size >= maxBytes {
		r.rotate()
	}
	return r, nil
}

func (r *RotatingFile) open() error {
	file, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("ouverture du journal %s: %w", r.path, err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	r.file = file
	r.size = info.Size()
	return nil
}

// rotate closes the file before renaming it: Windows refuses to rename an open file.
// A rename that still fails (another process holds the file) keeps appending.
func (r *RotatingFile) rotate() {
	if r.file != nil {
		_ = r.file.Close()
		r.file = nil
	}
	_ = os.Remove(fmt.Sprintf("%s.%d", r.path, r.keep))
	for i := r.keep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", r.path, i), fmt.Sprintf("%s.%d", r.path, i+1))
	}
	_ = os.Rename(r.path, r.path+".1")
	if err := r.open(); err != nil {
		r.file = nil
	}
}

func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file != nil && r.size > 0 && r.size+int64(len(p)) > r.maxBytes {
		r.rotate()
	}
	if r.file == nil {
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	n, err := r.file.Write(p)
	r.size += int64(n)
	return n, err
}

// Close closes the current file.
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return nil
	}
	err := r.file.Close()
	r.file = nil
	return err
}

// Entry is one journal record sent to stream subscribers.
type Entry struct {
	Time    string                 `json:"time"`
	Level   string                 `json:"level"`
	Message string                 `json:"msg"`
	Attrs   map[string]interface{} `json:"attrs,omitempty"`
}

type subscriber struct {
	level slog.Level
	ch    chan Entry
}

// Broadcaster fans records out to live subscribers. A slow subscriber loses
// records instead of blocking the daemon.
type Broadcaster struct {
	mu   sync.RWMutex
	subs map[*subscriber]struct{}
}

// NewBroadcaster creates an empty feed.
func NewBroadcaster() *Broadcaster {
	return &Broadcaster{subs: make(map[*subscriber]struct{})}
}

// Subscribe receives records at or above level until the returned function is called.
func (b *Broadcaster) Subscribe(level slog.Level, buffer int) (<-chan Entry, func()) {
	if buffer <= 0 {
		buffer = 256
	}
	sub := &subscriber{level: level, ch: make(chan Entry, buffer)}
	b.mu.Lock()
	b.subs[sub] = struct{}{}
	b.mu.Unlock()
	var once sync.Once
	return sub.ch, func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.subs, sub)
			b.mu.Unlock()
			close(sub.ch)
		})
	}
}

// Wants reports whether a subscriber listens at this level.
func (b *Broadcaster) Wants(level slog.Level) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for sub := range b.subs {
		if level >= sub.level {
			return true
		}
	}
	return false
}

// Publish delivers entry without blocking.
func (b *Broadcaster) Publish(level slog.Level, entry Entry) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for sub := range b.subs {
		if level < sub.level {
			continue
		}
		select {
		case sub.ch <- entry:
		default:
		}
	}
}

type fanout struct {
	file      slog.Handler
	fileLevel slog.Level
	stream    *Broadcaster
	attrs     []slog.Attr
	group     string
}

func (h *fanout) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.fileLevel || h.stream.Wants(level)
}

func (h *fanout) Handle(ctx context.Context, record slog.Record) error {
	var err error
	if record.Level >= h.fileLevel {
		err = h.file.Handle(ctx, record)
	}
	if h.stream.Wants(record.Level) {
		attrs := make(map[string]interface{}, len(h.attrs)+record.NumAttrs())
		for _, attr := range h.attrs {
			attrs[attr.Key] = attrValue(attr.Value)
		}
		record.Attrs(func(attr slog.Attr) bool {
			attrs[h.group+attr.Key] = attrValue(attr.Value)
			return true
		})
		stamp := record.Time
		if stamp.IsZero() {
			stamp = time.Now()
		}
		h.stream.Publish(record.Level, Entry{
			Time:    stamp.UTC().Format(time.RFC3339Nano),
			Level:   LevelName(record.Level),
			Message: record.Message,
			Attrs:   attrs,
		})
	}
	return err
}

func (h *fanout) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := *h
	next.file = h.file.WithAttrs(attrs)
	next.attrs = append([]slog.Attr{}, h.attrs...)
	for _, attr := range attrs {
		next.attrs = append(next.attrs, slog.Attr{Key: h.group + attr.Key, Value: attr.Value})
	}
	return &next
}

func (h *fanout) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	next := *h
	next.file = h.file.WithGroup(name)
	next.group = h.group + name + "."
	return &next
}

// attrValue keeps the stream JSON-serialisable: errors become their message.
func attrValue(value slog.Value) interface{} {
	value = value.Resolve()
	switch value.Kind() {
	case slog.KindDuration:
		return value.Duration().Milliseconds()
	case slog.KindTime:
		return value.Time().UTC().Format(time.RFC3339Nano)
	case slog.KindGroup:
		group := map[string]interface{}{}
		for _, attr := range value.Group() {
			group[attr.Key] = attrValue(attr.Value)
		}
		return group
	case slog.KindAny:
		raw := value.Any()
		if err, ok := raw.(error); ok {
			return err.Error()
		}
		if _, err := json.Marshal(raw); err != nil {
			return fmt.Sprint(raw)
		}
		return raw
	default:
		return value.Any()
	}
}
