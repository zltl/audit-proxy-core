package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/segmentio/kafka-go"
)

const auditQueuePublishTimeout = 10 * time.Second

type auditQueueSink interface {
	Close() error
	PublishBatch(ctx context.Context, events []auditBackupEvent) error
}

type auditQueueSinkFactory func(*Config) (auditQueueSink, error)

type auditQueueForwarder struct {
	backend    string
	endpoint   string
	topic      string
	exchange   string
	routingKey string
	sink       auditQueueSink

	statePath string
	stateMu   sync.Mutex
	offsets   map[string]int64
}

type auditQueueSyncState struct {
	Backend    string           `json:"backend"`
	Endpoint   string           `json:"endpoint"`
	Topic      string           `json:"topic,omitempty"`
	Exchange   string           `json:"exchange,omitempty"`
	RoutingKey string           `json:"routing_key,omitempty"`
	Offsets    map[string]int64 `json:"offsets"`
}

func newAuditQueueForwarder(cfg *Config) (*auditQueueForwarder, error) {
	return newAuditQueueForwarderWithFactory(cfg, newAuditQueueSinkFromConfig)
}

func newAuditQueueForwarderWithFactory(cfg *Config, factory auditQueueSinkFactory) (*auditQueueForwarder, error) {
	if cfg == nil || strings.TrimSpace(cfg.AuditQueueBackend) == "" {
		return nil, nil
	}
	if factory == nil {
		return nil, fmt.Errorf("audit queue: sink factory is required")
	}
	sink, err := factory(cfg)
	if err != nil {
		return nil, err
	}
	forwarder := &auditQueueForwarder{
		backend:    strings.TrimSpace(cfg.AuditQueueBackend),
		endpoint:   strings.TrimSpace(cfg.AuditQueueEndpoint),
		topic:      strings.TrimSpace(cfg.AuditQueueTopic),
		exchange:   strings.TrimSpace(cfg.AuditQueueExchange),
		routingKey: strings.TrimSpace(cfg.AuditQueueRoutingKey),
		sink:       sink,
		statePath:  dataFilePath(cfg.DataDir, "audit_queue_offsets.json"),
		offsets:    map[string]int64{},
	}
	if err := forwarder.loadState(); err != nil {
		_ = sink.Close()
		return nil, err
	}
	return forwarder, nil
}

func (f *auditQueueForwarder) Close() error {
	if f == nil || f.sink == nil {
		return nil
	}
	return f.sink.Close()
}

func (f *auditQueueForwarder) SyncDir(dir string) error {
	if f == nil || f.sink == nil {
		return nil
	}
	if strings.TrimSpace(dir) == "" {
		return fmt.Errorf("audit log directory not configured")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read audit directory: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".jsonl") && !strings.HasSuffix(name, ".log") {
			continue
		}
		path := filepath.Join(dir, name)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		offset := f.fileOffset(path)
		if info.Size() < offset {
			offset = 0
		}
		nextOffset, err := f.syncFile(path, offset)
		if err != nil {
			return err
		}
		if err := f.saveFileOffset(path, nextOffset); err != nil {
			return err
		}
	}
	return nil
}

func (f *auditQueueForwarder) syncFile(path string, offset int64) (int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return offset, err
	}
	defer file.Close()

	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return offset, err
	}

	reader := bufio.NewReader(file)
	currentOffset := offset
	events := make([]auditBackupEvent, 0, auditSearchBulkBatchSize)
	flush := func() error {
		if len(events) == 0 {
			return nil
		}
		if err := f.publishBatch(events); err != nil {
			return err
		}
		events = events[:0]
		return nil
	}

	for {
		lineOffset := currentOffset
		line, readErr := reader.ReadBytes('\n')
		currentOffset += int64(len(line))
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) > 0 {
			event, err := parseAuditLogLine(path, lineOffset, trimmed)
			if err == nil && event != nil {
				events = append(events, auditBackupEvent{
					Event:      *event,
					RawEvent:   string(trimmed),
					SourceFile: path,
				})
				if len(events) >= auditSearchBulkBatchSize {
					if err := flush(); err != nil {
						return offset, err
					}
				}
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return offset, readErr
		}
	}
	if err := flush(); err != nil {
		return offset, err
	}
	return currentOffset, nil
}

func (f *auditQueueForwarder) publishBatch(events []auditBackupEvent) error {
	ctx, cancel := context.WithTimeout(context.Background(), auditQueuePublishTimeout)
	defer cancel()
	return f.sink.PublishBatch(ctx, events)
}

func (f *auditQueueForwarder) fileOffset(path string) int64 {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	return f.offsets[path]
}

func (f *auditQueueForwarder) saveFileOffset(path string, offset int64) error {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	f.offsets[path] = offset
	return f.persistStateLocked()
}

func (f *auditQueueForwarder) loadState() error {
	if strings.TrimSpace(f.statePath) == "" {
		return nil
	}
	data, err := os.ReadFile(f.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("audit queue: read sync state: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}

	var state auditQueueSyncState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("audit queue: decode sync state: %w", err)
	}
	if strings.TrimSpace(state.Backend) != f.backend ||
		strings.TrimSpace(state.Endpoint) != f.endpoint ||
		strings.TrimSpace(state.Topic) != f.topic ||
		strings.TrimSpace(state.Exchange) != f.exchange ||
		strings.TrimSpace(state.RoutingKey) != f.routingKey {
		return nil
	}
	if state.Offsets != nil {
		f.offsets = state.Offsets
	}
	return nil
}

func (f *auditQueueForwarder) persistStateLocked() error {
	if strings.TrimSpace(f.statePath) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(f.statePath), 0o755); err != nil {
		return fmt.Errorf("audit queue: create sync state dir: %w", err)
	}
	state := auditQueueSyncState{
		Backend:    f.backend,
		Endpoint:   f.endpoint,
		Topic:      f.topic,
		Exchange:   f.exchange,
		RoutingKey: f.routingKey,
		Offsets:    f.offsets,
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("audit queue: encode sync state: %w", err)
	}
	tmpPath := f.statePath + ".tmp"
	if err := os.WriteFile(tmpPath, raw, 0o600); err != nil {
		return fmt.Errorf("audit queue: write sync state: %w", err)
	}
	if err := os.Rename(tmpPath, f.statePath); err != nil {
		return fmt.Errorf("audit queue: persist sync state: %w", err)
	}
	return nil
}

func newAuditQueueSinkFromConfig(cfg *Config) (auditQueueSink, error) {
	switch strings.TrimSpace(cfg.AuditQueueBackend) {
	case "kafka":
		return newKafkaAuditQueueSink(cfg)
	case "rabbitmq":
		return newRabbitMQAuditQueueSink(cfg)
	default:
		return nil, fmt.Errorf("audit queue: unsupported backend %q", cfg.AuditQueueBackend)
	}
}

type kafkaAuditQueueSink struct {
	writer *kafka.Writer
}

func newKafkaAuditQueueSink(cfg *Config) (*kafkaAuditQueueSink, error) {
	brokers := make([]string, 0)
	for _, broker := range strings.Split(cfg.AuditQueueEndpoint, ",") {
		broker = strings.TrimSpace(broker)
		if broker != "" {
			brokers = append(brokers, broker)
		}
	}
	writer := &kafka.Writer{
		Addr:                   kafka.TCP(brokers...),
		Topic:                  strings.TrimSpace(cfg.AuditQueueTopic),
		Balancer:               &kafka.Hash{},
		RequiredAcks:           kafka.RequireAll,
		AllowAutoTopicCreation: true,
	}
	return &kafkaAuditQueueSink{writer: writer}, nil
}

func (s *kafkaAuditQueueSink) PublishBatch(ctx context.Context, events []auditBackupEvent) error {
	messages := make([]kafka.Message, 0, len(events))
	for _, event := range events {
		payload, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("audit queue: encode kafka message: %w", err)
		}
		messages = append(messages, kafka.Message{
			Key:   []byte(event.Event.ID),
			Value: payload,
			Time:  event.Event.Timestamp,
			Headers: []kafka.Header{
				{Key: "event_type", Value: []byte(event.Event.EventType)},
				{Key: "username", Value: []byte(event.Event.Username)},
				{Key: "source_ip", Value: []byte(event.Event.SourceIP)},
			},
		})
	}
	return s.writer.WriteMessages(ctx, messages...)
}

func (s *kafkaAuditQueueSink) Close() error {
	if s == nil || s.writer == nil {
		return nil
	}
	return s.writer.Close()
}

type rabbitMQAuditQueueSink struct {
	endpoint   string
	exchange   string
	routingKey string

	mu   sync.Mutex
	conn *amqp.Connection
	ch   *amqp.Channel
}

func newRabbitMQAuditQueueSink(cfg *Config) (*rabbitMQAuditQueueSink, error) {
	sink := &rabbitMQAuditQueueSink{
		endpoint:   strings.TrimSpace(cfg.AuditQueueEndpoint),
		exchange:   strings.TrimSpace(cfg.AuditQueueExchange),
		routingKey: strings.TrimSpace(cfg.AuditQueueRoutingKey),
	}
	if err := sink.connect(); err != nil {
		return nil, err
	}
	return sink, nil
}

func (s *rabbitMQAuditQueueSink) PublishBatch(ctx context.Context, events []auditBackupEvent) error {
	if err := s.publishBatch(ctx, events); err == nil {
		return nil
	}
	s.mu.Lock()
	_ = s.closeLocked()
	s.mu.Unlock()
	if err := s.connect(); err != nil {
		return err
	}
	return s.publishBatch(ctx, events)
}

func (s *rabbitMQAuditQueueSink) publishBatch(ctx context.Context, events []auditBackupEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.connectLocked(); err != nil {
		return err
	}
	for _, event := range events {
		payload, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("audit queue: encode rabbitmq message: %w", err)
		}
		if err := s.ch.PublishWithContext(ctx, s.exchange, s.routingKey, false, false, amqp.Publishing{
			ContentType:  "application/json",
			DeliveryMode: amqp.Persistent,
			MessageId:    event.Event.ID,
			Type:         event.Event.EventType,
			Timestamp:    event.Event.Timestamp,
			Body:         payload,
			Headers: amqp.Table{
				"username":  event.Event.Username,
				"source_ip": event.Event.SourceIP,
			},
		}); err != nil {
			return fmt.Errorf("audit queue: publish rabbitmq message: %w", err)
		}
	}
	return nil
}

func (s *rabbitMQAuditQueueSink) connect() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connectLocked()
}

func (s *rabbitMQAuditQueueSink) connectLocked() error {
	if s.conn != nil && !s.conn.IsClosed() && s.ch != nil {
		return nil
	}
	conn, err := amqp.Dial(s.endpoint)
	if err != nil {
		return fmt.Errorf("audit queue: dial rabbitmq: %w", err)
	}
	ch, err := conn.Channel()
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("audit queue: open rabbitmq channel: %w", err)
	}
	s.conn = conn
	s.ch = ch
	return nil
}

func (s *rabbitMQAuditQueueSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeLocked()
}

func (s *rabbitMQAuditQueueSink) closeLocked() error {
	var closeErr error
	if s.ch != nil {
		if err := s.ch.Close(); closeErr == nil {
			closeErr = err
		}
		s.ch = nil
	}
	if s.conn != nil {
		if err := s.conn.Close(); closeErr == nil {
			closeErr = err
		}
		s.conn = nil
	}
	return closeErr
}

func (a *API) syncAuditQueue() error {
	if a == nil || a.auditQueue == nil {
		return nil
	}
	a.auditQueueMu.Lock()
	defer a.auditQueueMu.Unlock()
	return a.auditQueue.SyncDir(a.config.AuditLogDir)
}

// StartAuditQueueSync mirrors append-only audit log files into the configured message queue.
func (a *API) StartAuditQueueSync(ctx context.Context, interval time.Duration) {
	if a == nil || a.auditQueue == nil || ctx == nil {
		return
	}
	if interval <= 0 {
		interval = defaultAuditSyncInterval
	}
	a.auditQueueOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			_ = a.syncAuditQueue()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					_ = a.syncAuditQueue()
				}
			}
		}()
	})
}
