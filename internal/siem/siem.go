package siem

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// SIEMType identifies the downstream SIEM system.
type SIEMType string

const (
	SIEMSplunk   SIEMType = "splunk"
	SIEMDatadog  SIEMType = "datadog"
	SIEMElastic  SIEMType = "elastic"
	SIEMLogstash SIEMType = "logstash"
	SIEMSumo     SIEMType = "sumo"
	SIEMSyslog   SIEMType = "syslog"
	SIEMQRadar   SIEMType = "qradar"
	SIEMWazuh    SIEMType = "wazuh"
	SIEMWebhook  SIEMType = "webhook"
)

// SIEMConfig configures the SIEM forwarder.
type SIEMConfig struct {
	Type          SIEMType      `json:"type"`
	Endpoint      string        `json:"endpoint"`
	Token         string        `json:"token"`
	Index         string        `json:"index"`
	Source        string        `json:"source"`
	Format        string        `json:"format,omitempty"`
	Insecure      bool          `json:"insecure"`
	BatchSize     int           `json:"batch_size"`
	FlushInterval time.Duration `json:"flush_interval"`
}

// Event is a single SIEM event.
type Event struct {
	Timestamp time.Time              `json:"timestamp"`
	Source    string                 `json:"source"`
	EventType string                 `json:"event_type"`
	Severity  string                 `json:"severity"`
	Data      map[string]interface{} `json:"data"`
}

// Status reports the forwarder's operational state.
type Status struct {
	Running    bool      `json:"running"`
	BufferSize int       `json:"buffer_size"`
	LastFlush  time.Time `json:"last_flush"`
	LastError  string    `json:"last_error,omitempty"`
	EventsSent int64     `json:"events_sent"`
}

// Forwarder buffers events and flushes them to a SIEM endpoint.
type Forwarder struct {
	config     *SIEMConfig
	client     *http.Client
	buffer     []Event
	mu         sync.Mutex
	stopCh     chan struct{}
	running    bool
	lastFlush  time.Time
	lastError  string
	eventsSent int64
}

// NewForwarder creates a Forwarder for the given configuration.
func NewForwarder(cfg *SIEMConfig) (*Forwarder, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("siem: endpoint is required")
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 5 * time.Second
	}
	if cfg.Source == "" {
		cfg.Source = "ssh-proxy"
	}
	if cfg.Format == "" {
		switch cfg.Type {
		case SIEMQRadar:
			cfg.Format = "leef"
		case SIEMSyslog:
			cfg.Format = "rfc5424"
		case SIEMWazuh:
			cfg.Format = "json"
		}
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.Insecure}, // #nosec G402 -- explicit operator opt-in for private or self-signed SIEM endpoints.
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	return &Forwarder{
		config: cfg,
		client: client,
		buffer: make([]Event, 0, cfg.BatchSize),
		stopCh: make(chan struct{}),
	}, nil
}

// Send buffers an event for asynchronous delivery. It is non-blocking.
func (f *Forwarder) Send(event Event) error {
	if event.Source == "" {
		event.Source = f.config.Source
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	f.mu.Lock()
	f.buffer = append(f.buffer, event)
	shouldFlush := len(f.buffer) >= f.config.BatchSize
	f.mu.Unlock()

	if shouldFlush {
		return f.Flush()
	}
	return nil
}

// Flush sends all buffered events to the SIEM endpoint immediately.
func (f *Forwarder) Flush() error {
	f.mu.Lock()
	if len(f.buffer) == 0 {
		f.mu.Unlock()
		return nil
	}
	batch := f.buffer
	f.buffer = make([]Event, 0, f.config.BatchSize)
	f.mu.Unlock()

	var err error
	switch f.config.Type {
	case SIEMSplunk:
		err = f.sendSplunk(batch)
	case SIEMDatadog:
		err = f.sendDatadog(batch)
	case SIEMElastic:
		err = f.sendElastic(batch)
	case SIEMLogstash:
		err = f.sendLogstash(batch)
	case SIEMSumo:
		err = f.sendSumo(batch)
	case SIEMSyslog:
		err = f.sendSyslog(batch)
	case SIEMQRadar:
		err = f.sendSyslog(batch)
	case SIEMWazuh:
		err = f.sendSyslog(batch)
	case SIEMWebhook:
		err = f.sendWebhook(batch)
	default:
		err = fmt.Errorf("siem: unsupported type %q", f.config.Type)
	}

	f.mu.Lock()
	f.lastFlush = time.Now().UTC()
	if err != nil {
		f.lastError = err.Error()
	} else {
		f.eventsSent += int64(len(batch))
		f.lastError = ""
	}
	f.mu.Unlock()
	return err
}

// Start begins the background flush loop. It blocks until ctx is cancelled
// or Stop is called.
func (f *Forwarder) Start(ctx context.Context) error {
	f.mu.Lock()
	if f.running {
		f.mu.Unlock()
		return fmt.Errorf("siem: forwarder already running")
	}
	f.running = true
	f.mu.Unlock()

	ticker := time.NewTicker(f.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			_ = f.Flush()
		case <-ctx.Done():
			_ = f.Flush()
			f.mu.Lock()
			f.running = false
			f.mu.Unlock()
			return ctx.Err()
		case <-f.stopCh:
			_ = f.Flush()
			f.mu.Lock()
			f.running = false
			f.mu.Unlock()
			return nil
		}
	}
}

// Stop flushes remaining events and signals the background loop to exit.
func (f *Forwarder) Stop() error {
	f.mu.Lock()
	running := f.running
	f.mu.Unlock()

	if running {
		select {
		case f.stopCh <- struct{}{}:
		default:
		}
	} else {
		return f.Flush()
	}
	return nil
}

// Status returns the current forwarder status.
func (f *Forwarder) Status() Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return Status{
		Running:    f.running,
		BufferSize: len(f.buffer),
		LastFlush:  f.lastFlush,
		LastError:  f.lastError,
		EventsSent: f.eventsSent,
	}
}

// ---------------------------------------------------------------------------
// Splunk HEC
// ---------------------------------------------------------------------------

type splunkHECPayload struct {
	Event      interface{} `json:"event"`
	Sourcetype string      `json:"sourcetype"`
	Index      string      `json:"index,omitempty"`
	Source     string      `json:"source,omitempty"`
	Time       float64     `json:"time"`
}

func (f *Forwarder) sendSplunk(events []Event) error {
	data, err := FormatSplunkHEC(events, f.config.Index, f.config.Source)
	if err != nil {
		return fmt.Errorf("siem: splunk encode: %w", err)
	}

	url := f.config.Endpoint + "/services/collector/event"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("siem: splunk request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if f.config.Token != "" {
		req.Header.Set("Authorization", "Splunk "+f.config.Token)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("siem: splunk send: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("siem: splunk returned %d", resp.StatusCode)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Datadog Logs intake
// ---------------------------------------------------------------------------

type datadogLogPayload struct {
	Message    string                 `json:"message"`
	Service    string                 `json:"service,omitempty"`
	DDSource   string                 `json:"ddsource,omitempty"`
	Status     string                 `json:"status,omitempty"`
	Hostname   string                 `json:"hostname,omitempty"`
	Timestamp  int64                  `json:"timestamp,omitempty"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

func (f *Forwarder) sendDatadog(events []Event) error {
	data, err := FormatDatadogLogs(events, f.config.Source)
	if err != nil {
		return fmt.Errorf("siem: datadog encode: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, f.config.Endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("siem: datadog request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if f.config.Token != "" {
		req.Header.Set("DD-API-KEY", f.config.Token)
	}
	if f.config.Source != "" {
		req.Header.Set("DD-Source", f.config.Source)
		req.Header.Set("DD-Service", f.config.Source)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("siem: datadog send: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("siem: datadog returned %d", resp.StatusCode)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Elastic bulk API
// ---------------------------------------------------------------------------

func (f *Forwarder) sendElastic(events []Event) error {
	var buf bytes.Buffer
	index := f.config.Index
	if index == "" {
		index = "ssh-proxy"
	}

	for _, ev := range events {
		// action line
		action := map[string]interface{}{
			"index": map[string]interface{}{
				"_index": index,
			},
		}
		if err := json.NewEncoder(&buf).Encode(action); err != nil {
			return fmt.Errorf("siem: elastic action encode: %w", err)
		}
		// source line
		if err := json.NewEncoder(&buf).Encode(ev); err != nil {
			return fmt.Errorf("siem: elastic event encode: %w", err)
		}
	}

	url := f.config.Endpoint + "/" + index + "/_bulk"
	req, err := http.NewRequest(http.MethodPost, url, &buf)
	if err != nil {
		return fmt.Errorf("siem: elastic request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if f.config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+f.config.Token)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("siem: elastic send: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("siem: elastic returned %d", resp.StatusCode)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Syslog RFC 5424 over TCP
// ---------------------------------------------------------------------------

// severityToSyslog maps severity strings to RFC 5424 severity values.
func severityToSyslog(sev string) int {
	switch sev {
	case "critical":
		return 2 // Critical
	case "error":
		return 3 // Error
	case "warning":
		return 4 // Warning
	case "info":
		return 6 // Informational
	default:
		return 6
	}
}

func (f *Forwarder) sendSyslog(events []Event) error {
	conn, err := net.DialTimeout("tcp", f.config.Endpoint, 5*time.Second)
	if err != nil {
		return fmt.Errorf("siem: syslog connect: %w", err)
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))

	facility := 4 // auth
	hostname := "ssh-proxy"
	appName := f.config.Source
	if appName == "" {
		appName = "ssh-proxy"
	}

	for _, ev := range events {
		msg := formatSyslogMessage(ev, hostname, appName, facility, f.config.Format)
		if _, err := conn.Write([]byte(msg)); err != nil {
			return fmt.Errorf("siem: syslog write: %w", err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Logstash HTTP input / ELK
// ---------------------------------------------------------------------------

func (f *Forwarder) sendLogstash(events []Event) error {
	data, err := FormatLogstashPayload(events)
	if err != nil {
		return fmt.Errorf("siem: logstash encode: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, f.config.Endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("siem: logstash request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if f.config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+f.config.Token)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("siem: logstash send: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("siem: logstash returned %d", resp.StatusCode)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Sumo Logic HTTP source
// ---------------------------------------------------------------------------

func (f *Forwarder) sendSumo(events []Event) error {
	data, err := FormatSumoPayload(events)
	if err != nil {
		return fmt.Errorf("siem: sumo encode: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, f.config.Endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("siem: sumo request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sumo-Host", "ssh-proxy")
	if f.config.Source != "" {
		req.Header.Set("X-Sumo-Category", f.config.Source)
		req.Header.Set("X-Sumo-Name", f.config.Source)
	}
	if f.config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+f.config.Token)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("siem: sumo send: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("siem: sumo returned %d", resp.StatusCode)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Generic webhook
// ---------------------------------------------------------------------------

func (f *Forwarder) sendWebhook(events []Event) error {
	payload := struct {
		Source string  `json:"source"`
		Events []Event `json:"events"`
	}{
		Source: f.config.Source,
		Events: events,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("siem: webhook encode: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, f.config.Endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("siem: webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if f.config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+f.config.Token)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("siem: webhook send: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("siem: webhook returned %d", resp.StatusCode)
	}
	return nil
}

// FormatSplunkHEC returns the Splunk HEC JSON bytes for a batch.
func FormatSplunkHEC(events []Event, index, source string) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, ev := range events {
		payload := splunkHECPayload{
			Event:      ev,
			Sourcetype: "ssh_proxy",
			Index:      index,
			Source:     source,
			Time:       float64(ev.Timestamp.UnixNano()) / 1e9,
		}
		if err := enc.Encode(payload); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// FormatDatadogLogs returns a Datadog-compatible JSON array for a batch of logs.
func FormatDatadogLogs(events []Event, source string) ([]byte, error) {
	logs := make([]datadogLogPayload, 0, len(events))
	for _, ev := range events {
		logs = append(logs, datadogLogPayload{
			Message:   ev.EventType,
			Service:   source,
			DDSource:  source,
			Status:    ev.Severity,
			Hostname:  "ssh-proxy",
			Timestamp: ev.Timestamp.UnixMilli(),
			Attributes: map[string]interface{}{
				"source":     ev.Source,
				"event_type": ev.EventType,
				"data":       ev.Data,
			},
		})
	}
	return json.Marshal(logs)
}

// FormatElasticBulk returns the Elastic bulk API NDJSON bytes for a batch.
func FormatElasticBulk(events []Event, index string) ([]byte, error) {
	if index == "" {
		index = "ssh-proxy"
	}
	var buf bytes.Buffer
	for _, ev := range events {
		action := map[string]interface{}{
			"index": map[string]interface{}{"_index": index},
		}
		if err := json.NewEncoder(&buf).Encode(action); err != nil {
			return nil, err
		}
		if err := json.NewEncoder(&buf).Encode(ev); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// FormatSumoPayload returns newline-delimited JSON for Sumo HTTP sources.
func FormatSumoPayload(events []Event) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// FormatLogstashPayload returns newline-delimited JSON for Logstash HTTP input.
func FormatLogstashPayload(events []Event) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, ev := range events {
		record := map[string]interface{}{
			"@timestamp": ev.Timestamp.UTC().Format(time.RFC3339Nano),
			"source":     ev.Source,
			"event_type": ev.EventType,
			"severity":   ev.Severity,
			"data":       ev.Data,
		}
		if err := enc.Encode(record); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// FormatSyslog returns a slice of RFC 5424 formatted messages.
func FormatSyslog(events []Event, source string) []string {
	return formatSyslogMessages(events, source, "rfc5424")
}

// FormatCEF returns a slice of RFC 5424 syslog messages whose payloads use CEF.
func FormatCEF(events []Event, source string) []string {
	return formatSyslogMessages(events, source, "cef")
}

// FormatLEEF returns a slice of RFC 5424 syslog messages whose payloads use LEEF.
func FormatLEEF(events []Event, source string) []string {
	return formatSyslogMessages(events, source, "leef")
}

func formatSyslogMessages(events []Event, source, format string) []string {
	if source == "" {
		source = "ssh-proxy"
	}
	facility := 4
	hostname := "ssh-proxy"

	msgs := make([]string, 0, len(events))
	for _, ev := range events {
		msgs = append(msgs, formatSyslogMessage(ev, hostname, source, facility, format))
	}
	return msgs
}

func formatSyslogMessage(ev Event, hostname, appName string, facility int, format string) string {
	severity := severityToSyslog(ev.Severity)
	pri := facility*8 + severity
	timestamp := ev.Timestamp.UTC().Format(time.RFC3339)

	switch strings.ToLower(format) {
	case "cef":
		return fmt.Sprintf("<%d>1 %s %s %s - - - %s\n", pri, timestamp, hostname, appName, formatCEFBody(ev))
	case "leef":
		return fmt.Sprintf("<%d>1 %s %s %s - - - %s\n", pri, timestamp, hostname, appName, formatLEEFBody(ev))
	case "json":
		payload, _ := json.Marshal(map[string]interface{}{
			"@timestamp": ev.Timestamp.UTC().Format(time.RFC3339Nano),
			"source":     ev.Source,
			"event_type": ev.EventType,
			"severity":   ev.Severity,
			"data":       ev.Data,
		})
		return fmt.Sprintf("<%d>1 %s %s %s - - - %s\n", pri, timestamp, hostname, appName, string(payload))
	default:
		data, _ := json.Marshal(ev.Data)
		return fmt.Sprintf("<%d>1 %s %s %s - - - %s %s\n",
			pri,
			timestamp,
			hostname,
			appName,
			ev.EventType,
			string(data),
		)
	}
}

func formatCEFBody(ev Event) string {
	return fmt.Sprintf(
		"CEF:0|SSH Proxy|Core|2.0.0|%s|%s|%d|%s",
		escapeCEF(ev.EventType),
		escapeCEF(ev.EventType),
		severityToCEF(ev.Severity),
		formatKeyValues(ev, " "),
	)
}

func formatLEEFBody(ev Event) string {
	return fmt.Sprintf(
		"LEEF:2.0|SSH Proxy|Core|2.0.0|%s\t%s",
		escapeLEEF(ev.EventType),
		formatKeyValues(ev, "\t"),
	)
}

func formatKeyValues(ev Event, sep string) string {
	parts := []string{
		"rt=" + sanitizeKV(ev.Timestamp.UTC().Format(time.RFC3339)),
		"event_type=" + sanitizeKV(ev.EventType),
		"source=" + sanitizeKV(ev.Source),
	}
	keys := make([]string, 0, len(ev.Data))
	for key := range ev.Data {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parts = append(parts, sanitizeKV(key)+"="+sanitizeKV(fmt.Sprint(ev.Data[key])))
	}
	return strings.Join(parts, sep)
}

func sanitizeKV(v string) string {
	replacer := strings.NewReplacer("\n", " ", "\r", " ", "\t", " ", "|", "\\|", "=", "\\=")
	return replacer.Replace(v)
}

func escapeCEF(v string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "|", "\\|")
	return replacer.Replace(v)
}

func escapeLEEF(v string) string {
	replacer := strings.NewReplacer("\n", " ", "\r", " ", "\t", " ", "|", "\\|")
	return replacer.Replace(v)
}

func severityToCEF(sev string) int {
	switch sev {
	case "critical":
		return 10
	case "error":
		return 8
	case "warning":
		return 5
	default:
		return 3
	}
}
