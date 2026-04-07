package collab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RecordingEvent represents a single event in a session recording.
type RecordingEvent struct {
	Time     float64 `json:"time"`
	Type     string  `json:"type"`
	Data     string  `json:"data"`
	Username string  `json:"username,omitempty"`
}

// Recorder records session events in NDJSON format.
type Recorder struct {
	sessionID string
	events    []RecordingEvent
	mu        sync.Mutex
	startTime time.Time
	file      *os.File
}

// NewRecorder creates a new Recorder that writes to outputDir/<sessionID>.jsonl.
func NewRecorder(sessionID, outputDir string) (*Recorder, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, err
	}

	path := filepath.Join(outputDir, sessionID+".jsonl")
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}

	return &Recorder{
		sessionID: sessionID,
		events:    make([]RecordingEvent, 0),
		startTime: time.Now(),
		file:      f,
	}, nil
}

func (r *Recorder) elapsed() float64 {
	return time.Since(r.startTime).Seconds()
}

func (r *Recorder) record(event RecordingEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, event)

	if r.file != nil {
		data, err := json.Marshal(event)
		if err == nil {
			r.file.Write(data)
			r.file.Write([]byte("\n"))
		}
	}
}

// RecordOutput records terminal output data.
func (r *Recorder) RecordOutput(data string) {
	r.record(RecordingEvent{
		Time: r.elapsed(),
		Type: "output",
		Data: data,
	})
}

// RecordInput records user input data.
func (r *Recorder) RecordInput(username, data string) {
	r.record(RecordingEvent{
		Time:     r.elapsed(),
		Type:     "input",
		Data:     data,
		Username: username,
	})
}

// RecordJoin records a user joining the session.
func (r *Recorder) RecordJoin(username string) {
	r.record(RecordingEvent{
		Time:     r.elapsed(),
		Type:     "join",
		Data:     username + " joined",
		Username: username,
	})
}

// RecordLeave records a user leaving the session.
func (r *Recorder) RecordLeave(username string) {
	r.record(RecordingEvent{
		Time:     r.elapsed(),
		Type:     "leave",
		Data:     username + " left",
		Username: username,
	})
}

// RecordChat records a chat message.
func (r *Recorder) RecordChat(username, message string) {
	r.record(RecordingEvent{
		Time:     r.elapsed(),
		Type:     "chat",
		Data:     message,
		Username: username,
	})
}

// RecordControlChange records a control handoff between users.
func (r *Recorder) RecordControlChange(from, to string) {
	r.record(RecordingEvent{
		Time: r.elapsed(),
		Type: "control",
		Data: "control transferred from " + from + " to " + to,
	})
}

// Close flushes and closes the recording file.
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.file != nil {
		return r.file.Close()
	}
	return nil
}

// Events returns a copy of all recorded events.
func (r *Recorder) Events() []RecordingEvent {
	r.mu.Lock()
	defer r.mu.Unlock()

	result := make([]RecordingEvent, len(r.events))
	copy(result, r.events)
	return result
}
