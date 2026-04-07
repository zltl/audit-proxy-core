package collab

import (
	"sync"
	"time"
)

// ChatMessage represents a single message in a session chat.
type ChatMessage struct {
	ID        string    `json:"id"`
	SessionID string    `json:"session_id"`
	Username  string    `json:"username"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
}

// ChatRoom manages the chat for a single shared session.
type ChatRoom struct {
	sessionID   string
	messages    []ChatMessage
	mu          sync.RWMutex
	maxMessages int
	subscribers map[string]chan ChatMessage
}

// NewChatRoom creates a new ChatRoom for the given session.
func NewChatRoom(sessionID string, maxMessages int) *ChatRoom {
	return &ChatRoom{
		sessionID:   sessionID,
		messages:    make([]ChatMessage, 0),
		maxMessages: maxMessages,
		subscribers: make(map[string]chan ChatMessage),
	}
}

// SendMessage sends a user message to the chat room.
func (cr *ChatRoom) SendMessage(username, message string) *ChatMessage {
	msg := ChatMessage{
		ID:        generateID(),
		SessionID: cr.sessionID,
		Username:  username,
		Message:   message,
		Timestamp: time.Now(),
		Type:      "message",
	}

	cr.addMessage(msg)
	return &msg
}

// SystemMessage sends a system message to the chat room.
func (cr *ChatRoom) SystemMessage(message string) *ChatMessage {
	msg := ChatMessage{
		ID:        generateID(),
		SessionID: cr.sessionID,
		Username:  "system",
		Message:   message,
		Timestamp: time.Now(),
		Type:      "system",
	}

	cr.addMessage(msg)
	return &msg
}

func (cr *ChatRoom) addMessage(msg ChatMessage) {
	cr.mu.Lock()
	cr.messages = append(cr.messages, msg)
	if cr.maxMessages > 0 && len(cr.messages) > cr.maxMessages {
		cr.messages = cr.messages[len(cr.messages)-cr.maxMessages:]
	}

	// Copy subscriber map to release lock before sending
	subs := make(map[string]chan ChatMessage, len(cr.subscribers))
	for k, v := range cr.subscribers {
		subs[k] = v
	}
	cr.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- msg:
		default:
		}
	}
}

// GetHistory returns the last `limit` messages. If limit <= 0, returns all.
func (cr *ChatRoom) GetHistory(limit int) []ChatMessage {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	if limit <= 0 || limit > len(cr.messages) {
		result := make([]ChatMessage, len(cr.messages))
		copy(result, cr.messages)
		return result
	}

	start := len(cr.messages) - limit
	result := make([]ChatMessage, limit)
	copy(result, cr.messages[start:])
	return result
}

// Subscribe returns a channel that receives new chat messages.
func (cr *ChatRoom) Subscribe(username string) <-chan ChatMessage {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	ch := make(chan ChatMessage, 256)
	cr.subscribers[username] = ch
	return ch
}

// Unsubscribe removes a user's chat subscription and closes the channel.
func (cr *ChatRoom) Unsubscribe(username string) {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	if ch, ok := cr.subscribers[username]; ok {
		close(ch)
		delete(cr.subscribers, username)
	}
}
