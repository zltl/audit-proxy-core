// Package ws provides WebSocket handlers including a terminal proxy that
// bridges browser xterm.js sessions to SSH connections through the data plane.
package ws

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// TerminalHandler handles WebSocket connections for the web terminal feature.
// It connects the browser (xterm.js) to a target SSH server by opening a raw
// TCP connection to the data plane's SSH proxy port.
type TerminalHandler struct {
	// ProxyAddr is the data plane SSH proxy address (e.g., "127.0.0.1:2222").
	ProxyAddr string
}

// terminalMsg is the JSON message format between browser and server.
type terminalMsg struct {
	Type string `json:"type"`           // "data", "resize", "ping"
	Data string `json:"data,omitempty"` // terminal data (base64 or raw)
	Cols int    `json:"cols,omitempty"` // terminal columns (for resize)
	Rows int    `json:"rows,omitempty"` // terminal rows (for resize)
}

// ServeHTTP upgrades to WebSocket and bridges to the SSH proxy.
func (h *TerminalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	wsConn, err := Upgrade(w, r)
	if err != nil {
		log.Printf("terminal: websocket upgrade failed: %v", err)
		return
	}
	defer wsConn.Close()

	host := r.URL.Query().Get("host")
	if host == "" {
		wsConn.WriteText([]byte(`{"type":"error","data":"missing host parameter"}`))
		return
	}

	// Connect to the SSH proxy data plane.
	proxyAddr := h.ProxyAddr
	if proxyAddr == "" {
		proxyAddr = "127.0.0.1:2222"
	}

	tcpConn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		errMsg, _ := json.Marshal(terminalMsg{
			Type: "error",
			Data: "failed to connect to SSH proxy: " + err.Error(),
		})
		wsConn.WriteText(errMsg)
		log.Printf("terminal: connect to proxy %s: %v", proxyAddr, err)
		return
	}
	defer tcpConn.Close()

	// Send connection metadata (target host) as initial message.
	connectMsg, _ := json.Marshal(terminalMsg{
		Type: "data",
		Data: "Connected to " + host + " via SSH Proxy\r\n",
	})
	wsConn.WriteText(connectMsg)

	var wg sync.WaitGroup
	done := make(chan struct{})

	// WebSocket → TCP (browser input to SSH).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			_, payload, err := wsConn.ReadMessage()
			if err != nil {
				if err != io.EOF {
					log.Printf("terminal: ws read: %v", err)
				}
				tcpConn.Close()
				return
			}

			var msg terminalMsg
			if err := json.Unmarshal(payload, &msg); err != nil {
				// Raw data fallback.
				tcpConn.Write(payload)
				continue
			}

			switch msg.Type {
			case "data":
				tcpConn.Write([]byte(msg.Data))
			case "resize":
				// SSH window change would be handled here.
				log.Printf("terminal: resize %dx%d", msg.Cols, msg.Rows)
			case "ping":
				wsConn.WriteText([]byte(`{"type":"pong"}`))
			}
		}
	}()

	// TCP → WebSocket (SSH output to browser).
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := tcpConn.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("terminal: tcp read: %v", err)
				}
				close(done)
				return
			}
			msg, _ := json.Marshal(terminalMsg{
				Type: "data",
				Data: string(buf[:n]),
			})
			if err := wsConn.WriteText(msg); err != nil {
				log.Printf("terminal: ws write: %v", err)
				return
			}
		}
	}()

	<-done
	wg.Wait()
}
