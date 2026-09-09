# ASCII Stream Demo

Timed ASCII “video stream” storyboard in **asciicast v2** — the same format the
proxy writes for real SSH sessions. Use it to show live drip + sealed playback
without standing up a dataplane.

## 30-second talk track

1. Open **ASCII Demo** in the sidebar (`/demo/ascii-stream`).
2. Click **Start live stream** (2× is fine). Call out matrix rain → proxy
   handshake → normal commands → policy block → session kill.
3. Point at the WebSocket: same `session.live.chunk` shape as
   `/ws/sessions/{id}/live`.
4. Scroll to **Recording Playback** and scrub the sealed cast — identical bytes
   as `GET /api/v2/demo/ascii-stream.cast`.

## CLI

```bash
# Regenerate committed casts (also copy into internal/asciidemo for embed)
go run ./demos/ascii-stream generate -out demos/ascii-stream/demo.cast
cp demos/ascii-stream/demo.cast internal/asciidemo/demo.cast

# Local terminal “video stream”
audit-proxy play --file demos/ascii-stream/demo.cast
audit-proxy play --file demos/ascii-stream/demo.cast --speed 4

# Optional: drip into a live-writable file via dp.Recorder
go run ./demos/ascii-stream drip -out /tmp/ascii-live.cast --speed 2
```

Or: `make demo-ascii` to regenerate both cast copies.

## Layout

| Path | Role |
|------|------|
| `internal/asciidemo/` | Storyboard, cast writer/drip, embedded `demo.cast` |
| `demos/ascii-stream/main.go` | `generate` / `drip` CLI |
| `/demo/ascii-stream` | Web live + asciinema playback |
| `/ws/demo/ascii-stream` | Timed drip WebSocket |
| `/api/v2/demo/ascii-stream.cast` | Cast download |
