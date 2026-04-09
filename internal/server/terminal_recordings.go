package server

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/ws"
)

const terminalRecordingBasePath = "/api/v2/terminal/recordings"

func (s *Server) handleTerminalRecordingDownload(terminalHandler *ws.TerminalHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if terminalHandler == nil {
			http.NotFound(w, r)
			return
		}

		recordingID := r.PathValue("id")
		recordingPath, err := terminalHandler.RecordingFilePath(recordingID)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				http.Error(w, "terminal recording not found", http.StatusNotFound)
				return
			}
			http.Error(w, "invalid terminal recording identifier", http.StatusBadRequest)
			return
		}

		file, err := os.Open(recordingPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				http.Error(w, "terminal recording not found", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to open terminal recording", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		info, err := file.Stat()
		if err != nil {
			http.Error(w, "failed to stat terminal recording", http.StatusInternalServerError)
			return
		}

		name := filepath.Base(recordingPath)
		w.Header().Set("Content-Type", "application/x-asciicast")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
		http.ServeContent(w, r, name, info.ModTime(), file)
	}
}
