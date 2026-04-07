package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

// loadAuditEvents reads NDJSON audit log files from the configured directory.
func (a *API) loadAuditEvents() ([]models.AuditEvent, error) {
	dir := a.config.AuditLogDir
	if dir == "" {
		return nil, fmt.Errorf("audit log directory not configured")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []models.AuditEvent{}, nil
		}
		return nil, fmt.Errorf("failed to read audit directory: %w", err)
	}

	var events []models.AuditEvent
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		filePath := filepath.Join(dir, entry.Name())
		fileEvents, err := readNDJSON(filePath)
		if err != nil {
			continue // skip corrupt files
		}
		events = append(events, fileEvents...)
	}

	// Sort by timestamp descending (most recent first)
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.After(events[j].Timestamp)
	})

	return events, nil
}

func readNDJSON(path string) ([]models.AuditEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var events []models.AuditEvent
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<20) // 1MB buffer
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev models.AuditEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}
		events = append(events, ev)
	}
	return events, scanner.Err()
}

// handleListAuditEvents lists audit events with pagination and filtering.
func (a *API) handleListAuditEvents(w http.ResponseWriter, r *http.Request) {
	events, err := a.loadAuditEvents()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	q := r.URL.Query()
	typeFilter := q.Get("type")
	userFilter := q.Get("user")
	fromStr := q.Get("from")
	toStr := q.Get("to")

	var fromTime, toTime time.Time
	if fromStr != "" {
		fromTime, _ = time.Parse(time.RFC3339, fromStr)
	}
	if toStr != "" {
		toTime, _ = time.Parse(time.RFC3339, toStr)
	}

	filtered := events[:0:0]
	for _, ev := range events {
		if typeFilter != "" && ev.EventType != typeFilter {
			continue
		}
		if userFilter != "" && ev.Username != userFilter {
			continue
		}
		if !fromTime.IsZero() && ev.Timestamp.Before(fromTime) {
			continue
		}
		if !toTime.IsZero() && ev.Timestamp.After(toTime) {
			continue
		}
		filtered = append(filtered, ev)
	}

	page, perPage := parsePagination(r)
	total := len(filtered)
	start, end := paginate(total, page, perPage)

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    filtered[start:end],
		Total:   total,
		Page:    page,
		PerPage: perPage,
	})
}

// handleGetAuditEvent returns a single audit event by ID.
func (a *API) handleGetAuditEvent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing event id")
		return
	}

	events, err := a.loadAuditEvents()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	for _, ev := range events {
		if ev.ID == id {
			writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: ev})
			return
		}
	}

	writeError(w, http.StatusNotFound, "audit event not found")
}

// handleSearchAudit performs full-text search across audit logs.
func (a *API) handleSearchAudit(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		writeError(w, http.StatusBadRequest, "query parameter 'q' is required")
		return
	}

	events, err := a.loadAuditEvents()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	queryLower := strings.ToLower(query)
	var results []models.AuditEvent
	for _, ev := range events {
		// Search across multiple fields
		searchable := strings.ToLower(
			ev.EventType + " " + ev.Username + " " + ev.SourceIP + " " +
				ev.TargetHost + " " + ev.Details + " " + ev.SessionID,
		)
		if strings.Contains(searchable, queryLower) {
			results = append(results, ev)
		}
	}

	page, perPage := parsePagination(r)
	total := len(results)
	start, end := paginate(total, page, perPage)

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    results[start:end],
		Total:   total,
		Page:    page,
		PerPage: perPage,
	})
}

// handleExportAudit exports audit events as CSV.
func (a *API) handleExportAudit(w http.ResponseWriter, r *http.Request) {
	events, err := a.loadAuditEvents()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=audit_export.csv")
	w.WriteHeader(http.StatusOK)

	// Write CSV header
	fmt.Fprintln(w, "id,timestamp,event_type,username,source_ip,target_host,details,session_id")
	for _, ev := range events {
		fmt.Fprintf(w, "%s,%s,%s,%s,%s,%s,%s,%s\n",
			csvEscape(ev.ID),
			ev.Timestamp.Format(time.RFC3339),
			csvEscape(ev.EventType),
			csvEscape(ev.Username),
			csvEscape(ev.SourceIP),
			csvEscape(ev.TargetHost),
			csvEscape(ev.Details),
			csvEscape(ev.SessionID),
		)
	}
}

// handleAuditStats returns aggregate statistics about audit events.
func (a *API) handleAuditStats(w http.ResponseWriter, r *http.Request) {
	events, err := a.loadAuditEvents()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	byType := make(map[string]int)
	byHour := make(map[string]int)
	byUser := make(map[string]int)

	for _, ev := range events {
		byType[ev.EventType]++
		hour := ev.Timestamp.Format("2006-01-02T15")
		byHour[hour]++
		byUser[ev.Username]++
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"total":        len(events),
			"by_type":      byType,
			"by_hour":      byHour,
			"by_user":      byUser,
		},
	})
}

// csvEscape quotes a string for CSV output.
func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}
