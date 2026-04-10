package api

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

// loadAuditEvents loads audit events from the configured backend. When a SQL
// audit store is enabled it mirrors local append-only audit files into the
// database and reads from there; otherwise it falls back to direct file scans.
func (a *API) loadAuditEvents() ([]models.AuditEvent, error) {
	if a != nil && a.auditStore != nil {
		var syncErr error
		if !a.auditSyncBg.Load() {
			syncErr = a.syncAuditStore()
		}
		events, err := a.auditStore.ListEvents()
		switch {
		case err == nil && (syncErr == nil || len(events) > 0):
			return events, nil
		case err != nil:
			return nil, err
		default:
			return nil, syncErr
		}
	}
	events, localNames, err := a.loadAuditEventsFromFiles()
	if err != nil {
		return nil, err
	}
	if a == nil || a.auditArchiveStore == nil {
		return events, nil
	}
	archived, archiveErr := a.loadArchivedAuditEvents(context.Background(), localNames)
	if archiveErr != nil {
		if len(events) > 0 {
			log.Printf("api: load archived audit events: %v", archiveErr)
			return events, nil
		}
		return nil, archiveErr
	}
	return mergeAuditEvents(events, archived), nil
}

func (a *API) loadAuditEventsFromFiles() ([]models.AuditEvent, map[string]struct{}, error) {
	dir := a.config.AuditLogDir
	if dir == "" {
		return nil, nil, fmt.Errorf("audit log directory not configured")
	}

	paths, err := listAuditLogFiles(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []models.AuditEvent{}, map[string]struct{}{}, nil
		}
		return nil, nil, fmt.Errorf("failed to read audit directory: %w", err)
	}

	events := make([]models.AuditEvent, 0)
	localNames := make(map[string]struct{}, len(paths))
	for _, filePath := range paths {
		localNames[auditArchiveRelativeName(dir, filePath)] = struct{}{}
		file, err := os.Open(filePath)
		if err != nil {
			return nil, nil, err
		}
		fileEvents, readErr := readAuditEventsFromReader(filePath, file)
		_ = file.Close()
		if readErr != nil {
			return nil, nil, readErr
		}
		events = append(events, fileEvents...)
	}
	return mergeAuditEvents(events), localNames, nil
}

func readAuditEventsFromReader(sourcePath string, r io.Reader) ([]models.AuditEvent, error) {
	var events []models.AuditEvent
	reader := bufio.NewReader(r)
	var currentOffset int64
	for {
		lineOffset := currentOffset
		line, readErr := reader.ReadBytes('\n')
		currentOffset += int64(len(line))
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) > 0 {
			event, err := parseAuditLogLine(sourcePath, lineOffset, trimmed)
			if err == nil && event != nil {
				events = append(events, *event)
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return nil, readErr
		}
	}
	return events, nil
}

func mergeAuditEvents(groups ...[]models.AuditEvent) []models.AuditEvent {
	if len(groups) == 0 {
		return []models.AuditEvent{}
	}
	byID := make(map[string]models.AuditEvent)
	for _, group := range groups {
		for _, event := range group {
			byID[event.ID] = event
		}
	}
	events := make([]models.AuditEvent, 0, len(byID))
	for _, event := range byID {
		events = append(events, event)
	}
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.After(events[j].Timestamp)
	})
	return events
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
			"total":   len(events),
			"by_type": byType,
			"by_hour": byHour,
			"by_user": byUser,
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
