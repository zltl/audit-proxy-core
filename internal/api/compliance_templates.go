package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/compliance"
)

var errReportTemplateNotFound = errors.New("report template not found")

type reportTemplateStore struct {
	mu        sync.RWMutex
	path      string
	templates map[string]compliance.CustomReportTemplate
}

func newReportTemplateStore(path string) *reportTemplateStore {
	store := &reportTemplateStore{
		path:      path,
		templates: make(map[string]compliance.CustomReportTemplate),
	}
	store.load()
	return store
}

func (s *reportTemplateStore) load() {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var templates []compliance.CustomReportTemplate
	if err := json.Unmarshal(data, &templates); err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, template := range templates {
		s.templates[template.ID] = template
	}
}

func (s *reportTemplateStore) saveLocked() error {
	templates := make([]compliance.CustomReportTemplate, 0, len(s.templates))
	for _, template := range s.templates {
		templates = append(templates, template)
	}
	sort.Slice(templates, func(i, j int) bool {
		if templates[i].Name == templates[j].Name {
			return templates[i].ID < templates[j].ID
		}
		return templates[i].Name < templates[j].Name
	})
	data, err := json.MarshalIndent(templates, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}

func (s *reportTemplateStore) list() []compliance.CustomReportTemplate {
	if s == nil {
		return []compliance.CustomReportTemplate{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	templates := make([]compliance.CustomReportTemplate, 0, len(s.templates))
	for _, template := range s.templates {
		templates = append(templates, template)
	}
	sort.Slice(templates, func(i, j int) bool {
		if templates[i].Name == templates[j].Name {
			return templates[i].ID < templates[j].ID
		}
		return templates[i].Name < templates[j].Name
	})
	return templates
}

func (s *reportTemplateStore) get(id string) (compliance.CustomReportTemplate, bool) {
	if s == nil {
		return compliance.CustomReportTemplate{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	template, ok := s.templates[id]
	return template, ok
}

func (s *reportTemplateStore) create(template compliance.CustomReportTemplate) (compliance.CustomReportTemplate, error) {
	if s == nil {
		return compliance.CustomReportTemplate{}, errReportTemplateNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if template.ID == "" {
		template.ID = newReportTemplateID()
	}
	if _, exists := s.templates[template.ID]; exists {
		return compliance.CustomReportTemplate{}, fmt.Errorf("report template already exists")
	}
	s.templates[template.ID] = template
	if err := s.saveLocked(); err != nil {
		delete(s.templates, template.ID)
		return compliance.CustomReportTemplate{}, err
	}
	return template, nil
}

func (s *reportTemplateStore) update(id string, template compliance.CustomReportTemplate) (compliance.CustomReportTemplate, error) {
	if s == nil {
		return compliance.CustomReportTemplate{}, errReportTemplateNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.templates[id]; !exists {
		return compliance.CustomReportTemplate{}, errReportTemplateNotFound
	}
	template.ID = id
	s.templates[id] = template
	if err := s.saveLocked(); err != nil {
		return compliance.CustomReportTemplate{}, err
	}
	return template, nil
}

func (s *reportTemplateStore) delete(id string) error {
	if s == nil {
		return errReportTemplateNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.templates[id]; !exists {
		return errReportTemplateNotFound
	}
	delete(s.templates, id)
	return s.saveLocked()
}

func newReportTemplateID() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("tpl-%d", time.Now().UnixNano())
	}
	return "tpl-" + hex.EncodeToString(raw[:])
}

func (a *API) handleListReportTemplates(w http.ResponseWriter, r *http.Request) {
	if !a.requireCompliance(w) {
		return
	}
	templates := a.compliance.templates.list()
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    templates,
		Total:   len(templates),
	})
}

func (a *API) handleGetReportTemplate(w http.ResponseWriter, r *http.Request) {
	if !a.requireCompliance(w) {
		return
	}
	template, ok := a.compliance.templates.get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "report template not found")
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: template})
}

func (a *API) handleCreateReportTemplate(w http.ResponseWriter, r *http.Request) {
	if !a.requireCompliance(w) {
		return
	}
	template, err := a.readReportTemplatePayload(r, compliance.CustomReportTemplate{})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	template, err = a.compliance.templates.create(template)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, APIResponse{Success: true, Data: template})
}

func (a *API) handleUpdateReportTemplate(w http.ResponseWriter, r *http.Request) {
	if !a.requireCompliance(w) {
		return
	}
	existing, ok := a.compliance.templates.get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "report template not found")
		return
	}
	template, err := a.readReportTemplatePayload(r, existing)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	template, err = a.compliance.templates.update(existing.ID, template)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: template})
}

func (a *API) handleDeleteReportTemplate(w http.ResponseWriter, r *http.Request) {
	if !a.requireCompliance(w) {
		return
	}
	if err := a.compliance.templates.delete(r.PathValue("id")); err != nil {
		if errors.Is(err, errReportTemplateNotFound) {
			writeError(w, http.StatusNotFound, "report template not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: map[string]string{"message": "Report template deleted"}})
}

func (a *API) handleExportReportTemplate(w http.ResponseWriter, r *http.Request) {
	if !a.requireCompliance(w) {
		return
	}
	template, ok := a.compliance.templates.get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "report template not found")
		return
	}
	result, err := a.compliance.gen.ExecuteCustomReportTemplate(template)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = strings.ToLower(strings.TrimSpace(template.DefaultFormat))
	}
	switch format {
	case "", "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename="+template.ID+".csv")
		if err := a.compliance.gen.ExportCustomReportCSV(result, w); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
	case "pdf":
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", "attachment; filename="+template.ID+".pdf")
		if err := a.compliance.gen.ExportCustomReportPDF(result, w); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
	default:
		writeError(w, http.StatusBadRequest, "unsupported export format")
	}
}

func (a *API) readReportTemplatePayload(r *http.Request, base compliance.CustomReportTemplate) (compliance.CustomReportTemplate, error) {
	var req struct {
		ID            string `json:"id"`
		Name          string `json:"name"`
		Description   string `json:"description"`
		Query         string `json:"query"`
		DefaultFormat string `json:"default_format"`
	}
	if err := readJSON(r, &req); err != nil {
		return compliance.CustomReportTemplate{}, err
	}
	now := time.Now().UTC()
	if base.ID == "" {
		base.CreatedAt = now
	}
	base.ID = strings.TrimSpace(req.ID)
	base.Name = strings.TrimSpace(req.Name)
	base.Description = strings.TrimSpace(req.Description)
	base.Query = strings.TrimSpace(req.Query)
	base.DefaultFormat = strings.ToLower(strings.TrimSpace(req.DefaultFormat))
	if base.DefaultFormat == "" {
		base.DefaultFormat = "csv"
	}
	base.UpdatedAt = now
	user := strings.TrimSpace(r.Header.Get("X-User"))
	if base.CreatedBy == "" {
		base.CreatedBy = user
	}
	base.UpdatedBy = user
	if err := a.compliance.gen.ValidateCustomReportTemplate(base); err != nil {
		return compliance.CustomReportTemplate{}, err
	}
	return base, nil
}
