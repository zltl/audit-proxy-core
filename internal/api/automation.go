package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

var (
	errAutomationScriptNotFound = errors.New("automation script not found")
	errAutomationJobNotFound    = errors.New("automation job not found")
	errAutomationRunNotFound    = errors.New("automation run not found")
	errAutomationJobBusy        = errors.New("automation job is already running")
)

type automationScript struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Shell       string    `json:"shell,omitempty"`
	Body        string    `json:"body"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	CreatedBy   string    `json:"created_by,omitempty"`
	UpdatedBy   string    `json:"updated_by,omitempty"`
}

type automationHop struct {
	Name       string `json:"name,omitempty"`
	Host       string `json:"host"`
	Port       int    `json:"port,omitempty"`
	Username   string `json:"username"`
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

type automationTarget struct {
	ID                        string            `json:"id,omitempty"`
	Name                      string            `json:"name,omitempty"`
	Host                      string            `json:"host,omitempty"`
	Port                      int               `json:"port,omitempty"`
	Username                  string            `json:"username,omitempty"`
	Password                  string            `json:"password,omitempty"`
	PrivateKey                string            `json:"private_key,omitempty"`
	Passphrase                string            `json:"passphrase,omitempty"`
	KnownHostsPath            string            `json:"known_hosts_path,omitempty"`
	InsecureSkipHostKeyVerify bool              `json:"insecure_skip_host_key_verify,omitempty"`
	Environment               map[string]string `json:"environment,omitempty"`
}

type automationJob struct {
	ID                        string            `json:"id"`
	Name                      string            `json:"name"`
	Description               string            `json:"description,omitempty"`
	Command                   string            `json:"command,omitempty"`
	ScriptID                  string            `json:"script_id,omitempty"`
	Schedule                  string            `json:"schedule,omitempty"`
	Timeout                   string            `json:"timeout,omitempty"`
	ServerIDs                 []string          `json:"server_ids,omitempty"`
	Targets                   []automationTarget `json:"targets,omitempty"`
	Environment               map[string]string `json:"environment,omitempty"`
	Username                  string            `json:"username,omitempty"`
	Password                  string            `json:"password,omitempty"`
	PrivateKey                string            `json:"private_key,omitempty"`
	Passphrase                string            `json:"passphrase,omitempty"`
	KnownHostsPath            string            `json:"known_hosts_path,omitempty"`
	InsecureSkipHostKeyVerify bool              `json:"insecure_skip_host_key_verify,omitempty"`
	JumpChain                 []automationHop   `json:"jump_chain,omitempty"`
	TriggerProviders          []string          `json:"trigger_providers,omitempty"`
	Enabled                   bool              `json:"enabled"`
	NextRunAt                 time.Time         `json:"next_run_at,omitempty"`
	LastRunAt                 time.Time         `json:"last_run_at,omitempty"`
	LastStatus                string            `json:"last_status,omitempty"`
	LastSummary               string            `json:"last_summary,omitempty"`
	LastError                 string            `json:"last_error,omitempty"`
	CreatedAt                 time.Time         `json:"created_at"`
	UpdatedAt                 time.Time         `json:"updated_at"`
	CreatedBy                 string            `json:"created_by,omitempty"`
	UpdatedBy                 string            `json:"updated_by,omitempty"`
}

type automationTargetResult struct {
	TargetID   string    `json:"target_id,omitempty"`
	TargetName string    `json:"target_name,omitempty"`
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	Status     string    `json:"status"`
	ExitCode   int       `json:"exit_code,omitempty"`
	Summary    string    `json:"summary,omitempty"`
	Stdout     string    `json:"stdout,omitempty"`
	Stderr     string    `json:"stderr,omitempty"`
	Error      string    `json:"error,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}

type automationRun struct {
	ID         string                   `json:"id"`
	JobID      string                   `json:"job_id"`
	JobName    string                   `json:"job_name"`
	Trigger    string                   `json:"trigger"`
	RequestedBy string                  `json:"requested_by,omitempty"`
	Status     string                   `json:"status"`
	Summary    string                   `json:"summary,omitempty"`
	StartedAt  time.Time                `json:"started_at"`
	FinishedAt time.Time                `json:"finished_at,omitempty"`
	Results    []automationTargetResult `json:"results,omitempty"`
}

type automationResolvedTarget struct {
	ID                        string
	Name                      string
	Host                      string
	Port                      int
	Username                  string
	Password                  string
	PrivateKey                string
	Passphrase                string
	KnownHostsPath            string
	InsecureSkipHostKeyVerify bool
	Environment               map[string]string
	JumpChain                 []automationHop
}

type automationExecutionRequest struct {
	Command     string
	Environment map[string]string
	Script      *automationScript
	Target      automationResolvedTarget
}

type automationExecutor interface {
	Execute(ctx context.Context, req automationExecutionRequest) automationTargetResult
}

type automationState struct {
	scripts       *automationScriptStore
	jobs          *automationJobStore
	runs          *automationRunStore
	executor      automationExecutor
	schedulerOnce sync.Once
	activeMu      sync.Mutex
	activeJobs    map[string]struct{}
}

type automationScriptStore struct {
	mu      sync.RWMutex
	path    string
	scripts map[string]automationScript
}

type automationJobStore struct {
	mu   sync.RWMutex
	path string
	jobs map[string]automationJob
}

type automationRunStore struct {
	mu   sync.RWMutex
	path string
	runs map[string]automationRun
}

func newAutomationState(dataDir string, executor automationExecutor) *automationState {
	if executor == nil {
		executor = newSSHAutomationExecutor()
	}
	return &automationState{
		scripts:    newAutomationScriptStore(dataFilePath(dataDir, "automation_scripts.json")),
		jobs:       newAutomationJobStore(dataFilePath(dataDir, "automation_jobs.json")),
		runs:       newAutomationRunStore(dataFilePath(dataDir, "automation_runs.json")),
		executor:   executor,
		activeJobs: make(map[string]struct{}),
	}
}

func newAutomationScriptStore(path string) *automationScriptStore {
	store := &automationScriptStore{
		path:    path,
		scripts: make(map[string]automationScript),
	}
	store.load()
	return store
}

func (s *automationScriptStore) load() {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var scripts []automationScript
	if err := json.Unmarshal(data, &scripts); err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, script := range scripts {
		s.scripts[script.ID] = script
	}
}

func (s *automationScriptStore) saveLocked() error {
	items := make([]automationScript, 0, len(s.scripts))
	for _, script := range s.scripts {
		items = append(items, script)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Name == items[j].Name {
			return items[i].ID < items[j].ID
		}
		return items[i].Name < items[j].Name
	})
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}

func (s *automationScriptStore) list() []automationScript {
	if s == nil {
		return []automationScript{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]automationScript, 0, len(s.scripts))
	for _, script := range s.scripts {
		items = append(items, script)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Name == items[j].Name {
			return items[i].ID < items[j].ID
		}
		return items[i].Name < items[j].Name
	})
	return items
}

func (s *automationScriptStore) get(id string) (automationScript, bool) {
	if s == nil {
		return automationScript{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.scripts[id]
	return item, ok
}

func (s *automationScriptStore) create(script automationScript) (automationScript, error) {
	if s == nil {
		return automationScript{}, errors.New("automation scripts unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if script.ID == "" {
		script.ID = newAutomationID("script")
	}
	if _, exists := s.scripts[script.ID]; exists {
		return automationScript{}, fmt.Errorf("automation script already exists")
	}
	s.scripts[script.ID] = script
	if err := s.saveLocked(); err != nil {
		delete(s.scripts, script.ID)
		return automationScript{}, err
	}
	return script, nil
}

func (s *automationScriptStore) update(id string, script automationScript) (automationScript, error) {
	if s == nil {
		return automationScript{}, errors.New("automation scripts unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.scripts[id]; !exists {
		return automationScript{}, errAutomationScriptNotFound
	}
	script.ID = id
	s.scripts[id] = script
	if err := s.saveLocked(); err != nil {
		return automationScript{}, err
	}
	return script, nil
}

func (s *automationScriptStore) delete(id string) error {
	if s == nil {
		return errors.New("automation scripts unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.scripts[id]; !exists {
		return errAutomationScriptNotFound
	}
	delete(s.scripts, id)
	return s.saveLocked()
}

func newAutomationJobStore(path string) *automationJobStore {
	store := &automationJobStore{
		path: path,
		jobs: make(map[string]automationJob),
	}
	store.load()
	return store
}

func (s *automationJobStore) load() {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var jobs []automationJob
	if err := json.Unmarshal(data, &jobs); err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, job := range jobs {
		s.jobs[job.ID] = job
	}
}

func (s *automationJobStore) saveLocked() error {
	items := make([]automationJob, 0, len(s.jobs))
	for _, job := range s.jobs {
		items = append(items, job)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Name == items[j].Name {
			return items[i].ID < items[j].ID
		}
		return items[i].Name < items[j].Name
	})
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}

func (s *automationJobStore) list() []automationJob {
	if s == nil {
		return []automationJob{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]automationJob, 0, len(s.jobs))
	for _, job := range s.jobs {
		items = append(items, job)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Name == items[j].Name {
			return items[i].ID < items[j].ID
		}
		return items[i].Name < items[j].Name
	})
	return items
}

func (s *automationJobStore) get(id string) (automationJob, bool) {
	if s == nil {
		return automationJob{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.jobs[id]
	return item, ok
}

func (s *automationJobStore) create(job automationJob) (automationJob, error) {
	if s == nil {
		return automationJob{}, errors.New("automation jobs unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if job.ID == "" {
		job.ID = newAutomationID("job")
	}
	if _, exists := s.jobs[job.ID]; exists {
		return automationJob{}, fmt.Errorf("automation job already exists")
	}
	s.jobs[job.ID] = job
	if err := s.saveLocked(); err != nil {
		delete(s.jobs, job.ID)
		return automationJob{}, err
	}
	return job, nil
}

func (s *automationJobStore) update(id string, job automationJob) (automationJob, error) {
	if s == nil {
		return automationJob{}, errors.New("automation jobs unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.jobs[id]; !exists {
		return automationJob{}, errAutomationJobNotFound
	}
	job.ID = id
	s.jobs[id] = job
	if err := s.saveLocked(); err != nil {
		return automationJob{}, err
	}
	return job, nil
}

func (s *automationJobStore) patch(id string, mutate func(*automationJob) error) (automationJob, error) {
	if s == nil {
		return automationJob{}, errors.New("automation jobs unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	job, exists := s.jobs[id]
	if !exists {
		return automationJob{}, errAutomationJobNotFound
	}
	if err := mutate(&job); err != nil {
		return automationJob{}, err
	}
	s.jobs[id] = job
	if err := s.saveLocked(); err != nil {
		return automationJob{}, err
	}
	return job, nil
}

func (s *automationJobStore) delete(id string) error {
	if s == nil {
		return errors.New("automation jobs unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.jobs[id]; !exists {
		return errAutomationJobNotFound
	}
	delete(s.jobs, id)
	return s.saveLocked()
}

func newAutomationRunStore(path string) *automationRunStore {
	store := &automationRunStore{
		path: path,
		runs: make(map[string]automationRun),
	}
	store.load()
	return store
}

func (s *automationRunStore) load() {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var runs []automationRun
	if err := json.Unmarshal(data, &runs); err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, run := range runs {
		s.runs[run.ID] = run
	}
}

func (s *automationRunStore) saveLocked() error {
	items := make([]automationRun, 0, len(s.runs))
	for _, run := range s.runs {
		items = append(items, run)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].StartedAt.Equal(items[j].StartedAt) {
			return items[i].ID > items[j].ID
		}
		return items[i].StartedAt.After(items[j].StartedAt)
	})
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}

func (s *automationRunStore) list() []automationRun {
	if s == nil {
		return []automationRun{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]automationRun, 0, len(s.runs))
	for _, run := range s.runs {
		items = append(items, run)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].StartedAt.Equal(items[j].StartedAt) {
			return items[i].ID > items[j].ID
		}
		return items[i].StartedAt.After(items[j].StartedAt)
	})
	return items
}

func (s *automationRunStore) get(id string) (automationRun, bool) {
	if s == nil {
		return automationRun{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.runs[id]
	return item, ok
}

func (s *automationRunStore) create(run automationRun) (automationRun, error) {
	if s == nil {
		return automationRun{}, errors.New("automation runs unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if run.ID == "" {
		run.ID = newAutomationID("run")
	}
	s.runs[run.ID] = run
	if err := s.saveLocked(); err != nil {
		delete(s.runs, run.ID)
		return automationRun{}, err
	}
	return run, nil
}

func (s *automationRunStore) update(id string, run automationRun) (automationRun, error) {
	if s == nil {
		return automationRun{}, errors.New("automation runs unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.runs[id]; !exists {
		return automationRun{}, errAutomationRunNotFound
	}
	run.ID = id
	s.runs[id] = run
	if err := s.saveLocked(); err != nil {
		return automationRun{}, err
	}
	return run, nil
}

func (s *automationRunStore) getOrCreate(id string, run automationRun) (automationRun, error) {
	if s == nil {
		return automationRun{}, errors.New("automation runs unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == "" {
		id = run.ID
	}
	if id == "" {
		id = newAutomationID("run")
	}
	run.ID = id
	s.runs[id] = run
	if err := s.saveLocked(); err != nil {
		return automationRun{}, err
	}
	return run, nil
}

func (s *automationState) beginRun(jobID string) bool {
	if s == nil {
		return false
	}
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	if _, exists := s.activeJobs[jobID]; exists {
		return false
	}
	s.activeJobs[jobID] = struct{}{}
	return true
}

func (s *automationState) endRun(jobID string) {
	if s == nil {
		return
	}
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	delete(s.activeJobs, jobID)
}

func (a *API) RegisterAutomationRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v2/automation/scripts", a.handleListAutomationScripts)
	mux.HandleFunc("POST /api/v2/automation/scripts", a.handleCreateAutomationScript)
	mux.HandleFunc("GET /api/v2/automation/scripts/{id}", a.handleGetAutomationScript)
	mux.HandleFunc("PUT /api/v2/automation/scripts/{id}", a.handleUpdateAutomationScript)
	mux.HandleFunc("DELETE /api/v2/automation/scripts/{id}", a.handleDeleteAutomationScript)
	mux.HandleFunc("GET /api/v2/automation/jobs", a.handleListAutomationJobs)
	mux.HandleFunc("POST /api/v2/automation/jobs", a.handleCreateAutomationJob)
	mux.HandleFunc("GET /api/v2/automation/jobs/{id}", a.handleGetAutomationJob)
	mux.HandleFunc("PUT /api/v2/automation/jobs/{id}", a.handleUpdateAutomationJob)
	mux.HandleFunc("DELETE /api/v2/automation/jobs/{id}", a.handleDeleteAutomationJob)
	mux.HandleFunc("POST /api/v2/automation/jobs/{id}/run", a.handleRunAutomationJob)
	mux.HandleFunc("POST /api/v2/automation/jobs/{id}/trigger", a.handleTriggerAutomationJob)
	mux.HandleFunc("GET /api/v2/automation/runs", a.handleListAutomationRuns)
	mux.HandleFunc("GET /api/v2/automation/runs/{id}", a.handleGetAutomationRun)
}

func (a *API) StartAutomationScheduler(ctx context.Context, interval time.Duration) {
	if a == nil || a.automation == nil {
		return
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	a.automation.schedulerOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				a.runDueAutomationJobs(ctx)
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	})
}

func (a *API) requireAutomation(w http.ResponseWriter) bool {
	if a == nil || a.automation == nil {
		writeError(w, http.StatusServiceUnavailable, "automation is not enabled")
		return false
	}
	return true
}

func (a *API) handleListAutomationScripts(w http.ResponseWriter, r *http.Request) {
	if !a.requireAutomation(w) {
		return
	}
	items := a.automation.scripts.list()
	page, perPage := parsePagination(r)
	total := len(items)
	start, end := paginate(total, page, perPage)
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    items[start:end],
		Total:   total,
		Page:    page,
		PerPage: perPage,
	})
}

func (a *API) handleCreateAutomationScript(w http.ResponseWriter, r *http.Request) {
	if !a.requireAutomation(w) {
		return
	}
	var req automationScript
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if strings.TrimSpace(req.Body) == "" {
		writeError(w, http.StatusBadRequest, "body is required")
		return
	}
	user := strings.TrimSpace(r.Header.Get("X-User"))
	if user == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	now := time.Now().UTC()
	req.Name = strings.TrimSpace(req.Name)
	req.Description = strings.TrimSpace(req.Description)
	req.Shell = normalizeAutomationShell(req.Shell)
	req.CreatedAt = now
	req.UpdatedAt = now
	req.CreatedBy = user
	req.UpdatedBy = user
	created, err := a.automation.scripts.create(req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, APIResponse{
		Success: true,
		Data:    created,
	})
}

func (a *API) handleGetAutomationScript(w http.ResponseWriter, r *http.Request) {
	if !a.requireAutomation(w) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing script id")
		return
	}
	script, ok := a.automation.scripts.get(id)
	if !ok {
		writeError(w, http.StatusNotFound, errAutomationScriptNotFound.Error())
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    script,
	})
}

func (a *API) handleUpdateAutomationScript(w http.ResponseWriter, r *http.Request) {
	if !a.requireAutomation(w) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing script id")
		return
	}
	current, ok := a.automation.scripts.get(id)
	if !ok {
		writeError(w, http.StatusNotFound, errAutomationScriptNotFound.Error())
		return
	}
	var req automationScript
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if strings.TrimSpace(req.Body) == "" {
		writeError(w, http.StatusBadRequest, "body is required")
		return
	}
	user := strings.TrimSpace(r.Header.Get("X-User"))
	if user == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	current.Name = strings.TrimSpace(req.Name)
	current.Description = strings.TrimSpace(req.Description)
	current.Shell = normalizeAutomationShell(req.Shell)
	current.Body = req.Body
	current.UpdatedAt = time.Now().UTC()
	current.UpdatedBy = user
	updated, err := a.automation.scripts.update(id, current)
	if err != nil {
		if errors.Is(err, errAutomationScriptNotFound) {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    updated,
	})
}

func (a *API) handleDeleteAutomationScript(w http.ResponseWriter, r *http.Request) {
	if !a.requireAutomation(w) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing script id")
		return
	}
	for _, job := range a.automation.jobs.list() {
		if job.ScriptID == id {
			writeError(w, http.StatusConflict, "automation script is still referenced by a job")
			return
		}
	}
	if err := a.automation.scripts.delete(id); err != nil {
		if errors.Is(err, errAutomationScriptNotFound) {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"status": "deleted"},
	})
}

func (a *API) handleListAutomationJobs(w http.ResponseWriter, r *http.Request) {
	if !a.requireAutomation(w) {
		return
	}
	enabledFilter := strings.TrimSpace(r.URL.Query().Get("enabled"))
	providerFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("provider")))
	items := make([]automationJob, 0)
	for _, job := range a.automation.jobs.list() {
		if enabledFilter != "" {
			switch enabledFilter {
			case "true":
				if !job.Enabled {
					continue
				}
			case "false":
				if job.Enabled {
					continue
				}
			}
		}
		if providerFilter != "" && !automationProvidersAllow(job.TriggerProviders, providerFilter) {
			continue
		}
		items = append(items, job)
	}
	page, perPage := parsePagination(r)
	total := len(items)
	start, end := paginate(total, page, perPage)
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    items[start:end],
		Total:   total,
		Page:    page,
		PerPage: perPage,
	})
}

func (a *API) handleCreateAutomationJob(w http.ResponseWriter, r *http.Request) {
	if !a.requireAutomation(w) {
		return
	}
	currentUser := strings.TrimSpace(r.Header.Get("X-User"))
	if currentUser == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	job, status, err := a.decodeAutomationJobRequest(r, automationJob{}, currentUser)
	if err != nil {
		writeError(w, status, err.Error())
		return
	}
	created, err := a.automation.jobs.create(job)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, APIResponse{
		Success: true,
		Data:    created,
	})
}

func (a *API) handleGetAutomationJob(w http.ResponseWriter, r *http.Request) {
	if !a.requireAutomation(w) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing job id")
		return
	}
	job, ok := a.automation.jobs.get(id)
	if !ok {
		writeError(w, http.StatusNotFound, errAutomationJobNotFound.Error())
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    job,
	})
}

func (a *API) handleUpdateAutomationJob(w http.ResponseWriter, r *http.Request) {
	if !a.requireAutomation(w) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing job id")
		return
	}
	current, ok := a.automation.jobs.get(id)
	if !ok {
		writeError(w, http.StatusNotFound, errAutomationJobNotFound.Error())
		return
	}
	currentUser := strings.TrimSpace(r.Header.Get("X-User"))
	if currentUser == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	job, status, err := a.decodeAutomationJobRequest(r, current, currentUser)
	if err != nil {
		writeError(w, status, err.Error())
		return
	}
	updated, err := a.automation.jobs.update(id, job)
	if err != nil {
		if errors.Is(err, errAutomationJobNotFound) {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    updated,
	})
}

func (a *API) handleDeleteAutomationJob(w http.ResponseWriter, r *http.Request) {
	if !a.requireAutomation(w) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing job id")
		return
	}
	if err := a.automation.jobs.delete(id); err != nil {
		if errors.Is(err, errAutomationJobNotFound) {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"status": "deleted"},
	})
}

func (a *API) handleRunAutomationJob(w http.ResponseWriter, r *http.Request) {
	if !a.requireAutomation(w) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing job id")
		return
	}
	job, ok := a.automation.jobs.get(id)
	if !ok {
		writeError(w, http.StatusNotFound, errAutomationJobNotFound.Error())
		return
	}
	requestedBy := strings.TrimSpace(r.Header.Get("X-User"))
	if requestedBy == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req struct {
		Trigger     string            `json:"trigger,omitempty"`
		Environment map[string]string `json:"environment,omitempty"`
	}
	if r.ContentLength > 0 {
		if err := readJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	trigger := strings.TrimSpace(req.Trigger)
	if trigger == "" {
		trigger = "manual"
	}
	run, err := a.executeAutomationJob(r.Context(), job, trigger, requestedBy, req.Environment)
	if err != nil {
		switch {
		case errors.Is(err, errAutomationJobBusy):
			writeError(w, http.StatusConflict, err.Error())
		default:
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    run,
	})
}

func (a *API) handleTriggerAutomationJob(w http.ResponseWriter, r *http.Request) {
	if !a.requireAutomation(w) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing job id")
		return
	}
	job, ok := a.automation.jobs.get(id)
	if !ok {
		writeError(w, http.StatusNotFound, errAutomationJobNotFound.Error())
		return
	}
	requestedBy := strings.TrimSpace(r.Header.Get("X-User"))
	if requestedBy == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req struct {
		Provider    string            `json:"provider"`
		Ref         string            `json:"ref,omitempty"`
		Workflow    string            `json:"workflow,omitempty"`
		PipelineID  string            `json:"pipeline_id,omitempty"`
		Environment map[string]string `json:"environment,omitempty"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	if provider == "" {
		writeError(w, http.StatusBadRequest, "provider is required")
		return
	}
	if !automationProvidersAllow(job.TriggerProviders, provider) {
		writeError(w, http.StatusForbidden, "provider is not allowed for this automation job")
		return
	}
	trigger := provider
	if value := strings.TrimSpace(req.Workflow); value != "" {
		trigger += ":" + value
	}
	if value := strings.TrimSpace(req.Ref); value != "" {
		trigger += "@" + value
	}
	if value := strings.TrimSpace(req.PipelineID); value != "" {
		trigger += "#" + value
	}
	run, err := a.executeAutomationJob(r.Context(), job, trigger, requestedBy, req.Environment)
	if err != nil {
		switch {
		case errors.Is(err, errAutomationJobBusy):
			writeError(w, http.StatusConflict, err.Error())
		default:
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusAccepted, APIResponse{
		Success: true,
		Data:    run,
	})
}

func (a *API) handleListAutomationRuns(w http.ResponseWriter, r *http.Request) {
	if !a.requireAutomation(w) {
		return
	}
	jobFilter := strings.TrimSpace(r.URL.Query().Get("job_id"))
	statusFilter := strings.TrimSpace(r.URL.Query().Get("status"))
	items := make([]automationRun, 0)
	for _, run := range a.automation.runs.list() {
		if jobFilter != "" && run.JobID != jobFilter {
			continue
		}
		if statusFilter != "" && run.Status != statusFilter {
			continue
		}
		items = append(items, run)
	}
	page, perPage := parsePagination(r)
	total := len(items)
	start, end := paginate(total, page, perPage)
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    items[start:end],
		Total:   total,
		Page:    page,
		PerPage: perPage,
	})
}

func (a *API) handleGetAutomationRun(w http.ResponseWriter, r *http.Request) {
	if !a.requireAutomation(w) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing run id")
		return
	}
	run, ok := a.automation.runs.get(id)
	if !ok {
		writeError(w, http.StatusNotFound, errAutomationRunNotFound.Error())
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    run,
	})
}

func (a *API) decodeAutomationJobRequest(r *http.Request, current automationJob, currentUser string) (automationJob, int, error) {
	var req automationJob
	if err := readJSON(r, &req); err != nil {
		return automationJob{}, http.StatusBadRequest, err
	}
	normalized, err := normalizeAutomationJob(req)
	if err != nil {
		return automationJob{}, http.StatusBadRequest, err
	}
	if normalized.ScriptID != "" {
		if _, ok := a.automation.scripts.get(normalized.ScriptID); !ok {
			return automationJob{}, http.StatusBadRequest, fmt.Errorf("automation script %q not found", normalized.ScriptID)
		}
	}
	if _, err := a.resolveAutomationTargets(normalized); err != nil {
		return automationJob{}, http.StatusBadRequest, err
	}
	now := time.Now().UTC()
	if current.ID == "" {
		normalized.CreatedAt = now
		normalized.CreatedBy = currentUser
	} else {
		normalized.ID = current.ID
		normalized.CreatedAt = current.CreatedAt
		normalized.CreatedBy = current.CreatedBy
		normalized.LastRunAt = current.LastRunAt
		normalized.LastStatus = current.LastStatus
		normalized.LastSummary = current.LastSummary
		normalized.LastError = current.LastError
	}
	normalized.UpdatedAt = now
	normalized.UpdatedBy = currentUser
	normalized.NextRunAt = automationNextRun(now, normalized.Schedule, normalized.Enabled)
	return normalized, http.StatusOK, nil
}

func normalizeAutomationJob(job automationJob) (automationJob, error) {
	job.Name = strings.TrimSpace(job.Name)
	job.Description = strings.TrimSpace(job.Description)
	job.Command = strings.TrimSpace(job.Command)
	job.ScriptID = strings.TrimSpace(job.ScriptID)
	job.Schedule = strings.TrimSpace(job.Schedule)
	job.Timeout = strings.TrimSpace(job.Timeout)
	job.Username = strings.TrimSpace(job.Username)
	job.Password = strings.TrimSpace(job.Password)
	job.PrivateKey = strings.TrimSpace(job.PrivateKey)
	job.Passphrase = strings.TrimSpace(job.Passphrase)
	job.KnownHostsPath = strings.TrimSpace(job.KnownHostsPath)
	if job.Name == "" {
		return automationJob{}, fmt.Errorf("name is required")
	}
	if (job.Command == "" && job.ScriptID == "") || (job.Command != "" && job.ScriptID != "") {
		return automationJob{}, fmt.Errorf("exactly one of command or script_id is required")
	}
	if len(job.ServerIDs) == 0 && len(job.Targets) == 0 {
		return automationJob{}, fmt.Errorf("at least one server_id or target is required")
	}
	if job.Schedule != "" {
		duration, err := time.ParseDuration(job.Schedule)
		if err != nil || duration <= 0 {
			return automationJob{}, fmt.Errorf("schedule must be a positive Go duration")
		}
	}
	if job.Timeout != "" {
		duration, err := time.ParseDuration(job.Timeout)
		if err != nil || duration <= 0 {
			return automationJob{}, fmt.Errorf("timeout must be a positive Go duration")
		}
	}
	job.ServerIDs = normalizeAutomationStringList(job.ServerIDs)
	job.TriggerProviders = normalizeAutomationStringList(job.TriggerProviders)
	if job.Environment == nil {
		job.Environment = map[string]string{}
	}
	job.Environment = normalizeAutomationEnvironment(job.Environment)
	if len(job.ServerIDs) > 0 && strings.TrimSpace(job.Username) == "" {
		return automationJob{}, fmt.Errorf("username is required when server_ids are used")
	}
	if len(job.ServerIDs) > 0 && strings.TrimSpace(job.Password) == "" && strings.TrimSpace(job.PrivateKey) == "" {
		return automationJob{}, fmt.Errorf("password or private_key is required when server_ids are used")
	}
	for index := range job.Targets {
		target := &job.Targets[index]
		target.ID = strings.TrimSpace(target.ID)
		target.Name = strings.TrimSpace(target.Name)
		target.Host = strings.TrimSpace(target.Host)
		target.Username = strings.TrimSpace(target.Username)
		target.Password = strings.TrimSpace(target.Password)
		target.PrivateKey = strings.TrimSpace(target.PrivateKey)
		target.Passphrase = strings.TrimSpace(target.Passphrase)
		target.KnownHostsPath = strings.TrimSpace(target.KnownHostsPath)
		if target.Port <= 0 {
			target.Port = 22
		}
		if target.Name == "" {
			target.Name = target.Host
		}
		if target.Host == "" {
			return automationJob{}, fmt.Errorf("target host is required")
		}
		target.Environment = normalizeAutomationEnvironment(target.Environment)
		if target.Username == "" {
			target.Username = job.Username
		}
		if target.Password == "" {
			target.Password = job.Password
		}
		if target.PrivateKey == "" {
			target.PrivateKey = job.PrivateKey
		}
		if target.Passphrase == "" {
			target.Passphrase = job.Passphrase
		}
		if target.KnownHostsPath == "" {
			target.KnownHostsPath = job.KnownHostsPath
		}
		if !target.InsecureSkipHostKeyVerify {
			target.InsecureSkipHostKeyVerify = job.InsecureSkipHostKeyVerify
		}
		if target.Username == "" {
			return automationJob{}, fmt.Errorf("target username is required")
		}
		if target.Password == "" && target.PrivateKey == "" {
			return automationJob{}, fmt.Errorf("target password or private_key is required")
		}
		if target.KnownHostsPath == "" && !target.InsecureSkipHostKeyVerify {
			return automationJob{}, fmt.Errorf("known_hosts_path or insecure_skip_host_key_verify=true is required for target %s", target.Host)
		}
	}
	for index := range job.JumpChain {
		hop := &job.JumpChain[index]
		hop.Name = strings.TrimSpace(hop.Name)
		hop.Host = strings.TrimSpace(hop.Host)
		hop.Username = strings.TrimSpace(hop.Username)
		hop.Password = strings.TrimSpace(hop.Password)
		hop.PrivateKey = strings.TrimSpace(hop.PrivateKey)
		hop.Passphrase = strings.TrimSpace(hop.Passphrase)
		if hop.Port <= 0 {
			hop.Port = 22
		}
		if hop.Host == "" {
			return automationJob{}, fmt.Errorf("jump_chain host is required")
		}
		if hop.Username == "" {
			return automationJob{}, fmt.Errorf("jump_chain username is required")
		}
		if hop.Password == "" && hop.PrivateKey == "" {
			return automationJob{}, fmt.Errorf("jump_chain password or private_key is required")
		}
	}
	if job.KnownHostsPath == "" && !job.InsecureSkipHostKeyVerify {
		hasTargetOverride := false
		for _, target := range job.Targets {
			if target.KnownHostsPath != "" || target.InsecureSkipHostKeyVerify {
				hasTargetOverride = true
				break
			}
		}
		if !hasTargetOverride {
			return automationJob{}, fmt.Errorf("known_hosts_path or insecure_skip_host_key_verify=true is required")
		}
	}
	return job, nil
}

func normalizeAutomationEnvironment(values map[string]string) map[string]string {
	if len(values) == 0 {
		return map[string]string{}
	}
	normalized := make(map[string]string, len(values))
	for key, value := range values {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		normalized[key] = value
	}
	return normalized
}

func normalizeAutomationStringList(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, item := range values {
		value := strings.ToLower(strings.TrimSpace(item))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	return normalized
}

func normalizeAutomationShell(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "/bin/sh"
	}
	return raw
}

func automationNextRun(now time.Time, schedule string, enabled bool) time.Time {
	if !enabled {
		return time.Time{}
	}
	duration, err := time.ParseDuration(strings.TrimSpace(schedule))
	if err != nil || duration <= 0 {
		return time.Time{}
	}
	return now.Add(duration)
}

func automationProvidersAllow(allowed []string, provider string) bool {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		return false
	}
	if len(allowed) == 0 {
		return true
	}
	for _, item := range allowed {
		if item == provider {
			return true
		}
	}
	return false
}

func (a *API) resolveAutomationTargets(job automationJob) ([]automationResolvedTarget, error) {
	targets := make([]automationResolvedTarget, 0, len(job.Targets)+len(job.ServerIDs))
	for _, target := range job.Targets {
		resolved := automationResolvedTarget{
			ID:                        target.ID,
			Name:                      target.Name,
			Host:                      target.Host,
			Port:                      target.Port,
			Username:                  target.Username,
			Password:                  target.Password,
			PrivateKey:                target.PrivateKey,
			Passphrase:                target.Passphrase,
			KnownHostsPath:            target.KnownHostsPath,
			InsecureSkipHostKeyVerify: target.InsecureSkipHostKeyVerify,
			Environment:               cloneAutomationMap(target.Environment),
			JumpChain:                 cloneAutomationJumpChain(job.JumpChain),
		}
		if resolved.Port <= 0 {
			resolved.Port = 22
		}
		if resolved.Name == "" {
			resolved.Name = resolved.Host
		}
		if err := validateResolvedAutomationTarget(resolved); err != nil {
			return nil, err
		}
		targets = append(targets, resolved)
	}
	if len(job.ServerIDs) == 0 {
		return targets, nil
	}
	managedServers, err := a.listManagedServers()
	if err != nil {
		return nil, fmt.Errorf("resolve managed servers: %w", err)
	}
	byID := make(map[string]models.Server, len(managedServers))
	for _, server := range managedServers {
		byID[strings.ToLower(server.ID)] = server
	}
	for _, id := range job.ServerIDs {
		server, ok := byID[strings.ToLower(id)]
		if !ok {
			return nil, fmt.Errorf("managed server %q was not found", id)
		}
		resolved := automationResolvedTarget{
			ID:                        server.ID,
			Name:                      firstAutomationValue(server.Name, server.Host),
			Host:                      server.Host,
			Port:                      server.Port,
			Username:                  job.Username,
			Password:                  job.Password,
			PrivateKey:                job.PrivateKey,
			Passphrase:                job.Passphrase,
			KnownHostsPath:            job.KnownHostsPath,
			InsecureSkipHostKeyVerify: job.InsecureSkipHostKeyVerify,
			Environment:               map[string]string{},
			JumpChain:                 cloneAutomationJumpChain(job.JumpChain),
		}
		if resolved.Port <= 0 {
			resolved.Port = 22
		}
		if err := validateResolvedAutomationTarget(resolved); err != nil {
			return nil, err
		}
		targets = append(targets, resolved)
	}
	return targets, nil
}

func validateResolvedAutomationTarget(target automationResolvedTarget) error {
	if strings.TrimSpace(target.Host) == "" {
		return fmt.Errorf("target host is required")
	}
	if target.Port <= 0 {
		return fmt.Errorf("target port is required for %s", target.Host)
	}
	if strings.TrimSpace(target.Username) == "" {
		return fmt.Errorf("target username is required for %s", target.Host)
	}
	if strings.TrimSpace(target.Password) == "" && strings.TrimSpace(target.PrivateKey) == "" {
		return fmt.Errorf("target password or private_key is required for %s", target.Host)
	}
	if strings.TrimSpace(target.KnownHostsPath) == "" && !target.InsecureSkipHostKeyVerify {
		return fmt.Errorf("known_hosts_path or insecure_skip_host_key_verify=true is required for %s", target.Host)
	}
	return nil
}

func cloneAutomationJumpChain(items []automationHop) []automationHop {
	if len(items) == 0 {
		return []automationHop{}
	}
	out := make([]automationHop, len(items))
	copy(out, items)
	return out
}

func cloneAutomationMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func firstAutomationValue(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func (a *API) runDueAutomationJobs(ctx context.Context) {
	if a == nil || a.automation == nil {
		return
	}
	now := time.Now().UTC()
	for _, job := range a.automation.jobs.list() {
		if !job.Enabled {
			continue
		}
		if strings.TrimSpace(job.Schedule) == "" {
			continue
		}
		if !job.NextRunAt.IsZero() && job.NextRunAt.After(now) {
			continue
		}
		if !a.automation.beginRun(job.ID) {
			continue
		}
		go func(runJob automationJob) {
			defer a.automation.endRun(runJob.ID)
			if _, err := a.executeAutomationJobLocked(ctx, runJob, "scheduler", "system", nil); err != nil {
				log.Printf("automation: scheduled job %s: %v", runJob.ID, err)
			}
		}(job)
	}
}

func (a *API) executeAutomationJob(ctx context.Context, job automationJob, trigger, requestedBy string, overrideEnv map[string]string) (automationRun, error) {
	if a == nil || a.automation == nil {
		return automationRun{}, errors.New("automation is not enabled")
	}
	if !a.automation.beginRun(job.ID) {
		return automationRun{}, errAutomationJobBusy
	}
	defer a.automation.endRun(job.ID)
	return a.executeAutomationJobLocked(ctx, job, trigger, requestedBy, overrideEnv)
}

func (a *API) executeAutomationJobLocked(ctx context.Context, job automationJob, trigger, requestedBy string, overrideEnv map[string]string) (automationRun, error) {
	if strings.TrimSpace(trigger) == "" {
		trigger = "manual"
	}
	var script *automationScript
	if job.ScriptID != "" {
		value, ok := a.automation.scripts.get(job.ScriptID)
		if !ok {
			return automationRun{}, fmt.Errorf("automation script %q not found", job.ScriptID)
		}
		script = &value
	}
	targets, err := a.resolveAutomationTargets(job)
	if err != nil {
		return automationRun{}, err
	}
	timeout := 30 * time.Second
	if value := strings.TrimSpace(job.Timeout); value != "" {
		timeout, err = time.ParseDuration(value)
		if err != nil {
			return automationRun{}, fmt.Errorf("parse timeout: %w", err)
		}
	}
	run := automationRun{
		ID:          newAutomationID("run"),
		JobID:       job.ID,
		JobName:     job.Name,
		Trigger:     trigger,
		RequestedBy: requestedBy,
		Status:      "running",
		StartedAt:   time.Now().UTC(),
	}
	run, err = a.automation.runs.create(run)
	if err != nil {
		return automationRun{}, err
	}
	results := make([]automationTargetResult, 0, len(targets))
	baseEnv := cloneAutomationMap(job.Environment)
	for key, value := range overrideEnv {
		baseEnv[strings.TrimSpace(key)] = value
	}
	for _, target := range targets {
		targetEnv := cloneAutomationMap(baseEnv)
		for key, value := range target.Environment {
			targetEnv[key] = value
		}
		targetCtx, cancel := context.WithTimeout(ctx, timeout)
		result := a.automation.executor.Execute(targetCtx, automationExecutionRequest{
			Command:     job.Command,
			Environment: targetEnv,
			Script:      script,
			Target:      target,
		})
		cancel()
		results = append(results, result)
	}
	run.Results = results
	run.FinishedAt = time.Now().UTC()
	run.Status, run.Summary, run.Results = summarizeAutomationRun(results)
	if _, err := a.automation.runs.update(run.ID, run); err != nil {
		return automationRun{}, err
	}
	_, patchErr := a.automation.jobs.patch(job.ID, func(item *automationJob) error {
		item.LastRunAt = run.FinishedAt
		item.LastStatus = run.Status
		item.LastSummary = run.Summary
		item.LastError = automationRunLastError(results)
		item.UpdatedAt = time.Now().UTC()
		if requestedBy != "" {
			item.UpdatedBy = requestedBy
		}
		item.NextRunAt = automationNextRun(run.FinishedAt, item.Schedule, item.Enabled)
		return nil
	})
	if patchErr != nil {
		return automationRun{}, patchErr
	}
	if err := a.recordAutomationRunAudit(job, run, requestedBy); err != nil {
		log.Printf("automation: append audit event for job %s: %v", job.ID, err)
	}
	return run, nil
}

func summarizeAutomationRun(results []automationTargetResult) (string, string, []automationTargetResult) {
	if len(results) == 0 {
		return "failed", "no targets were executed", []automationTargetResult{}
	}
	successCount := 0
	failedCount := 0
	for index := range results {
		if results[index].FinishedAt.IsZero() {
			results[index].FinishedAt = time.Now().UTC()
		}
		switch results[index].Status {
		case "completed":
			successCount++
		default:
			failedCount++
		}
	}
	status := "completed"
	switch {
	case successCount == 0:
		status = "failed"
	case failedCount > 0:
		status = "partial"
	}
	summary := fmt.Sprintf("%d target(s) succeeded, %d target(s) failed", successCount, failedCount)
	return status, summary, results
}

func automationRunLastError(results []automationTargetResult) string {
	for _, result := range results {
		if strings.TrimSpace(result.Error) != "" {
			return result.Error
		}
	}
	return ""
}

func (a *API) recordAutomationRunAudit(job automationJob, run automationRun, requestedBy string) error {
	if a == nil || a.config == nil || strings.TrimSpace(a.config.AuditLogDir) == "" {
		return nil
	}
	event := models.AuditEvent{
		ID:         newAuditEventID("automation"),
		Timestamp:  run.FinishedAt,
		EventType:  "automation.job_run",
		Username:   firstAutomationValue(requestedBy, run.RequestedBy, "system"),
		TargetHost: job.Name,
		Details:    fmt.Sprintf("job_id=%s trigger=%s status=%s summary=%q", job.ID, run.Trigger, run.Status, run.Summary),
	}
	return a.appendControlPlaneAuditEvent(event)
}

func newAutomationID(prefix string) string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UTC().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(buf[:])
}
