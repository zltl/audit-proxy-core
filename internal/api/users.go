package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

// UserFile is the serializable format for the user store JSON file.
type UserFile struct {
	Users []UserRecord `json:"users"`
}

// UserRecord extends the model with fields needed for persistence.
type UserRecord struct {
	models.User
	PassHash  string `json:"pass_hash"`
	MFASecret string `json:"mfa_secret,omitempty"`
}

var (
	errUserExists   = errors.New("user already exists")
	errUserNotFound = errors.New("user not found")
	errMFAGenerate  = errors.New("generate mfa secret")
)

func newUserStore(path string, sqlStore *sqlStorage, usePostgres bool) (*userStore, error) {
	us := &userStore{
		users:       make(map[string]models.User),
		path:        path,
		sqlStore:    sqlStore,
		usePostgres: usePostgres,
	}
	if usePostgres {
		if err := us.bootstrapPostgres(); err != nil {
			return nil, err
		}
		return us, nil
	}
	us.load()
	return us, nil
}

func (us *userStore) load() {
	records, err := readUserFile(us.path)
	if err != nil {
		return
	}
	us.mu.Lock()
	defer us.mu.Unlock()
	for _, rec := range records {
		u := rec.User
		u.PassHash = rec.PassHash
		u.MFASecret = rec.MFASecret
		us.users[u.Username] = u
	}
}

func (us *userStore) save() error {
	if us == nil || us.usePostgres {
		return nil
	}
	us.mu.RLock()
	defer us.mu.RUnlock()
	var file UserFile
	for _, u := range us.users {
		file.Users = append(file.Users, UserRecord{
			User:      u,
			PassHash:  u.PassHash,
			MFASecret: u.MFASecret,
		})
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(us.path, data, 0600)
}

func readUserFile(path string) ([]UserRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file UserFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	return file.Users, nil
}

func writeUserFile(path string, users []models.User) error {
	file := UserFile{Users: make([]UserRecord, 0, len(users))}
	for _, user := range users {
		file.Users = append(file.Users, UserRecord{
			User:      user,
			PassHash:  user.PassHash,
			MFASecret: user.MFASecret,
		})
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func (us *userStore) bootstrapPostgres() error {
	if us == nil || !us.usePostgres || us.sqlStore == nil {
		return nil
	}
	count, err := us.sqlStore.CountUsers()
	if err != nil || count > 0 {
		return err
	}
	records, err := readUserFile(us.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read %s: %w", us.path, err)
	}
	for _, rec := range records {
		user := rec.User
		user.PassHash = rec.PassHash
		user.MFASecret = rec.MFASecret
		if err := us.sqlStore.CreateUser(user); err != nil && !errors.Is(err, errUserExists) {
			return err
		}
	}
	return nil
}

func (us *userStore) list() ([]models.User, error) {
	if us == nil {
		return []models.User{}, nil
	}
	if us.usePostgres {
		return us.sqlStore.ListUsers()
	}
	us.mu.RLock()
	users := make([]models.User, 0, len(us.users))
	for _, user := range us.users {
		users = append(users, user)
	}
	us.mu.RUnlock()
	sort.Slice(users, func(i, j int) bool {
		return users[i].Username < users[j].Username
	})
	return users, nil
}

func (us *userStore) count() (int, error) {
	if us == nil {
		return 0, nil
	}
	if us.usePostgres {
		return us.sqlStore.CountUsers()
	}
	us.mu.RLock()
	defer us.mu.RUnlock()
	return len(us.users), nil
}

func (us *userStore) get(username string) (models.User, bool, error) {
	if us == nil {
		return models.User{}, false, nil
	}
	if us.usePostgres {
		return us.sqlStore.GetUser(username)
	}
	us.mu.RLock()
	user, ok := us.users[username]
	us.mu.RUnlock()
	return user, ok, nil
}

func (us *userStore) create(user models.User) error {
	if us == nil {
		return nil
	}
	if us.usePostgres {
		return us.sqlStore.CreateUser(user)
	}
	us.mu.Lock()
	if _, exists := us.users[user.Username]; exists {
		us.mu.Unlock()
		return errUserExists
	}
	us.users[user.Username] = user
	us.mu.Unlock()
	return us.save()
}

func (us *userStore) update(username string, mutate func(models.User) (models.User, error)) (models.User, error) {
	if us == nil {
		return models.User{}, errUserNotFound
	}
	if us.usePostgres {
		user, ok, err := us.sqlStore.GetUser(username)
		if err != nil {
			return models.User{}, err
		}
		if !ok {
			return models.User{}, errUserNotFound
		}
		updated, err := mutate(user)
		if err != nil {
			return models.User{}, err
		}
		if err := us.sqlStore.UpdateUser(updated); err != nil {
			return models.User{}, err
		}
		return updated, nil
	}
	us.mu.Lock()
	user, ok := us.users[username]
	if !ok {
		us.mu.Unlock()
		return models.User{}, errUserNotFound
	}
	updated, err := mutate(user)
	if err != nil {
		us.mu.Unlock()
		return models.User{}, err
	}
	us.users[username] = updated
	us.mu.Unlock()
	if err := us.save(); err != nil {
		return models.User{}, err
	}
	return updated, nil
}

func (us *userStore) delete(username string) error {
	if us == nil {
		return errUserNotFound
	}
	if us.usePostgres {
		return us.sqlStore.DeleteUser(username)
	}
	us.mu.Lock()
	if _, ok := us.users[username]; !ok {
		us.mu.Unlock()
		return errUserNotFound
	}
	delete(us.users, username)
	us.mu.Unlock()
	return us.save()
}

// handleListUsers returns all users.
func (a *API) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := a.users.list()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list users: "+err.Error())
		return
	}

	page, perPage := parsePagination(r)
	total := len(users)
	start, end := paginate(total, page, perPage)

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    users[start:end],
		Total:   total,
		Page:    page,
		PerPage: perPage,
	})
}

// handleCreateUser creates a new user.
func (a *API) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    string   `json:"username"`
		DisplayName string   `json:"display_name"`
		Email       string   `json:"email"`
		Role        string   `json:"role"`
		Password    string   `json:"password"`
		AllowedIPs  []string `json:"allowed_ips"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	if req.Role == "" {
		req.Role = "viewer"
	}

	now := time.Now().UTC()
	u := models.User{
		Username:    req.Username,
		DisplayName: req.DisplayName,
		Email:       req.Email,
		Role:        req.Role,
		Enabled:     true,
		PassHash:    hashPassword(req.Password),
		CreatedAt:   now,
		UpdatedAt:   now,
		AllowedIPs:  req.AllowedIPs,
	}
	if err := a.users.create(u); err != nil {
		if errors.Is(err, errUserExists) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to save user: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, APIResponse{
		Success: true,
		Data:    u,
	})
}

// handleGetUser returns a single user by username.
func (a *API) handleGetUser(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	if username == "" {
		writeError(w, http.StatusBadRequest, "missing username")
		return
	}

	u, ok, err := a.users.get(username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load user: "+err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    u,
	})
}

// handleUpdateUser updates user fields.
func (a *API) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	if username == "" {
		writeError(w, http.StatusBadRequest, "missing username")
		return
	}

	var req struct {
		DisplayName *string  `json:"display_name"`
		Email       *string  `json:"email"`
		Role        *string  `json:"role"`
		Enabled     *bool    `json:"enabled"`
		AllowedIPs  []string `json:"allowed_ips"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	u, err := a.users.update(username, func(u models.User) (models.User, error) {
		if req.DisplayName != nil {
			u.DisplayName = *req.DisplayName
		}
		if req.Email != nil {
			u.Email = *req.Email
		}
		if req.Role != nil {
			u.Role = *req.Role
		}
		if req.Enabled != nil {
			u.Enabled = *req.Enabled
		}
		if req.AllowedIPs != nil {
			u.AllowedIPs = req.AllowedIPs
		}
		u.UpdatedAt = time.Now().UTC()
		return u, nil
	})
	if err != nil {
		if errors.Is(err, errUserNotFound) {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to save user: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    u,
	})
}

// handleDeleteUser removes a user.
func (a *API) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	if username == "" {
		writeError(w, http.StatusBadRequest, "missing username")
		return
	}

	if err := a.users.delete(username); err != nil {
		if errors.Is(err, errUserNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to save users: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"message": "user " + username + " deleted"},
	})
}

// handleChangePassword changes a user's password.
func (a *API) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	if username == "" {
		writeError(w, http.StatusBadRequest, "missing username")
		return
	}

	var req struct {
		NewPassword string `json:"new_password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "new_password is required")
		return
	}

	if len(req.NewPassword) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	if _, err := a.users.update(username, func(u models.User) (models.User, error) {
		u.PassHash = hashPassword(req.NewPassword)
		u.UpdatedAt = time.Now().UTC()
		return u, nil
	}); err != nil {
		if errors.Is(err, errUserNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to save user: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"message": "password updated"},
	})
}

// handleConfigureMFA enables or configures MFA for a user.
func (a *API) handleConfigureMFA(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	if username == "" {
		writeError(w, http.StatusBadRequest, "missing username")
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	u, err := a.users.update(username, func(u models.User) (models.User, error) {
		u.MFAEnabled = req.Enabled
		if req.Enabled && u.MFASecret == "" {
			secret, err := generateTOTPSecret()
			if err != nil {
				return models.User{}, fmt.Errorf("%w: %v", errMFAGenerate, err)
			}
			u.MFASecret = secret
		}
		if !req.Enabled {
			u.MFASecret = ""
		}
		u.UpdatedAt = time.Now().UTC()
		return u, nil
	})
	if err != nil {
		if errors.Is(err, errUserNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		if errors.Is(err, errMFAGenerate) {
			writeError(w, http.StatusInternalServerError, "failed to generate MFA secret")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to save user: "+err.Error())
		return
	}

	resp := map[string]interface{}{
		"mfa_enabled": u.MFAEnabled,
	}
	if u.MFAEnabled {
		resp["secret"] = u.MFASecret
		resp["otpauth_uri"] = fmt.Sprintf("otpauth://totp/SSHProxy:%s?secret=%s&issuer=SSHProxy", username, u.MFASecret)
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    resp,
	})
}

// handleMFAQRCode returns the MFA secret and otpauth URI for QR code generation.
func (a *API) handleMFAQRCode(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	if username == "" {
		writeError(w, http.StatusBadRequest, "missing username")
		return
	}

	u, ok, err := a.users.get(username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load user: "+err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	if !u.MFAEnabled || u.MFASecret == "" {
		writeError(w, http.StatusBadRequest, "MFA is not enabled for this user")
		return
	}

	otpauthURI := fmt.Sprintf("otpauth://totp/SSHProxy:%s?secret=%s&issuer=SSHProxy", username, u.MFASecret)

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]string{
			"secret":      u.MFASecret,
			"otpauth_uri": otpauthURI,
		},
	})
}

// generateTOTPSecret creates a random base32-encoded TOTP secret.
func generateTOTPSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// hashPassword creates a simple HMAC-SHA1 hash for the password.
// In production, use bcrypt — but we avoid external dependencies here.
func hashPassword(password string) string {
	mac := hmac.New(sha1.New, []byte("ssh-proxy-salt"))
	mac.Write([]byte(password))
	return fmt.Sprintf("%x", mac.Sum(nil))
}

// checkPassword verifies a password against its hash.
func checkPassword(password, hash string) bool {
	return strings.EqualFold(hashPassword(password), hash)
}
