package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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

func newUserStore(path string) *userStore {
	us := &userStore{
		users: make(map[string]models.User),
		path:  path,
	}
	us.load()
	return us
}

func (us *userStore) load() {
	data, err := os.ReadFile(us.path)
	if err != nil {
		return
	}
	var file UserFile
	if err := json.Unmarshal(data, &file); err != nil {
		return
	}
	us.mu.Lock()
	defer us.mu.Unlock()
	for _, rec := range file.Users {
		u := rec.User
		u.PassHash = rec.PassHash
		u.MFASecret = rec.MFASecret
		us.users[u.Username] = u
	}
}

func (us *userStore) save() error {
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

// handleListUsers returns all users.
func (a *API) handleListUsers(w http.ResponseWriter, r *http.Request) {
	a.users.mu.RLock()
	users := make([]models.User, 0, len(a.users.users))
	for _, u := range a.users.users {
		users = append(users, u)
	}
	a.users.mu.RUnlock()

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

	a.users.mu.Lock()
	if _, exists := a.users.users[req.Username]; exists {
		a.users.mu.Unlock()
		writeError(w, http.StatusConflict, "user already exists")
		return
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
	a.users.users[req.Username] = u
	a.users.mu.Unlock()

	if err := a.users.save(); err != nil {
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

	a.users.mu.RLock()
	u, ok := a.users.users[username]
	a.users.mu.RUnlock()

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

	a.users.mu.Lock()
	u, ok := a.users.users[username]
	if !ok {
		a.users.mu.Unlock()
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

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
	a.users.users[username] = u
	a.users.mu.Unlock()

	if err := a.users.save(); err != nil {
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

	a.users.mu.Lock()
	if _, ok := a.users.users[username]; !ok {
		a.users.mu.Unlock()
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	delete(a.users.users, username)
	a.users.mu.Unlock()

	if err := a.users.save(); err != nil {
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

	a.users.mu.Lock()
	u, ok := a.users.users[username]
	if !ok {
		a.users.mu.Unlock()
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	u.PassHash = hashPassword(req.NewPassword)
	u.UpdatedAt = time.Now().UTC()
	a.users.users[username] = u
	a.users.mu.Unlock()

	if err := a.users.save(); err != nil {
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

	a.users.mu.Lock()
	u, ok := a.users.users[username]
	if !ok {
		a.users.mu.Unlock()
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	u.MFAEnabled = req.Enabled
	if req.Enabled && u.MFASecret == "" {
		secret, err := generateTOTPSecret()
		if err != nil {
			a.users.mu.Unlock()
			writeError(w, http.StatusInternalServerError, "failed to generate MFA secret")
			return
		}
		u.MFASecret = secret
	}
	if !req.Enabled {
		u.MFASecret = ""
	}
	u.UpdatedAt = time.Now().UTC()
	a.users.users[username] = u
	a.users.mu.Unlock()

	if err := a.users.save(); err != nil {
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

	a.users.mu.RLock()
	u, ok := a.users.users[username]
	a.users.mu.RUnlock()

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
