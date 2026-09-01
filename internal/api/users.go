package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/authn"
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
	errUserExists     = errors.New("user already exists")
	errUserNotFound   = errors.New("user not found")
	errMFAGenerate    = errors.New("generate mfa secret")
	errMFANotPending  = errors.New("no pending mfa enrolment")
	errMFACodeInvalid = errors.New("invalid mfa code")
	errUnknownRole    = errors.New("unknown role")
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

// LookupUser resolves a stored user record. It is used by the login handler to
// authenticate against real accounts and to read their configured role, rather
// than assuming one.
func (a *API) LookupUser(username string) (models.User, bool, error) {
	if a == nil || a.users == nil {
		return models.User{}, false, nil
	}
	return a.users.get(username)
}

// UpgradeUserPasswordHash re-hashes a verified password under the current
// scheme. Callers must only invoke it after the password has been checked.
func (a *API) UpgradeUserPasswordHash(username, password string) error {
	if a == nil || a.users == nil {
		return nil
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	_, err = a.users.update(username, func(u models.User) (models.User, error) {
		u.PassHash = hash
		u.UpdatedAt = time.Now().UTC()
		return u, nil
	})
	return err
}

// CreateUser inserts a user record directly. PassHash must already be hashed by
// the caller; it is used by provisioning and import paths that hold credentials
// in their stored form rather than in plaintext.
func (a *API) CreateUser(user models.User) error {
	if a == nil || a.users == nil {
		return nil
	}
	if !isKnownRole(user.Role) {
		return errUnknownRole
	}
	now := time.Now().UTC()
	if user.CreatedAt.IsZero() {
		user.CreatedAt = now
	}
	user.UpdatedAt = now
	return a.users.create(user)
}

// RecordUserLogin stamps a successful authentication on the account.
func (a *API) RecordUserLogin(username string) error {
	if a == nil || a.users == nil {
		return nil
	}
	_, err := a.users.update(username, func(u models.User) (models.User, error) {
		u.LastLogin = time.Now().UTC()
		return u, nil
	})
	return err
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

	if !isKnownRole(req.Role) {
		writeError(w, http.StatusBadRequest, "role must be one of: admin, operator, viewer")
		return
	}

	if err := validatePasswordStrength(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	passHash, err := hashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	now := time.Now().UTC()
	u := models.User{
		Username:    req.Username,
		DisplayName: req.DisplayName,
		Email:       req.Email,
		Role:        req.Role,
		Enabled:     true,
		PassHash:    passHash,
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
			if !isKnownRole(*req.Role) {
				return models.User{}, errUnknownRole
			}
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
		if errors.Is(err, errUnknownRole) {
			writeError(w, http.StatusBadRequest, err.Error())
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

	if err := validatePasswordStrength(req.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	passHash, err := hashPassword(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	if _, err := a.users.update(username, func(u models.User) (models.User, error) {
		u.PassHash = passHash
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

// handleConfigureMFA starts or cancels TOTP enrolment for a user.
//
// Enabling issues a secret and puts the account in the pending state; the
// secret only becomes a second factor once handleVerifyMFA proves the user can
// generate codes from it. This is also the only moment the secret is readable
// through the API — afterwards it is write-only, so a stolen admin session
// cannot lift an existing user's TOTP seed.
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

	var issuedSecret string
	u, err := a.users.update(username, func(u models.User) (models.User, error) {
		if req.Enabled {
			secret, err := generateTOTPSecret()
			if err != nil {
				return models.User{}, fmt.Errorf("%w: %v", errMFAGenerate, err)
			}
			issuedSecret = secret
			u.MFASecret = secret
			u.MFAPending = true
			u.MFAEnabled = false
		} else {
			u.MFASecret = ""
			u.MFAPending = false
			u.MFAEnabled = false
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
		"mfa_pending": u.MFAPending,
	}
	if issuedSecret != "" {
		resp["secret"] = issuedSecret
		resp["otpauth_uri"] = totpProvisioningURI(username, issuedSecret)
		resp["message"] = "scan the secret, then POST a current code to /mfa/verify to activate"
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    resp,
	})
}

// handleVerifyMFA completes enrolment by checking a code from the pending secret.
func (a *API) handleVerifyMFA(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	if username == "" {
		writeError(w, http.StatusBadRequest, "missing username")
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Code) == "" {
		writeError(w, http.StatusBadRequest, "code is required")
		return
	}

	u, err := a.users.update(username, func(u models.User) (models.User, error) {
		if !u.MFAPending || u.MFASecret == "" {
			return models.User{}, errMFANotPending
		}
		if !authn.ValidateTOTP(u.MFASecret, req.Code, totpConfig()) {
			return models.User{}, errMFACodeInvalid
		}
		u.MFAPending = false
		u.MFAEnabled = true
		u.UpdatedAt = time.Now().UTC()
		return u, nil
	})
	if err != nil {
		switch {
		case errors.Is(err, errUserNotFound):
			writeError(w, http.StatusNotFound, "user not found")
		case errors.Is(err, errMFANotPending):
			writeError(w, http.StatusBadRequest, "no pending MFA enrolment for this user")
		case errors.Is(err, errMFACodeInvalid):
			writeError(w, http.StatusUnauthorized, "invalid MFA code")
		default:
			writeError(w, http.StatusInternalServerError, "failed to save user: "+err.Error())
		}
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"mfa_enabled": u.MFAEnabled,
			"mfa_pending": u.MFAPending,
		},
	})
}

// handleMFAQRCode returns the enrolment secret while it is still pending.
// Once the enrolment is confirmed the secret is never disclosed again.
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

	if !u.MFAPending || u.MFASecret == "" {
		writeError(w, http.StatusConflict, "no pending MFA enrolment; restart enrolment to obtain a new secret")
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]string{
			"secret":      u.MFASecret,
			"otpauth_uri": totpProvisioningURI(username, u.MFASecret),
		},
	})
}

// knownRoles is the closed set of control-plane roles. Rejecting anything else
// stops a typo from creating an account that no authorization rule matches.
var knownRoles = map[string]bool{"admin": true, "operator": true, "viewer": true}

func isKnownRole(role string) bool {
	return knownRoles[strings.ToLower(strings.TrimSpace(role))]
}

// minPasswordLength follows the NIST 800-63B recommendation for user-chosen
// secrets protected by a memory-hard hash.
const minPasswordLength = 12

func validatePasswordStrength(password string) error {
	if len([]rune(password)) < minPasswordLength {
		return fmt.Errorf("password must be at least %d characters", minPasswordLength)
	}
	return nil
}

// generateTOTPSecret creates a random base32-encoded TOTP secret.
func generateTOTPSecret() (string, error) {
	return authn.GenerateTOTPSecret()
}

// hashPassword derives an argon2id hash in PHC string format.
func hashPassword(password string) (string, error) {
	return authn.HashPassword(password)
}

// checkPassword verifies a password against its stored hash. Hashes written by
// earlier releases are still accepted so that upgrades do not lock anyone out;
// authn.NeedsRehash flags them for transparent upgrade on next login.
func checkPassword(password, hash string) bool {
	return authn.VerifyPassword(password, hash)
}

// totpConfig is the TOTP scheme advertised to authenticator apps.
func totpConfig() authn.TOTPConfig { return authn.DefaultTOTPConfig() }

func totpProvisioningURI(username, secret string) string {
	return authn.TOTPProvisioningURI("SSHProxy", username, secret, totpConfig())
}
