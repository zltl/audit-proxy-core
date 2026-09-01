package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/authn"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/store"
)

// SetDataPlaneStore attaches the database that holds identities, targets, and
// access policy, enabling the administration API for it.
func (a *API) SetDataPlaneStore(st *store.Store) {
	a.dpStore = st
}

// RegisterDataPlaneRoutes registers administration for the data-plane tables.
//
// These endpoints are how a deployment is configured once the file has stopped
// being the source of truth. Everything here changes who can reach what, so the
// authorization policy places the whole prefix behind the administrator role.
func (a *API) RegisterDataPlaneRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v2/dp/users", a.handleDPListUsers)
	mux.HandleFunc("POST /api/v2/dp/users", a.handleDPCreateUser)
	mux.HandleFunc("GET /api/v2/dp/users/{username}", a.handleDPGetUser)
	mux.HandleFunc("PATCH /api/v2/dp/users/{username}", a.handleDPUpdateUser)
	mux.HandleFunc("DELETE /api/v2/dp/users/{username}", a.handleDPDeleteUser)
	mux.HandleFunc("GET /api/v2/dp/users/{username}/keys", a.handleDPListKeys)
	mux.HandleFunc("POST /api/v2/dp/users/{username}/keys", a.handleDPAddKey)
	mux.HandleFunc("DELETE /api/v2/dp/users/{username}/keys/{fingerprint...}", a.handleDPDeleteKey)

	mux.HandleFunc("GET /api/v2/dp/targets", a.handleDPListTargets)
	mux.HandleFunc("POST /api/v2/dp/targets", a.handleDPCreateTarget)
	mux.HandleFunc("GET /api/v2/dp/targets/{name}", a.handleDPGetTarget)
	mux.HandleFunc("PATCH /api/v2/dp/targets/{name}", a.handleDPUpdateTarget)
	mux.HandleFunc("DELETE /api/v2/dp/targets/{name}", a.handleDPDeleteTarget)
	// The fingerprint segments below use a trailing wildcard because a SHA256
	// fingerprint is base64 and routinely contains a forward slash, which a
	// single path segment cannot hold.
	mux.HandleFunc("GET /api/v2/dp/targets/{name}/host-keys", a.handleDPListHostKeys)
	mux.HandleFunc("PUT /api/v2/dp/targets/{name}/host-keys/{fingerprint...}", a.handleDPSetHostKeyStatus)
	mux.HandleFunc("DELETE /api/v2/dp/targets/{name}/host-keys/{fingerprint...}", a.handleDPDeleteHostKey)
	mux.HandleFunc("GET /api/v2/dp/host-keys/pending", a.handleDPPendingHostKeys)

	mux.HandleFunc("GET /api/v2/dp/credentials", a.handleDPListCredentials)
	mux.HandleFunc("POST /api/v2/dp/credentials", a.handleDPCreateCredential)
	mux.HandleFunc("DELETE /api/v2/dp/credentials/{id}", a.handleDPDeleteCredential)

	mux.HandleFunc("GET /api/v2/dp/rules", a.handleDPListRules)
	mux.HandleFunc("POST /api/v2/dp/rules", a.handleDPPutRule)
	mux.HandleFunc("DELETE /api/v2/dp/rules/{id}", a.handleDPDeleteRule)
	mux.HandleFunc("POST /api/v2/dp/rules/evaluate", a.handleDPEvaluate)

	mux.HandleFunc("GET /api/v2/dp/ip-rules", a.handleDPListIPRules)
	mux.HandleFunc("POST /api/v2/dp/ip-rules", a.handleDPPutIPRule)
	mux.HandleFunc("DELETE /api/v2/dp/ip-rules/{id}", a.handleDPDeleteIPRule)

	mux.HandleFunc("GET /api/v2/dp/roles", a.handleDPListRoles)
	mux.HandleFunc("POST /api/v2/dp/role-bindings", a.handleDPBindRole)
	mux.HandleFunc("GET /api/v2/dp/role-bindings", a.handleDPListRoleBindings)

	mux.HandleFunc("GET /api/v2/dp/sessions", a.handleDPListSessions)
	mux.HandleFunc("POST /api/v2/dp/sessions/{id}/terminate", a.handleDPTerminateSession)

	mux.HandleFunc("GET /api/v2/dp/features", a.handleDPListFeatureNames)
}

// requireDPStore reports whether the data-plane store is available.
func (a *API) requireDPStore(w http.ResponseWriter) bool {
	if a == nil || a.dpStore == nil {
		writeError(w, http.StatusServiceUnavailable,
			"the data-plane store is not configured; set pdp_listen_addr to enable it")
		return false
	}
	return true
}

// writeStoreError maps store errors onto status codes.
func writeStoreError(w http.ResponseWriter, err error, action string) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, store.ErrNoSealer):
		writeError(w, http.StatusPreconditionFailed,
			"no encryption key is configured, so credentials cannot be stored")
	default:
		writeError(w, http.StatusInternalServerError, action+": "+err.Error())
	}
}

// --------------------------------------------------------------------------
// Identities
// --------------------------------------------------------------------------

// dpUserView is the API representation of an identity. It deliberately has no
// field for the password hash or the MFA secret: those are write-only, because
// an administration API that can read them turns one compromised session into
// every credential in the system.
type dpUserView struct {
	ID                     string    `json:"id"`
	Username               string    `json:"username"`
	DisplayName            string    `json:"display_name"`
	Email                  string    `json:"email"`
	Status                 string    `json:"status"`
	Source                 string    `json:"source"`
	MFAType                string    `json:"mfa_type"`
	MFAPending             bool      `json:"mfa_pending"`
	PasswordChangeRequired bool      `json:"password_change_required"`
	PasswordChangedAt      time.Time `json:"password_changed_at,omitempty"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
	LastLoginAt            time.Time `json:"last_login_at,omitempty"`
	Roles                  []string  `json:"roles,omitempty"`
}

func (a *API) dpUserToView(u store.User) dpUserView {
	view := dpUserView{
		ID:                     u.ID,
		Username:               u.Username,
		DisplayName:            u.DisplayName,
		Email:                  u.Email,
		Status:                 string(u.Status),
		Source:                 string(u.Source),
		MFAType:                string(u.MFAType),
		MFAPending:             u.MFAPending,
		PasswordChangeRequired: u.PasswordChangeRequired,
		PasswordChangedAt:      u.PasswordChangedAt,
		CreatedAt:              u.CreatedAt,
		UpdatedAt:              u.UpdatedAt,
		LastLoginAt:            u.LastLoginAt,
	}
	if roles, err := a.dpStore.RolesForUser(u.Username); err == nil {
		view.Roles = roles
	}
	return view
}

func (a *API) handleDPListUsers(w http.ResponseWriter, r *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	users, err := a.dpStore.ListUsers()
	if err != nil {
		writeStoreError(w, err, "list users")
		return
	}
	views := make([]dpUserView, 0, len(users))
	for _, u := range users {
		views = append(views, a.dpUserToView(u))
	}
	page, perPage := parsePagination(r)
	start, end := paginate(len(views), page, perPage)
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true, Data: views[start:end], Total: len(views), Page: page, PerPage: perPage,
	})
}

func (a *API) handleDPCreateUser(w http.ResponseWriter, r *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	var req struct {
		Username    string   `json:"username"`
		DisplayName string   `json:"display_name"`
		Email       string   `json:"email"`
		Password    string   `json:"password"`
		Source      string   `json:"source"`
		Roles       []string `json:"roles"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Username) == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}

	user := store.User{
		Username:    strings.TrimSpace(req.Username),
		DisplayName: req.DisplayName,
		Email:       req.Email,
		Status:      store.UserActive,
		Source:      store.IdentitySource(strings.TrimSpace(req.Source)),
	}
	if req.Password != "" {
		if err := validatePasswordStrength(req.Password); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		hash, err := authn.HashPassword(req.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to hash password")
			return
		}
		user.PasswordHash = hash
		user.PasswordChangedAt = time.Now().UTC()
	}

	created, err := a.dpStore.CreateUser(user)
	if err != nil {
		writeStoreError(w, err, "create user")
		return
	}
	for _, role := range req.Roles {
		if _, err := a.dpStore.BindRole(store.RoleBinding{
			SubjectKind: store.SubjectUser, Subject: created.Username, Role: role,
		}); err != nil {
			writeStoreError(w, err, "bind role")
			return
		}
	}
	writeJSON(w, http.StatusCreated, APIResponse{Success: true, Data: a.dpUserToView(created)})
}

func (a *API) handleDPGetUser(w http.ResponseWriter, r *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	user, err := a.dpStore.GetUser(r.PathValue("username"))
	if err != nil {
		writeStoreError(w, err, "load user")
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: a.dpUserToView(user)})
}

func (a *API) handleDPUpdateUser(w http.ResponseWriter, r *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	var req struct {
		DisplayName            *string `json:"display_name"`
		Email                  *string `json:"email"`
		Status                 *string `json:"status"`
		Password               *string `json:"password"`
		PasswordChangeRequired *bool   `json:"password_change_required"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	username := r.PathValue("username")
	var validationErr error
	updated, err := a.dpStore.UpdateUser(username, func(u *store.User) error {
		if req.DisplayName != nil {
			u.DisplayName = *req.DisplayName
		}
		if req.Email != nil {
			u.Email = *req.Email
		}
		if req.Status != nil {
			status := store.UserStatus(strings.TrimSpace(*req.Status))
			switch status {
			case store.UserActive, store.UserDisabled, store.UserLocked:
				u.Status = status
			default:
				validationErr = errors.New("status must be active, disabled, or locked")
				return validationErr
			}
		}
		if req.Password != nil {
			if err := validatePasswordStrength(*req.Password); err != nil {
				validationErr = err
				return err
			}
			hash, err := authn.HashPassword(*req.Password)
			if err != nil {
				return err
			}
			u.PasswordHash = hash
			u.PasswordChangedAt = time.Now().UTC()
		}
		if req.PasswordChangeRequired != nil {
			u.PasswordChangeRequired = *req.PasswordChangeRequired
		}
		return nil
	})
	if validationErr != nil {
		writeError(w, http.StatusBadRequest, validationErr.Error())
		return
	}
	if err != nil {
		writeStoreError(w, err, "update user")
		return
	}

	// Disabling an account has to take effect on sessions already open, not
	// only on the next login attempt.
	if updated.Status != store.UserActive {
		if _, err := a.dpStore.RevokeSessionsForUser(updated.Username, "account disabled"); err != nil {
			writeStoreError(w, err, "revoke sessions")
			return
		}
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: a.dpUserToView(updated)})
}

func (a *API) handleDPDeleteUser(w http.ResponseWriter, r *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	username := r.PathValue("username")
	if _, err := a.dpStore.RevokeSessionsForUser(username, "account removed"); err != nil {
		writeStoreError(w, err, "revoke sessions")
		return
	}
	if err := a.dpStore.DeleteUser(username); err != nil {
		writeStoreError(w, err, "delete user")
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true,
		Data: map[string]string{"message": "user " + username + " deleted"}})
}

// --------------------------------------------------------------------------
// Public keys
// --------------------------------------------------------------------------

func (a *API) handleDPListKeys(w http.ResponseWriter, r *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	user, err := a.dpStore.GetUser(r.PathValue("username"))
	if err != nil {
		writeStoreError(w, err, "load user")
		return
	}
	keys, err := a.dpStore.ListPublicKeys(user.ID)
	if err != nil {
		writeStoreError(w, err, "list public keys")
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: keys, Total: len(keys)})
}

func (a *API) handleDPAddKey(w http.ResponseWriter, r *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	var req struct {
		PublicKey string `json:"public_key"`
		Comment   string `json:"comment"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	user, err := a.dpStore.GetUser(r.PathValue("username"))
	if err != nil {
		writeStoreError(w, err, "load user")
		return
	}
	parsed, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid public key: "+err.Error())
		return
	}
	key := store.PublicKey{
		UserID:      user.ID,
		Fingerprint: ssh.FingerprintSHA256(parsed),
		Algorithm:   parsed.Type(),
		PublicKey:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(parsed))),
		Comment:     firstNonEmptyString(req.Comment, comment),
	}
	if req.ExpiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "expires_at must be an RFC3339 timestamp")
			return
		}
		key.ExpiresAt = expiresAt
	}

	created, err := a.dpStore.AddPublicKey(key)
	if err != nil {
		writeStoreError(w, err, "add public key")
		return
	}
	writeJSON(w, http.StatusCreated, APIResponse{Success: true, Data: created})
}

func (a *API) handleDPDeleteKey(w http.ResponseWriter, r *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	if err := a.dpStore.DeletePublicKey(r.PathValue("fingerprint")); err != nil {
		writeStoreError(w, err, "delete public key")
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true,
		Data: map[string]string{"message": "public key removed"}})
}

// --------------------------------------------------------------------------
// Targets and host keys
// --------------------------------------------------------------------------

func (a *API) handleDPListTargets(w http.ResponseWriter, r *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	targets, err := a.dpStore.ListTargets()
	if err != nil {
		writeStoreError(w, err, "list targets")
		return
	}
	page, perPage := parsePagination(r)
	start, end := paginate(len(targets), page, perPage)
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true, Data: targets[start:end], Total: len(targets), Page: page, PerPage: perPage,
	})
}

func (a *API) handleDPCreateTarget(w http.ResponseWriter, r *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	var req struct {
		Name    string            `json:"name"`
		Host    string            `json:"host"`
		Port    int               `json:"port"`
		Group   string            `json:"group"`
		OS      string            `json:"os"`
		Tags    map[string]string `json:"tags"`
		Weight  int               `json:"weight"`
		Enabled *bool             `json:"enabled"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	target := store.Target{
		Name: req.Name, Host: req.Host, Port: req.Port, Group: req.Group,
		OS: req.OS, Tags: req.Tags, Weight: req.Weight, Enabled: true,
	}
	if req.Enabled != nil {
		target.Enabled = *req.Enabled
	}
	created, err := a.dpStore.CreateTarget(target)
	if err != nil {
		writeStoreError(w, err, "create target")
		return
	}
	writeJSON(w, http.StatusCreated, APIResponse{Success: true, Data: created})
}

func (a *API) handleDPGetTarget(w http.ResponseWriter, r *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	target, err := a.dpStore.GetTarget(r.PathValue("name"))
	if err != nil {
		writeStoreError(w, err, "load target")
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: target})
}

func (a *API) handleDPUpdateTarget(w http.ResponseWriter, r *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	var req struct {
		Host        *string           `json:"host"`
		Port        *int              `json:"port"`
		Group       *string           `json:"group"`
		OS          *string           `json:"os"`
		Tags        map[string]string `json:"tags"`
		Weight      *int              `json:"weight"`
		Enabled     *bool             `json:"enabled"`
		Maintenance *bool             `json:"maintenance"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := a.dpStore.UpdateTarget(r.PathValue("name"), func(t *store.Target) error {
		if req.Host != nil {
			t.Host = *req.Host
		}
		if req.Port != nil {
			t.Port = *req.Port
		}
		if req.Group != nil {
			t.Group = *req.Group
		}
		if req.OS != nil {
			t.OS = *req.OS
		}
		if req.Tags != nil {
			t.Tags = req.Tags
		}
		if req.Weight != nil {
			t.Weight = *req.Weight
		}
		if req.Enabled != nil {
			t.Enabled = *req.Enabled
		}
		if req.Maintenance != nil {
			t.Maintenance = *req.Maintenance
		}
		return nil
	})
	if err != nil {
		writeStoreError(w, err, "update target")
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: updated})
}

func (a *API) handleDPDeleteTarget(w http.ResponseWriter, r *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	if err := a.dpStore.DeleteTarget(r.PathValue("name")); err != nil {
		writeStoreError(w, err, "delete target")
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true,
		Data: map[string]string{"message": "target removed"}})
}

func (a *API) handleDPListHostKeys(w http.ResponseWriter, r *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	target, err := a.dpStore.GetTarget(r.PathValue("name"))
	if err != nil {
		writeStoreError(w, err, "load target")
		return
	}
	keys, err := a.dpStore.ListHostKeys(target.ID)
	if err != nil {
		writeStoreError(w, err, "list host keys")
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: keys, Total: len(keys)})
}

// handleDPSetHostKeyStatus is how an operator rules on a key learned on first
// contact, and how a compromised key is retired.
func (a *API) handleDPSetHostKeyStatus(w http.ResponseWriter, r *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	var req struct {
		Status string `json:"status"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	status := store.HostKeyStatus(strings.TrimSpace(req.Status))
	switch status {
	case store.HostKeyTrusted, store.HostKeyPending, store.HostKeyRevoked:
	default:
		writeError(w, http.StatusBadRequest, "status must be trusted, pending, or revoked")
		return
	}

	target, err := a.dpStore.GetTarget(r.PathValue("name"))
	if err != nil {
		writeStoreError(w, err, "load target")
		return
	}
	if err := a.dpStore.SetHostKeyStatus(target.ID, r.PathValue("fingerprint"), status); err != nil {
		writeStoreError(w, err, "update host key")
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true,
		Data: map[string]string{"status": string(status)}})
}

func (a *API) handleDPDeleteHostKey(w http.ResponseWriter, r *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	target, err := a.dpStore.GetTarget(r.PathValue("name"))
	if err != nil {
		writeStoreError(w, err, "load target")
		return
	}
	if err := a.dpStore.DeleteHostKey(target.ID, r.PathValue("fingerprint")); err != nil {
		writeStoreError(w, err, "delete host key")
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true,
		Data: map[string]string{"message": "host key removed"}})
}

// handleDPPendingHostKeys lists keys awaiting a decision, which is the queue an
// operator works through rather than having to check each target.
func (a *API) handleDPPendingHostKeys(w http.ResponseWriter, _ *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	keys, err := a.dpStore.ListPendingHostKeys()
	if err != nil {
		writeStoreError(w, err, "list pending host keys")
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: keys, Total: len(keys)})
}

// --------------------------------------------------------------------------
// Upstream credentials
// --------------------------------------------------------------------------

// dpCredentialView omits the secret. The material is write-only: an API that
// can read a vaulted upstream password is a vault with a door in the back.
type dpCredentialView struct {
	ID             string    `json:"id"`
	TargetID       string    `json:"target_id,omitempty"`
	TargetSelector string    `json:"target_selector,omitempty"`
	Login          string    `json:"login"`
	Kind           string    `json:"kind"`
	HasSecret      bool      `json:"has_secret"`
	RotateAfter    string    `json:"rotate_after,omitempty"`
	LastRotatedAt  time.Time `json:"last_rotated_at,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

func credentialToView(c store.Credential) dpCredentialView {
	view := dpCredentialView{
		ID: c.ID, TargetID: c.TargetID, TargetSelector: c.TargetSelector,
		Login: c.Login, Kind: string(c.Kind), HasSecret: c.SecretRef != "",
		LastRotatedAt: c.LastRotatedAt, CreatedAt: c.CreatedAt,
	}
	if c.RotateAfter > 0 {
		view.RotateAfter = c.RotateAfter.String()
	}
	return view
}

func (a *API) handleDPListCredentials(w http.ResponseWriter, _ *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	credentials, err := a.dpStore.ListCredentials()
	if err != nil {
		writeStoreError(w, err, "list credentials")
		return
	}
	views := make([]dpCredentialView, 0, len(credentials))
	for _, c := range credentials {
		views = append(views, credentialToView(c))
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: views, Total: len(views)})
}

func (a *API) handleDPCreateCredential(w http.ResponseWriter, r *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	var req struct {
		TargetName     string `json:"target_name"`
		TargetSelector string `json:"target_selector"`
		Login          string `json:"login"`
		Kind           string `json:"kind"`
		// Secret is accepted on write and never returned.
		Secret      string `json:"secret"`
		RotateAfter string `json:"rotate_after"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	credential := store.Credential{
		TargetSelector: req.TargetSelector,
		Login:          req.Login,
		Kind:           store.CredentialKind(strings.TrimSpace(req.Kind)),
	}
	if name := strings.TrimSpace(req.TargetName); name != "" {
		target, err := a.dpStore.GetTarget(name)
		if err != nil {
			writeStoreError(w, err, "load target")
			return
		}
		credential.TargetID = target.ID
	}
	if req.RotateAfter != "" {
		duration, err := time.ParseDuration(req.RotateAfter)
		if err != nil {
			writeError(w, http.StatusBadRequest, "rotate_after must be a duration such as 720h")
			return
		}
		credential.RotateAfter = duration
	}

	switch credential.Kind {
	case store.CredentialPassword, store.CredentialPrivateKey:
		if req.Secret == "" {
			writeError(w, http.StatusBadRequest, "secret is required for this credential kind")
			return
		}
		if credential.Kind == store.CredentialPrivateKey {
			if _, err := ssh.ParsePrivateKey([]byte(req.Secret)); err != nil {
				writeError(w, http.StatusBadRequest, "the secret is not a usable private key: "+err.Error())
				return
			}
		}
		ref, err := a.dpStore.PutSecretString("upstream_"+string(credential.Kind), req.Secret)
		if err != nil {
			writeStoreError(w, err, "store secret")
			return
		}
		credential.SecretRef = ref
		credential.LastRotatedAt = time.Now().UTC()
	case store.CredentialCACert, store.CredentialAgent:
		// These hold nothing: a certificate is minted per session and an agent
		// belongs to the user.
	default:
		writeError(w, http.StatusBadRequest,
			"kind must be password, private_key, ca_cert, or agent")
		return
	}

	created, err := a.dpStore.PutCredential(credential)
	if err != nil {
		writeStoreError(w, err, "create credential")
		return
	}
	writeJSON(w, http.StatusCreated, APIResponse{Success: true, Data: credentialToView(created)})
}

func (a *API) handleDPDeleteCredential(w http.ResponseWriter, r *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	if err := a.dpStore.DeleteCredential(r.PathValue("id")); err != nil {
		writeStoreError(w, err, "delete credential")
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true,
		Data: map[string]string{"message": "credential removed"}})
}

// --------------------------------------------------------------------------
// Access rules
// --------------------------------------------------------------------------

// dpRuleRequest is the wire form of an access rule. Features travel as names
// rather than a bitmask so that a rule is legible in an API response, a diff,
// and an audit record.
type dpRuleRequest struct {
	ID               string             `json:"id"`
	Name             string             `json:"name"`
	Priority         int                `json:"priority"`
	Effect           string             `json:"effect"`
	SubjectKind      string             `json:"subject_kind"`
	Subject          string             `json:"subject"`
	TargetSelector   string             `json:"target_selector"`
	UpstreamLogins   []string           `json:"upstream_logins"`
	Features         []string           `json:"features"`
	DeniedFeatures   []string           `json:"denied_features"`
	SourceCIDRs      []string           `json:"source_cidrs"`
	TimeWindows      []store.TimeWindow `json:"time_windows"`
	MaxSessionTTL    string             `json:"max_session_ttl"`
	IdleTimeout      string             `json:"idle_timeout"`
	MaxConcurrent    int                `json:"max_concurrent_sessions"`
	RecordPolicy     string             `json:"record_policy"`
	CommandPolicyID  string             `json:"command_policy_id"`
	ApprovalRequired bool               `json:"approval_required"`
	Enabled          *bool              `json:"enabled"`
}

func ruleToView(r store.AccessRule) map[string]interface{} {
	view := map[string]interface{}{
		"id":                      r.ID,
		"name":                    r.Name,
		"priority":                r.Priority,
		"effect":                  string(r.Effect),
		"subject_kind":            string(r.SubjectKind),
		"subject":                 r.Subject,
		"target_selector":         r.TargetSelector,
		"upstream_logins":         r.UpstreamLogins,
		"features":                r.Features.Names(),
		"denied_features":         r.DeniedFeatures.Names(),
		"source_cidrs":            r.SourceCIDRs,
		"time_windows":            r.TimeWindows,
		"max_concurrent_sessions": r.MaxConcurrent,
		"record_policy":           string(r.RecordPolicy),
		"command_policy_id":       r.CommandPolicyID,
		"approval_required":       r.ApprovalRequired,
		"enabled":                 r.Enabled,
		"created_at":              r.CreatedAt,
		"updated_at":              r.UpdatedAt,
	}
	if r.MaxSessionTTL > 0 {
		view["max_session_ttl"] = r.MaxSessionTTL.String()
	}
	if r.IdleTimeout > 0 {
		view["idle_timeout"] = r.IdleTimeout.String()
	}
	return view
}

func (a *API) handleDPListRules(w http.ResponseWriter, _ *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	rules, err := a.dpStore.ListAccessRules()
	if err != nil {
		writeStoreError(w, err, "list access rules")
		return
	}
	views := make([]map[string]interface{}, 0, len(rules))
	for _, rule := range rules {
		views = append(views, ruleToView(rule))
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: views, Total: len(views)})
}

func (a *API) handleDPPutRule(w http.ResponseWriter, r *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	var req dpRuleRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	rule, err := req.toStoreRule()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	saved, err := a.dpStore.PutAccessRule(rule)
	if err != nil {
		writeStoreError(w, err, "save access rule")
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: ruleToView(saved)})
}

// toStoreRule validates and converts a rule request.
//
// Unknown feature names are rejected rather than ignored: silently dropping one
// would produce a rule that grants or denies less than its author wrote, which
// is the kind of mistake nobody notices until it matters.
func (r dpRuleRequest) toStoreRule() (store.AccessRule, error) {
	rule := store.AccessRule{
		ID: r.ID, Name: r.Name, Priority: r.Priority,
		Subject: r.Subject, TargetSelector: r.TargetSelector,
		UpstreamLogins: r.UpstreamLogins, SourceCIDRs: r.SourceCIDRs,
		TimeWindows: r.TimeWindows, MaxConcurrent: r.MaxConcurrent,
		CommandPolicyID: r.CommandPolicyID, ApprovalRequired: r.ApprovalRequired,
		Enabled: true,
	}
	if r.Enabled != nil {
		rule.Enabled = *r.Enabled
	}

	switch store.Effect(strings.TrimSpace(r.Effect)) {
	case store.EffectDeny:
		rule.Effect = store.EffectDeny
	case store.EffectAllow, "":
		rule.Effect = store.EffectAllow
	default:
		return rule, errors.New("effect must be allow or deny")
	}

	switch store.SubjectKind(strings.TrimSpace(r.SubjectKind)) {
	case store.SubjectUser, "":
		rule.SubjectKind = store.SubjectUser
	case store.SubjectRole:
		rule.SubjectKind = store.SubjectRole
	case store.SubjectGroup:
		rule.SubjectKind = store.SubjectGroup
	case store.SubjectAny:
		rule.SubjectKind = store.SubjectAny
	default:
		return rule, errors.New("subject_kind must be user, role, group, or any")
	}

	features, unknown := store.ParseFeatureSet(strings.Join(r.Features, ","))
	if len(unknown) > 0 {
		return rule, errors.New("unknown feature(s): " + strings.Join(unknown, ", ") +
			"; known features are " + strings.Join(store.AllFeatureNames(), ", "))
	}
	rule.Features = features

	denied, unknown := store.ParseFeatureSet(strings.Join(r.DeniedFeatures, ","))
	if len(unknown) > 0 {
		return rule, errors.New("unknown denied feature(s): " + strings.Join(unknown, ", "))
	}
	rule.DeniedFeatures = denied

	switch store.RecordPolicy(strings.TrimSpace(r.RecordPolicy)) {
	case store.RecordFull, "":
		rule.RecordPolicy = store.RecordFull
	case store.RecordCommands:
		rule.RecordPolicy = store.RecordCommands
	case store.RecordNone:
		rule.RecordPolicy = store.RecordNone
	default:
		return rule, errors.New("record_policy must be full, commands, or none")
	}

	if r.MaxSessionTTL != "" {
		duration, err := time.ParseDuration(r.MaxSessionTTL)
		if err != nil {
			return rule, errors.New("max_session_ttl must be a duration such as 8h")
		}
		rule.MaxSessionTTL = duration
	}
	if r.IdleTimeout != "" {
		duration, err := time.ParseDuration(r.IdleTimeout)
		if err != nil {
			return rule, errors.New("idle_timeout must be a duration such as 15m")
		}
		rule.IdleTimeout = duration
	}
	return rule, nil
}

func (a *API) handleDPDeleteRule(w http.ResponseWriter, r *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	if err := a.dpStore.DeleteAccessRule(r.PathValue("id")); err != nil {
		writeStoreError(w, err, "delete access rule")
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true,
		Data: map[string]string{"message": "access rule removed"}})
}

// handleDPEvaluate answers "what would happen if this person connected there".
//
// Access policy is a set of ordered rules with selectors and time windows, and
// reading it is not the same as knowing what it does. Being able to ask before
// a change goes live is the difference between an audited policy and a hoped-for
// one.
func (a *API) handleDPEvaluate(w http.ResponseWriter, r *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	var req struct {
		Username      string   `json:"username"`
		Roles         []string `json:"roles"`
		SourceIP      string   `json:"source_ip"`
		Target        string   `json:"target"`
		UpstreamLogin string   `json:"upstream_login"`
		At            string   `json:"at"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	target, err := a.dpStore.GetTarget(req.Target)
	if err != nil {
		writeStoreError(w, err, "load target")
		return
	}
	roles := req.Roles
	if len(roles) == 0 {
		if stored, err := a.dpStore.RolesForUser(req.Username); err == nil {
			roles = stored
		}
	}
	at := time.Now()
	if req.At != "" {
		parsed, err := time.Parse(time.RFC3339, req.At)
		if err != nil {
			writeError(w, http.StatusBadRequest, "at must be an RFC3339 timestamp")
			return
		}
		at = parsed
	}

	decision, err := a.dpStore.Evaluate(store.AccessRequest{
		Username: req.Username, Roles: roles, SourceIP: req.SourceIP,
		Target: target, UpstreamLogin: req.UpstreamLogin, At: at,
	})
	if err != nil {
		writeStoreError(w, err, "evaluate policy")
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: map[string]interface{}{
		"allowed":                 decision.Allowed,
		"reason":                  decision.Reason,
		"rule_id":                 decision.RuleID,
		"rule_name":               decision.RuleName,
		"features":                decision.Features.Names(),
		"record_policy":           string(decision.RecordPolicy),
		"max_concurrent_sessions": decision.MaxConcurrent,
		"approval_required":       decision.ApprovalRequired,
	}})
}

// --------------------------------------------------------------------------
// Source networks, roles, sessions
// --------------------------------------------------------------------------

func (a *API) handleDPListIPRules(w http.ResponseWriter, _ *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	rules, err := a.dpStore.ListIPRules()
	if err != nil {
		writeStoreError(w, err, "list ip rules")
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: rules, Total: len(rules)})
}

func (a *API) handleDPPutIPRule(w http.ResponseWriter, r *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	var req struct {
		ID        string `json:"id"`
		CIDR      string `json:"cidr"`
		Action    string `json:"action"`
		Priority  int    `json:"priority"`
		Comment   string `json:"comment"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	action := store.IPRuleAction(strings.TrimSpace(req.Action))
	if action != store.IPAllow && action != store.IPDeny {
		writeError(w, http.StatusBadRequest, "action must be allow or deny")
		return
	}
	rule := store.IPRule{
		ID: req.ID, CIDR: req.CIDR, Action: action,
		Priority: req.Priority, Comment: req.Comment,
	}
	if req.ExpiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "expires_at must be an RFC3339 timestamp")
			return
		}
		rule.ExpiresAt = expiresAt
	}
	saved, err := a.dpStore.PutIPRule(rule)
	if err != nil {
		writeStoreError(w, err, "save ip rule")
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: saved})
}

func (a *API) handleDPDeleteIPRule(w http.ResponseWriter, r *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	if err := a.dpStore.DeleteIPRule(r.PathValue("id")); err != nil {
		writeStoreError(w, err, "delete ip rule")
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true,
		Data: map[string]string{"message": "ip rule removed"}})
}

func (a *API) handleDPListRoles(w http.ResponseWriter, _ *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	roles, err := a.dpStore.ListRoles()
	if err != nil {
		writeStoreError(w, err, "list roles")
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: roles, Total: len(roles)})
}

func (a *API) handleDPBindRole(w http.ResponseWriter, r *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	var req struct {
		SubjectKind string `json:"subject_kind"`
		Subject     string `json:"subject"`
		Role        string `json:"role"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	kind := store.SubjectKind(strings.TrimSpace(req.SubjectKind))
	if kind == "" {
		kind = store.SubjectUser
	}
	binding, err := a.dpStore.BindRole(store.RoleBinding{
		SubjectKind: kind, Subject: req.Subject, Role: req.Role,
	})
	if err != nil {
		writeStoreError(w, err, "bind role")
		return
	}
	writeJSON(w, http.StatusCreated, APIResponse{Success: true, Data: binding})
}

func (a *API) handleDPListRoleBindings(w http.ResponseWriter, _ *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	bindings, err := a.dpStore.ListRoleBindings()
	if err != nil {
		writeStoreError(w, err, "list role bindings")
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: bindings, Total: len(bindings)})
}

func (a *API) handleDPListSessions(w http.ResponseWriter, r *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	filter := store.SessionFilter{
		Username: r.URL.Query().Get("user"),
		NodeID:   r.URL.Query().Get("node"),
		SourceIP: r.URL.Query().Get("ip"),
	}
	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = store.SessionStatus(status)
	}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		if parsed, err := strconv.Atoi(limit); err == nil {
			filter.Limit = parsed
		}
	}
	sessions, err := a.dpStore.ListSessions(filter)
	if err != nil {
		writeStoreError(w, err, "list sessions")
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: sessions, Total: len(sessions)})
}

// handleDPTerminateSession asks the node holding a session to disconnect it.
//
// The request is recorded rather than executed here, because the node with the
// socket is the only one that can actually close it; it notices on its next
// heartbeat or on the revocation stream.
func (a *API) handleDPTerminateSession(w http.ResponseWriter, r *http.Request) {
	if !a.requireDPStore(w) {
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	_ = readJSON(r, &req)
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "terminated by " + firstNonEmptyString(callerUsername(r), "an administrator")
	}
	if err := a.dpStore.RequestRevocation(r.PathValue("id"), reason); err != nil {
		writeStoreError(w, err, "request termination")
		return
	}
	writeJSON(w, http.StatusAccepted, APIResponse{Success: true, Data: map[string]string{
		"message": "termination requested; the node serving the session will disconnect it",
	}})
}

// handleDPListFeatureNames lists the capability names a rule may use, so the UI
// and anyone writing a rule by hand can discover them instead of guessing.
func (a *API) handleDPListFeatureNames(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, APIResponse{Success: true,
		Data: map[string]interface{}{"features": store.AllFeatureNames()}})
}
