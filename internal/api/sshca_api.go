package api

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/sshca"
)

// SetCA attaches a Certificate Authority to the API for SSH CA endpoints.
func (a *API) SetCA(ca *sshca.CA) {
	a.ca = ca
}

// RegisterCARoutes registers all SSH CA API routes on the given mux.
func (a *API) RegisterCARoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v2/ca/sign-user", a.handleSignUserCert)
	mux.HandleFunc("POST /api/v2/ca/sign-host", a.handleSignHostCert)
	mux.HandleFunc("GET /api/v2/ca/public-keys", a.handleCAPublicKeys)
	mux.HandleFunc("GET /api/v2/ca/certs", a.handleListCerts)
	mux.HandleFunc("GET /api/v2/ca/crl", a.handleExportCRL)
	mux.HandleFunc("POST /api/v2/ca/revoke", a.handleRevokeCert)
}

type signUserRequest struct {
	PublicKey       string   `json:"public_key"`
	Principals      []string `json:"principals"`
	TTL             string   `json:"ttl"`
	ForceCommand    string   `json:"force_command"`
	SourceAddresses []string `json:"source_addresses"`
}

type signHostRequest struct {
	PublicKey string `json:"public_key"`
	Hostname  string `json:"hostname"`
	TTL       string `json:"ttl"`
}

type certResponse struct {
	Certificate string `json:"certificate"`
	Serial      uint64 `json:"serial"`
	KeyID       string `json:"key_id"`
	ExpiresAt   string `json:"expires_at"`
}

type revokeRequest struct {
	Serial uint64 `json:"serial"`
}

func clientAddr(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

func (a *API) handleSignUserCert(w http.ResponseWriter, r *http.Request) {
	if a.ca == nil {
		writeError(w, http.StatusServiceUnavailable, "certificate authority not configured")
		return
	}

	var req signUserRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "public_key is required")
		return
	}
	if len(req.Principals) == 0 {
		writeError(w, http.StatusBadRequest, "at least one principal is required")
		return
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid public key: "+err.Error())
		return
	}

	ttl := 8 * time.Hour
	if req.TTL != "" {
		parsed, err := time.ParseDuration(req.TTL)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid TTL: "+err.Error())
			return
		}
		ttl = parsed
	}

	var opts []sshca.CertOption
	if req.ForceCommand != "" {
		opts = append(opts, sshca.WithForceCommand(req.ForceCommand))
	}
	if len(req.SourceAddresses) > 0 {
		opts = append(opts, sshca.WithSourceAddress(req.SourceAddresses...))
	}

	cert, err := a.ca.SignUserCert(pubKey, req.Principals[0], req.Principals, ttl, opts...)
	if err != nil {
		writeError(w, http.StatusBadRequest, "sign failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: certResponse{
			Certificate: sshca.MarshalCertAuthorizedKeys(cert),
			Serial:      cert.Serial,
			KeyID:       cert.KeyId,
			ExpiresAt:   sshca.FormatUnixTime(cert.ValidBefore),
		},
	})
	a.emitWebhookEvent("certificate.issued", req.Principals[0], clientAddr(r.RemoteAddr),
		"issued user certificate principal="+req.Principals[0]+" serial="+strconv.FormatUint(cert.Serial, 10))
}

func (a *API) handleSignHostCert(w http.ResponseWriter, r *http.Request) {
	if a.ca == nil {
		writeError(w, http.StatusServiceUnavailable, "certificate authority not configured")
		return
	}

	var req signHostRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "public_key is required")
		return
	}
	if req.Hostname == "" {
		writeError(w, http.StatusBadRequest, "hostname is required")
		return
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid public key: "+err.Error())
		return
	}

	ttl := 720 * time.Hour
	if req.TTL != "" {
		parsed, err := time.ParseDuration(req.TTL)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid TTL: "+err.Error())
			return
		}
		ttl = parsed
	}

	cert, err := a.ca.SignHostCert(pubKey, req.Hostname, ttl)
	if err != nil {
		writeError(w, http.StatusBadRequest, "sign failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: certResponse{
			Certificate: sshca.MarshalCertAuthorizedKeys(cert),
			Serial:      cert.Serial,
			KeyID:       cert.KeyId,
			ExpiresAt:   sshca.FormatUnixTime(cert.ValidBefore),
		},
	})
	a.emitWebhookEvent("certificate.issued", req.Hostname, clientAddr(r.RemoteAddr),
		"issued host certificate hostname="+req.Hostname+" serial="+strconv.FormatUint(cert.Serial, 10))
}

func (a *API) handleCAPublicKeys(w http.ResponseWriter, r *http.Request) {
	if a.ca == nil {
		writeError(w, http.StatusServiceUnavailable, "certificate authority not configured")
		return
	}

	format := r.URL.Query().Get("format")

	if format == "text" {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("# User CA Public Key\n"))
		w.Write([]byte(a.ca.UserPublicKey()))
		w.Write([]byte("\n# Host CA Public Key\n"))
		w.Write([]byte(a.ca.HostPublicKey()))
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]string{
			"user_ca_public_key": a.ca.UserPublicKey(),
			"host_ca_public_key": a.ca.HostPublicKey(),
		},
	})
}

func (a *API) handleListCerts(w http.ResponseWriter, r *http.Request) {
	if a.ca == nil {
		writeError(w, http.StatusServiceUnavailable, "certificate authority not configured")
		return
	}

	certs := a.ca.ListIssuedCerts()

	page, perPage := parsePagination(r)
	total := len(certs)
	start, end := paginate(total, page, perPage)

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    certs[start:end],
		Total:   total,
		Page:    page,
		PerPage: perPage,
	})
}

func (a *API) handleRevokeCert(w http.ResponseWriter, r *http.Request) {
	if a.ca == nil {
		writeError(w, http.StatusServiceUnavailable, "certificate authority not configured")
		return
	}

	var req revokeRequest

	// Support both JSON body and query parameter.
	if r.Header.Get("Content-Type") == "application/json" {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
	} else {
		serialStr := r.URL.Query().Get("serial")
		if serialStr == "" {
			writeError(w, http.StatusBadRequest, "serial is required")
			return
		}
		s, err := strconv.ParseUint(serialStr, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid serial: "+err.Error())
			return
		}
		req.Serial = s
	}

	if req.Serial == 0 {
		writeError(w, http.StatusBadRequest, "serial is required")
		return
	}

	if err := a.ca.RevokeCert(req.Serial); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"message": "certificate revoked"},
	})
	a.emitWebhookEvent("certificate.revoked", strconv.FormatUint(req.Serial, 10), clientAddr(r.RemoteAddr),
		"revoked certificate serial="+strconv.FormatUint(req.Serial, 10))
}

func (a *API) handleExportCRL(w http.ResponseWriter, r *http.Request) {
	if a.ca == nil {
		writeError(w, http.StatusServiceUnavailable, "certificate authority not configured")
		return
	}

	serials := a.ca.ListRevokedSerials()
	if r.URL.Query().Get("format") == "text" {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		for _, serial := range serials {
			_, _ = w.Write([]byte(strconv.FormatUint(serial, 10)))
			_, _ = w.Write([]byte("\n"))
		}
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"revoked_serials": serials,
			"count":           len(serials),
		},
	})
}
