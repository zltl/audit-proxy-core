package server

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc"

	"golang.org/x/crypto/ssh"

	sshproxyv1 "github.com/ssh-proxy-core/ssh-proxy-core/api/proto/sshproxy/v1"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/pdp"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/secrets"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/sshca"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/store"
)

// startAccessDecisionPoint brings up the service the data plane asks before it
// lets anything happen.
//
// It listens separately from the admin API, on a unix socket by default,
// because anything that can call it can obtain credentials for upstream hosts:
// that surface should not be reachable from wherever the web console is.
func (s *Server) startAccessDecisionPoint() error {
	address := strings.TrimSpace(s.config.PDPListenAddr)
	if address == "" {
		return nil
	}

	st, err := s.openDataPlaneStore()
	if err != nil {
		return err
	}
	s.dataPlaneStore = st

	decisionPoint, err := pdp.New(st, pdp.Config{
		StateSecret:     []byte(s.config.SessionSecret),
		TrustOnFirstUse: s.config.PDPTrustOnFirstUse,
	})
	if err != nil {
		return fmt.Errorf("server: init decision point: %w", err)
	}

	// Events land in the same directory the audit backends already consume, so
	// accepting one is durable regardless of which backends are reachable.
	sink, err := pdp.NewFileEventSink(s.config.AuditLogDir, true)
	if err != nil {
		return fmt.Errorf("server: init audit sink: %w", err)
	}
	s.pdpEventSink = sink
	decisionPoint.SetEventSink(sink)

	if s.apiHandler != nil {
		if ca := s.apiHandler.CertificateAuthority(); ca != nil {
			decisionPoint.SetCertificateSigner(upstreamCertificateSigner{ca: ca})
		}
		// The administration API for these tables only exists when the store
		// does, so it is registered here rather than with the other routes.
		s.apiHandler.SetDataPlaneStore(st)
		s.apiHandler.RegisterDataPlaneRoutes(s.mux)
	}

	listener, err := listenForDecisionPoint(address)
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer()
	sshproxyv1.RegisterAccessDecisionServiceServer(grpcServer, decisionPoint)

	s.pdpServer = grpcServer
	s.pdpListener = listener
	s.decisionPoint = decisionPoint

	go func() {
		if err := grpcServer.Serve(listener); err != nil &&
			!errors.Is(err, grpc.ErrServerStopped) && !errors.Is(err, net.ErrClosed) {
			log.Printf("control-plane: decision point serve error: %v", err)
		}
	}()

	log.Printf("control-plane: access decision point listening on %s", address)
	return nil
}

// listenForDecisionPoint binds a TCP address or a unix socket.
func listenForDecisionPoint(address string) (net.Listener, error) {
	if path, ok := strings.CutPrefix(address, "unix:"); ok {
		path = strings.TrimSpace(path)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, fmt.Errorf("server: create socket directory: %w", err)
		}
		// A socket left behind by a previous run would make the bind fail.
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("server: remove stale socket: %w", err)
		}
		listener, err := net.Listen("unix", path)
		if err != nil {
			return nil, fmt.Errorf("server: listen on %s: %w", path, err)
		}
		// 0660: reachable by the data plane's group and nobody else. The default
		// would let any local user ask for upstream credentials.
		if err := os.Chmod(path, 0o660); err != nil {
			_ = listener.Close()
			return nil, fmt.Errorf("server: restrict socket permissions: %w", err)
		}
		return listener, nil
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("server: listen on %s: %w", address, err)
	}
	return listener, nil
}

// openDataPlaneStore opens the database holding identities, targets, and policy.
func (s *Server) openDataPlaneStore() (*store.Store, error) {
	driver, dsn := s.dataPlaneStoreTarget()
	st, err := store.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("server: open data-plane store: %w", err)
	}

	if spec := strings.TrimSpace(s.config.SecretsEncryptionKey); spec != "" {
		provider, err := secrets.LoadStaticProvider(spec)
		if err != nil {
			_ = st.Close()
			return nil, fmt.Errorf("server: load secrets key: %w", err)
		}
		sealer, err := secrets.NewSealer(provider)
		if err != nil {
			_ = st.Close()
			return nil, fmt.Errorf("server: init sealer: %w", err)
		}
		st.SetSealer(sealer)
	} else {
		// Without a key the secret APIs refuse rather than storing plaintext, so
		// upstream password and key credentials simply cannot be used. Saying so
		// at startup is better than a confusing failure at the first connection.
		log.Printf("control-plane: no secrets_encryption_key is configured; " +
			"stored upstream credentials will be unavailable")
	}
	return st, nil
}

// dataPlaneStoreTarget picks where the store lives, preferring Postgres when
// one is configured and otherwise using a local database under the data
// directory.
func (s *Server) dataPlaneStoreTarget() (driver, dsn string) {
	if url := strings.TrimSpace(s.config.PostgresDatabaseURL); url != "" {
		return "pgx", url
	}
	dir := s.config.DataDir
	if dir == "" {
		dir = "."
	}
	return "sqlite", filepath.Join(dir, "dataplane.db")
}

// stopAccessDecisionPoint shuts the service down.
func (s *Server) stopAccessDecisionPoint() {
	if s.pdpServer != nil {
		s.pdpServer.GracefulStop()
		s.pdpServer = nil
	}
	if s.pdpListener != nil {
		_ = s.pdpListener.Close()
		s.pdpListener = nil
	}
	if s.pdpEventSink != nil {
		_ = s.pdpEventSink.Close()
		s.pdpEventSink = nil
	}
	if s.dataPlaneStore != nil {
		_ = s.dataPlaneStore.Close()
		s.dataPlaneStore = nil
	}
}

// upstreamCertificateSigner adapts the SSH CA to what the decision point needs.
//
// Certificates for upstream authentication are deliberately short lived: they
// exist for the moment of connecting, so expiry rather than revocation is what
// bounds their usefulness if one leaks.
type upstreamCertificateSigner struct {
	ca *sshca.CA
}

func (u upstreamCertificateSigner) SignUpstreamCertificate(publicKey string, principals []string, ttl time.Duration) (string, time.Time, error) {
	if u.ca == nil {
		return "", time.Time{}, errors.New("server: no certificate authority is configured")
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("server: parse ephemeral public key: %w", err)
	}
	principal := ""
	if len(principals) > 0 {
		principal = principals[0]
	}
	cert, err := u.ca.SignUserCert(parsed, principal, principals, ttl)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("server: sign upstream certificate: %w", err)
	}
	return sshca.MarshalCertAuthorizedKeys(cert), time.Unix(int64(cert.ValidBefore), 0).UTC(), nil
}
