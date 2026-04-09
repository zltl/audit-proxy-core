package grpcapi

import (
	"context"
	"strings"
	"time"

	sshproxyv1 "github.com/ssh-proxy-core/ssh-proxy-core/api/proto/sshproxy/v1"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/api"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// BridgeServer exposes a minimal gRPC surface backed by the existing data-plane client.
type BridgeServer struct {
	sshproxyv1.UnimplementedSystemServiceServer
	sshproxyv1.UnimplementedSessionServiceServer
	sshproxyv1.UnimplementedServerServiceServer
	sshproxyv1.UnimplementedConfigServiceServer

	dp        api.DataPlaneClient
	startedAt time.Time
}

// NewBridgeServer creates a gRPC bridge over the current runtime services.
func NewBridgeServer(dp api.DataPlaneClient) *BridgeServer {
	return &BridgeServer{
		dp:        dp,
		startedAt: time.Now().UTC(),
	}
}

// Register attaches every supported service to the provided gRPC registrar.
func Register(registrar grpc.ServiceRegistrar, srv *BridgeServer) {
	sshproxyv1.RegisterSystemServiceServer(registrar, srv)
	sshproxyv1.RegisterSessionServiceServer(registrar, srv)
	sshproxyv1.RegisterServerServiceServer(registrar, srv)
	sshproxyv1.RegisterConfigServiceServer(registrar, srv)
}

func (s *BridgeServer) requireDataPlane() error {
	if s.dp == nil {
		return status.Error(codes.FailedPrecondition, "data-plane client not configured")
	}
	return nil
}

func protoTimestamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t.UTC())
}

func paginate(total, page, perPage int) (normalizedPage, normalizedPerPage, start, end int) {
	normalizedPage = 1
	if page > 0 {
		normalizedPage = page
	}

	normalizedPerPage = 50
	if perPage > 0 && perPage <= 200 {
		normalizedPerPage = perPage
	}

	start = (normalizedPage - 1) * normalizedPerPage
	if start > total {
		start = total
	}
	end = start + normalizedPerPage
	if end > total {
		end = total
	}
	return normalizedPage, normalizedPerPage, start, end
}

func filterSessions(sessions []models.Session, statusFilter, userFilter, ipFilter string) []models.Session {
	statusFilter = strings.TrimSpace(statusFilter)
	userFilter = strings.ToLower(strings.TrimSpace(userFilter))
	ipFilter = strings.ToLower(strings.TrimSpace(ipFilter))

	filtered := make([]models.Session, 0, len(sessions))
	for _, item := range sessions {
		if statusFilter != "" && item.Status != statusFilter {
			continue
		}
		if userFilter != "" && !strings.Contains(strings.ToLower(item.Username), userFilter) {
			continue
		}
		if ipFilter != "" && !strings.Contains(strings.ToLower(item.SourceIP), ipFilter) {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func sanitizeConfigValue(key string, value interface{}) interface{} {
	lowerKey := strings.ToLower(key)
	for _, sensitive := range []string{"password", "secret", "token", "key", "pass_hash", "private_key"} {
		if strings.Contains(lowerKey, sensitive) {
			return "***REDACTED***"
		}
	}
	return sanitizeUntypedValue(value)
}

func sanitizeUntypedValue(value interface{}) interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		sanitizeConfigMap(typed)
		return typed
	case []interface{}:
		for i, item := range typed {
			typed[i] = sanitizeUntypedValue(item)
		}
		return typed
	default:
		return value
	}
}

func sanitizeConfigMap(cfg map[string]interface{}) {
	for key, value := range cfg {
		cfg[key] = sanitizeConfigValue(key, value)
	}
}

func toProtoSession(item models.Session) *sshproxyv1.Session {
	return &sshproxyv1.Session{
		Id:            item.ID,
		Username:      item.Username,
		SourceIp:      item.SourceIP,
		TargetHost:    item.TargetHost,
		TargetPort:    int32(item.TargetPort),
		StartTime:     protoTimestamp(item.StartTime),
		Duration:      item.Duration,
		BytesIn:       item.BytesIn,
		BytesOut:      item.BytesOut,
		Status:        item.Status,
		RecordingFile: item.RecordingFile,
	}
}

func toProtoServer(item models.Server) *sshproxyv1.Server {
	return &sshproxyv1.Server{
		Id:          item.ID,
		Host:        item.Host,
		Port:        int32(item.Port),
		Name:        item.Name,
		Group:       item.Group,
		Status:      item.Status,
		Healthy:     item.Healthy,
		Maintenance: item.Maintenance,
		Weight:      int32(item.Weight),
		MaxSessions: int32(item.MaxSessions),
		Sessions:    int32(item.Sessions),
		Tags:        item.Tags,
		CheckedAt:   protoTimestamp(item.CheckedAt),
	}
}

// GetHealth implements sshproxy.v1.SystemService.
func (s *BridgeServer) GetHealth(ctx context.Context, _ *emptypb.Empty) (*sshproxyv1.SystemHealth, error) {
	if err := s.requireDataPlane(); err != nil {
		return nil, err
	}

	health, err := s.dp.GetHealth()
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "get data-plane health: %v", err)
	}

	return &sshproxyv1.SystemHealth{
		Status:        "healthy",
		DataPlane:     health.Status,
		UptimeSeconds: int64(time.Since(s.startedAt).Seconds()),
		Timestamp:     timestamppb.Now(),
	}, nil
}

// ListSessions implements sshproxy.v1.SessionService.
func (s *BridgeServer) ListSessions(ctx context.Context, req *sshproxyv1.ListSessionsRequest) (*sshproxyv1.ListSessionsResponse, error) {
	if err := s.requireDataPlane(); err != nil {
		return nil, err
	}
	_ = ctx

	sessions, err := s.dp.ListSessions()
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "list sessions: %v", err)
	}

	filtered := filterSessions(sessions, req.GetStatus(), req.GetUser(), req.GetIp())
	page, perPage, start, end := paginate(len(filtered), int(req.GetPage()), int(req.GetPerPage()))

	out := make([]*sshproxyv1.Session, 0, end-start)
	for _, item := range filtered[start:end] {
		out = append(out, toProtoSession(item))
	}

	return &sshproxyv1.ListSessionsResponse{
		Sessions: out,
		Page: &sshproxyv1.PageInfo{
			Total:   int32(len(filtered)),
			Page:    int32(page),
			PerPage: int32(perPage),
		},
	}, nil
}

// GetSession implements sshproxy.v1.SessionService.
func (s *BridgeServer) GetSession(ctx context.Context, req *sshproxyv1.ResourceID) (*sshproxyv1.Session, error) {
	if err := s.requireDataPlane(); err != nil {
		return nil, err
	}
	_ = ctx

	if strings.TrimSpace(req.GetId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}

	sessions, err := s.dp.ListSessions()
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "list sessions: %v", err)
	}
	for _, item := range sessions {
		if item.ID == req.GetId() {
			return toProtoSession(item), nil
		}
	}
	return nil, status.Error(codes.NotFound, "session not found")
}

// KillSession implements sshproxy.v1.SessionService.
func (s *BridgeServer) KillSession(ctx context.Context, req *sshproxyv1.ResourceID) (*sshproxyv1.OperationStatus, error) {
	if err := s.requireDataPlane(); err != nil {
		return nil, err
	}
	_ = ctx

	if strings.TrimSpace(req.GetId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	if err := s.dp.KillSession(req.GetId()); err != nil {
		return nil, status.Errorf(codes.Unavailable, "kill session: %v", err)
	}
	return &sshproxyv1.OperationStatus{Message: "session " + req.GetId() + " terminated"}, nil
}

// ListServers implements sshproxy.v1.ServerService.
func (s *BridgeServer) ListServers(ctx context.Context, req *sshproxyv1.ListServersRequest) (*sshproxyv1.ListServersResponse, error) {
	if err := s.requireDataPlane(); err != nil {
		return nil, err
	}
	_ = ctx

	servers, err := s.dp.ListUpstreams()
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "list servers: %v", err)
	}
	page, perPage, start, end := paginate(len(servers), int(req.GetPage()), int(req.GetPerPage()))

	out := make([]*sshproxyv1.Server, 0, end-start)
	for _, item := range servers[start:end] {
		out = append(out, toProtoServer(item))
	}

	return &sshproxyv1.ListServersResponse{
		Servers: out,
		Page: &sshproxyv1.PageInfo{
			Total:   int32(len(servers)),
			Page:    int32(page),
			PerPage: int32(perPage),
		},
	}, nil
}

// GetHealthSummary implements sshproxy.v1.ServerService.
func (s *BridgeServer) GetHealthSummary(ctx context.Context, _ *emptypb.Empty) (*sshproxyv1.ServerHealthSummary, error) {
	if err := s.requireDataPlane(); err != nil {
		return nil, err
	}
	_ = ctx

	servers, err := s.dp.ListUpstreams()
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "list servers: %v", err)
	}

	var healthy, unhealthy, maintenance int32
	for _, item := range servers {
		if item.Maintenance {
			maintenance++
		}
		if item.Healthy {
			healthy++
		} else {
			unhealthy++
		}
	}

	return &sshproxyv1.ServerHealthSummary{
		Total:       int32(len(servers)),
		Healthy:     healthy,
		Unhealthy:   unhealthy,
		Maintenance: maintenance,
	}, nil
}

// GetConfig implements sshproxy.v1.ConfigService.
func (s *BridgeServer) GetConfig(ctx context.Context, _ *emptypb.Empty) (*sshproxyv1.ConfigDocument, error) {
	if err := s.requireDataPlane(); err != nil {
		return nil, err
	}
	_ = ctx

	cfg, err := s.dp.GetConfig()
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "get config: %v", err)
	}
	sanitizeConfigMap(cfg)

	payload, err := structpb.NewStruct(cfg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal config: %v", err)
	}
	return &sshproxyv1.ConfigDocument{Config: payload}, nil
}

// ReloadConfig implements sshproxy.v1.ConfigService.
func (s *BridgeServer) ReloadConfig(ctx context.Context, _ *emptypb.Empty) (*sshproxyv1.OperationStatus, error) {
	if err := s.requireDataPlane(); err != nil {
		return nil, err
	}
	_ = ctx

	if err := s.dp.ReloadConfig(); err != nil {
		return nil, status.Errorf(codes.Unavailable, "reload config: %v", err)
	}
	return &sshproxyv1.OperationStatus{Message: "configuration reloaded"}, nil
}
