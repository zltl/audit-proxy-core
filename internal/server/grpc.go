package server

import (
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/grpcapi"
	"google.golang.org/grpc"
)

func (s *Server) startGRPC() error {
	if s == nil || s.config == nil || s.config.GRPCListenAddr == "" {
		return nil
	}
	if s.grpcServer != nil {
		return nil
	}

	listener, err := net.Listen("tcp", s.config.GRPCListenAddr)
	if err != nil {
		return fmt.Errorf("server: listen gRPC %s: %w", s.config.GRPCListenAddr, err)
	}

	grpcServer := grpc.NewServer()
	grpcapi.Register(grpcServer, s.grpcBridge)

	s.grpcListener = listener
	s.grpcServer = grpcServer

	go func() {
		if serveErr := grpcServer.Serve(listener); serveErr != nil &&
			!errors.Is(serveErr, grpc.ErrServerStopped) &&
			!errors.Is(serveErr, net.ErrClosed) {
			log.Printf("control-plane gRPC serve error: %v", serveErr)
		}
	}()

	log.Printf("control-plane gRPC listening on %s", listener.Addr().String())
	return nil
}
