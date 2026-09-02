package dp_test

import (
	"testing"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/dp"
)

func BenchmarkGoDataPlaneConfigDefaults(b *testing.B) {
	cfg := dp.Config{
		ListenAddr:   "127.0.0.1:2222",
		NodeID:       "bench",
		HostKeyPaths: []string{"/nonexistent/for-bench"},
		RecordingDir: "/tmp",
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = cfg
	}
}
