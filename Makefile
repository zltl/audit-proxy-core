# SSH Proxy Core — Go control plane + Go data plane (default)
#
# Legacy C data plane: make legacy-c  (see legacy/c-dataplane/)

.PHONY: all build test clean go-build go-test go-smoke go-bench compose-smoke legacy-c legacy-test help

all: go-build

build: go-build

test: go-test

go-build:
	@mkdir -p build/bin
	go build -o build/bin/control-plane ./cmd/control-plane
	go build -o build/bin/dataplane ./cmd/dataplane
	go build -o build/bin/sshproxy ./cmd/sshproxy

go-test:
	go test ./...

go-smoke:
	./scripts/smoke-test.sh

go-bench:
	go test -bench=. -benchmem ./internal/dp/...

compose-smoke:
	./scripts/compose-smoke-test.sh

legacy-c:
	$(MAKE) -C legacy/c-dataplane all

legacy-test:
	$(MAKE) -C legacy/c-dataplane test

clean:
	rm -rf build
	$(MAKE) -C legacy/c-dataplane clean || true

help:
	@echo "SSH Proxy Core - Build System (Go default)"
	@echo ""
	@echo "Targets:"
	@echo "  all / build   - Build Go binaries (control-plane, dataplane, sshproxy)"
	@echo "  test          - Run Go tests"
	@echo "  go-smoke      - Local end-to-end smoke (scripts/smoke-test.sh)"
	@echo "  compose-smoke - Docker Compose bring-up smoke"
	@echo "  go-bench      - Data-plane microbenchmarks"
	@echo "  legacy-c      - Build deprecated C data plane"
	@echo "  legacy-test   - Run deprecated C unit tests"
	@echo "  clean         - Remove build artifacts"
