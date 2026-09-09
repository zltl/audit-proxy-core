# Audit Proxy Core — Go control plane + Go data plane (default)
#
# Legacy C data plane: make legacy-c  (see legacy/c-dataplane/)

.PHONY: all build test clean go-build go-test go-smoke go-bench compose-smoke legacy-c legacy-test demo-ascii demo-ascii-gif help

all: go-build

build: go-build

test: go-test

go-build:
	@mkdir -p build/bin
	go build -o build/bin/control-plane ./cmd/control-plane
	go build -o build/bin/dataplane ./cmd/dataplane
	go build -o build/bin/audit-proxy ./cmd/audit-proxy

go-test:
	go test ./...

demo-ascii:
	go run ./demos/ascii-stream generate -out demos/ascii-stream/demo.cast
	cp demos/ascii-stream/demo.cast internal/asciidemo/demo.cast

demo-ascii-gif: demo-ascii
	@command -v agg >/dev/null 2>&1 || { echo "install agg: cargo install --git https://github.com/asciinema/agg --locked"; exit 1; }
	agg --font-family "Adwaita Mono,DejaVu Sans Mono,Liberation Mono,Consolas" \
		--speed 3 --idle-time-limit 2 --font-size 14 \
		demos/ascii-stream/demo.cast docs/assets/ascii-stream-demo.gif

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
	@echo "Audit Proxy Core - Build System (Go default)"
	@echo ""
	@echo "Targets:"
	@echo "  all / build   - Build Go binaries (control-plane, dataplane, audit-proxy)"
	@echo "  test          - Run Go tests"
	@echo "  demo-ascii    - Regenerate ASCII stream demo.cast (demos + embed)"
	@echo "  demo-ascii-gif - Regenerate README hero GIF (requires agg)"
	@echo "  go-smoke      - Local end-to-end smoke (scripts/smoke-test.sh)"
	@echo "  compose-smoke - Docker Compose bring-up smoke"
	@echo "  go-bench      - Data-plane microbenchmarks"
	@echo "  legacy-c      - Build deprecated C data plane"
	@echo "  legacy-test   - Run deprecated C unit tests"
	@echo "  clean         - Remove build artifacts"
