GO ?= $(shell command -v go 2>/dev/null || command -v /private/tmp/go/bin/go 2>/dev/null)
GOFMT ?= $(shell command -v gofmt 2>/dev/null || command -v /private/tmp/go/bin/gofmt 2>/dev/null)
GOMODCACHE ?= $(CURDIR)/.cache/gomod
GOCACHE ?= $(CURDIR)/.cache/gocache
GOENV = GOMODCACHE=$(GOMODCACHE) GOCACHE=$(GOCACHE)
BIN ?= bin/timeline
DEMO_DIR ?= /tmp/timeline-demo-output
RELEASE_DIR ?= /tmp/timeline-release
VERSION ?= 0.1.0
COMMIT ?= local
DATE ?= local
LDFLAGS ?= -X timeline/internal/version.Version=$(VERSION) -X timeline/internal/version.Commit=$(COMMIT) -X timeline/internal/version.Date=$(DATE)

.PHONY: lint test test-race bench security build demo release-snapshot clean

lint:
	test -n "$(GO)"
	test -n "$(GOFMT)"
	test -z "$$($(GOFMT) -l cmd internal)"
	$(GOENV) $(GO) vet ./...

test:
	test -n "$(GO)"
	$(GOENV) $(GO) test ./...

test-race:
	test -n "$(GO)"
	$(GOENV) $(GO) test -race ./...

bench:
	test -n "$(GO)"
	$(GOENV) $(GO) test ./cmd/timeline -run '^$$' -bench 'Benchmark(IngestWindowsFixture|QueryFixture|SyntheticLargeCase)$$' -benchmem

security:
	test -n "$(GO)"
	$(GOENV) $(GO) run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...
	$(GOENV) $(GO) run github.com/securego/gosec/v2/cmd/gosec@v2.26.1 $$($(GOENV) $(GO) list -f '{{.Dir}}' ./...)
	$(GOENV) $(GO) run golang.org/x/vuln/cmd/govulncheck@v1.3.0 ./...

build:
	test -n "$(GO)"
	mkdir -p bin
	$(GOENV) $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/timeline

demo: build
	test -n "$(GO)"
	rm -rf $(DEMO_DIR)
	mkdir -p $(DEMO_DIR)
	$(GOENV) $(GO) run ./scripts/generate_demo_case.go -out $(DEMO_DIR)/artifacts
	$(BIN) ingest $(DEMO_DIR)/artifacts/baseline --os windows --out $(DEMO_DIR)/baseline.db --rules rules --fs-path 'C:\Users\Public\'
	$(BIN) ingest $(DEMO_DIR)/artifacts/incident --os windows --out $(DEMO_DIR)/incident.db --rules rules --fs-path 'C:\Users\Public\'
	$(BIN) diff $(DEMO_DIR)/baseline.db $(DEMO_DIR)/incident.db --out $(DEMO_DIR)/report.md
	$(BIN) query $(DEMO_DIR)/incident.db --severity high --format table > $(DEMO_DIR)/cli-output.txt
	$(BIN) export $(DEMO_DIR)/incident.db --format jsonl --out $(DEMO_DIR)/events.jsonl
	@echo "demo complete: $(DEMO_DIR)/baseline.db $(DEMO_DIR)/incident.db $(DEMO_DIR)/report.md $(DEMO_DIR)/events.jsonl"

release-snapshot:
	test -n "$(GO)"
	rm -rf $(RELEASE_DIR)
	mkdir -p $(RELEASE_DIR)/package
	env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GOENV) $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(RELEASE_DIR)/package/timeline ./cmd/timeline
	cp README.md SECURITY.md LICENSE $(RELEASE_DIR)/package/
	tar -C $(RELEASE_DIR)/package -czf $(RELEASE_DIR)/timeline_$(VERSION)_linux_amd64.tar.gz .
	rm -rf $(RELEASE_DIR)/package
	mkdir -p $(RELEASE_DIR)/package
	env GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GOENV) $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(RELEASE_DIR)/package/timeline ./cmd/timeline
	cp README.md SECURITY.md LICENSE $(RELEASE_DIR)/package/
	tar -C $(RELEASE_DIR)/package -czf $(RELEASE_DIR)/timeline_$(VERSION)_linux_arm64.tar.gz .
	rm -rf $(RELEASE_DIR)/package
	mkdir -p $(RELEASE_DIR)/package
	env GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 $(GOENV) $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(RELEASE_DIR)/package/timeline ./cmd/timeline
	cp README.md SECURITY.md LICENSE $(RELEASE_DIR)/package/
	tar -C $(RELEASE_DIR)/package -czf $(RELEASE_DIR)/timeline_$(VERSION)_darwin_amd64.tar.gz .
	rm -rf $(RELEASE_DIR)/package
	mkdir -p $(RELEASE_DIR)/package
	env GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 $(GOENV) $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(RELEASE_DIR)/package/timeline ./cmd/timeline
	cp README.md SECURITY.md LICENSE $(RELEASE_DIR)/package/
	tar -C $(RELEASE_DIR)/package -czf $(RELEASE_DIR)/timeline_$(VERSION)_darwin_arm64.tar.gz .
	rm -rf $(RELEASE_DIR)/package
	mkdir -p $(RELEASE_DIR)/package
	env GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GOENV) $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(RELEASE_DIR)/package/timeline.exe ./cmd/timeline
	cp README.md SECURITY.md LICENSE $(RELEASE_DIR)/package/
	cd $(RELEASE_DIR)/package && zip -qr ../timeline_$(VERSION)_windows_amd64.zip .
	rm -rf $(RELEASE_DIR)/package
	$(GOENV) $(GO) run ./scripts/sbom > $(RELEASE_DIR)/sbom-go-modules.json
	shasum -a 256 $(RELEASE_DIR)/timeline_$(VERSION)_*.tar.gz $(RELEASE_DIR)/timeline_$(VERSION)_*.zip $(RELEASE_DIR)/sbom-go-modules.json > $(RELEASE_DIR)/checksums.txt
	@echo "release snapshot complete: $(RELEASE_DIR)"

clean:
	rm -rf bin coverage.out .cache demo-output
