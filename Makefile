# ubi-gs: one static binary per platform, no cgo.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64 windows/amd64 darwin/arm64 darwin/amd64
GO ?= go

.PHONY: build all test race fuzz conformance vet clean

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o ubi-gs ./cmd/ubi-gs

all:
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		out=dist/ubi-gs-$$os-$$arch$$ext; \
		echo "$$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $$out ./cmd/ubi-gs || exit 1; \
	done

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...
	@test -z "$$(gofmt -l .)" || (gofmt -l .; exit 1)

# each fuzz target for FUZZTIME
FUZZTIME ?= 15s
fuzz:
	@for t in dl:FuzzDecode gsm:FuzzDecode crypto:FuzzXOR crypto:FuzzBlowfishDecrypt h5:FuzzRoomInfo h5:FuzzPlayerInfo \
		srp:FuzzParse nat:FuzzPacket cdkey:FuzzParse irc:FuzzSanitizeChat proxy:FuzzDecodeProfile; do \
		pkg=$${t%%:*}; fn=$${t#*:}; \
		$(GO) test ./internal/$$pkg -run '^$$' -fuzz "^$$fn$$" -fuzztime $(FUZZTIME) || exit 1; \
	done

# needs the Python ubi-gs: make conformance UBIGS_REF=../ubi-gs UBIGS_PYTHON=../ubi-gs/.venv/bin/python
conformance:
	UBIGS_REF=$(UBIGS_REF) UBIGS_PYTHON=$(UBIGS_PYTHON) $(GO) test -v -count=1 ./tests/conformance

clean:
	rm -rf ubi-gs dist
