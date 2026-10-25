# `make` builds every binary and the card README into dist/.
# Copy the whole dist/ folder to the SD card.

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GO      ?= go
DIST    := dist
BUILD   := build
LDFLAGS := -s -w -X main.version=$(VERSION)
GOBUILD := CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)'

.PHONY: all dist windows macos linux readme test clean

all: dist

dist: test windows macos linux readme
	@echo
	@ls -lh $(DIST)

windows:
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(DIST)/vault-windows.exe .

# One universal file when lipo is available (macOS), otherwise one per arch.
macos:
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BUILD)/vault-macos-arm64 .
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BUILD)/vault-macos-amd64 .
	@mkdir -p $(DIST)
	@if command -v lipo >/dev/null 2>&1; then \
		lipo -create -output $(DIST)/vault-macos $(BUILD)/vault-macos-arm64 $(BUILD)/vault-macos-amd64 && \
		echo "lipo: $(DIST)/vault-macos (arm64 + amd64)" && \
		codesign --force --sign - --identifier sd-vault $(DIST)/vault-macos; \
	else \
		cp $(BUILD)/vault-macos-arm64 $(BUILD)/vault-macos-amd64 $(DIST)/; \
	fi

linux:
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(DIST)/vault-linux-amd64 .
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(DIST)/vault-linux-arm64 .

readme:
	@mkdir -p $(DIST)
	cp README-card.txt $(DIST)/README.txt

test:
	$(GO) test ./...

clean:
	rm -rf $(DIST) $(BUILD)
