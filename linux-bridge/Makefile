SHELL := /bin/sh
GO ?= go
VERSION ?= 0.1.0
DIST := dist

.PHONY: all test build package package-amd64 package-arm64 clean

all: test build

test:
	$(GO) test ./... -count=1 -timeout 120s

build:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -buildvcs=false -ldflags "-s -w -X main.version=$(VERSION)" -o $(DIST)/whitedns-bridge-linux-amd64 ./cmd/whitedns-bridge
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -buildvcs=false -ldflags "-s -w -X main.version=$(VERSION)" -o $(DIST)/whitedns-bridge-linux-arm64 ./cmd/whitedns-bridge

define package_arch
	rm -rf $(DIST)/whitedns-bridge-$(VERSION)-linux-$(1)
	mkdir -p $(DIST)/whitedns-bridge-$(VERSION)-linux-$(1)/licenses
	cp $(DIST)/whitedns-bridge-linux-$(1) $(DIST)/whitedns-bridge-$(VERSION)-linux-$(1)/
	cp packaging/install.sh packaging/whitedns-bridge.service README.md README.fa.md LICENSE NOTICE $(DIST)/whitedns-bridge-$(VERSION)-linux-$(1)/
	cp third_party/soar/LICENSE $(DIST)/whitedns-bridge-$(VERSION)-linux-$(1)/licenses/Soar-LICENSE.txt
	cp third_party/soar/README.md $(DIST)/whitedns-bridge-$(VERSION)-linux-$(1)/licenses/Soar-README.md
	cp third_party/soar/WHITEDNS_CHANGES.md $(DIST)/whitedns-bridge-$(VERSION)-linux-$(1)/licenses/Soar-WHITEDNS_CHANGES.md
	cp third_party/soar/data/THIRD_PARTY.md $(DIST)/whitedns-bridge-$(VERSION)-linux-$(1)/licenses/Soar-data-THIRD_PARTY.md
	chmod 0755 $(DIST)/whitedns-bridge-$(VERSION)-linux-$(1)/whitedns-bridge-linux-$(1)
	chmod 0755 $(DIST)/whitedns-bridge-$(VERSION)-linux-$(1)/install.sh
	chmod 0644 $(DIST)/whitedns-bridge-$(VERSION)-linux-$(1)/whitedns-bridge.service
	chmod 0644 $(DIST)/whitedns-bridge-$(VERSION)-linux-$(1)/README.md $(DIST)/whitedns-bridge-$(VERSION)-linux-$(1)/README.fa.md $(DIST)/whitedns-bridge-$(VERSION)-linux-$(1)/LICENSE $(DIST)/whitedns-bridge-$(VERSION)-linux-$(1)/NOTICE
	chmod 0644 $(DIST)/whitedns-bridge-$(VERSION)-linux-$(1)/licenses/*
	cd $(DIST) && tar --owner=0 --group=0 -czf whitedns-bridge-$(VERSION)-linux-$(1).tar.gz whitedns-bridge-$(VERSION)-linux-$(1)
endef

package: package-amd64 package-arm64

package-amd64: build
	$(call package_arch,amd64)

package-arm64: build
	$(call package_arch,arm64)

clean:
	rm -rf $(DIST)
