.PHONY: all build test lint boundaries repro golden golden-update check clean

all: check

build:
	go build -trimpath -o bin/substrate ./cmd/substrate

test:
	go test ./... -race -count=1

lint:
	go vet ./...

boundaries:
	./scripts/check-boundaries.sh

repro: build
	./scripts/check-reproducible.sh

golden:
	go test ./... -run TestGolden -count=1

# Deliberately regenerate golden fixtures. Never run this to silence a
# failure without reading the diff first - that diff is a change in
# what we assert to the federal government.
golden-update:
	SUBSTRATE_UPDATE_GOLDEN=1 go test ./... -run TestGolden -count=1 -v

# Everything CI runs. Run this before every commit.
check: boundaries lint test build repro

clean:
	rm -rf bin dist
