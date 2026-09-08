.PHONY: all build test lint boundaries repro golden check clean

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

# Everything CI runs. Run this before every commit.
check: boundaries lint test build repro

clean:
	rm -rf bin dist
