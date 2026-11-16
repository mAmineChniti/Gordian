# Simple Makefile for a Go project

# Build the application
all: build

build:
	@echo "Building..."
	@CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o main ./cmd/api

# Run the application
run:
	@go run ./cmd/api

# Run the test suite with the race detector
test:
	@echo "Testing..."
	@go test -race ./...

# Run integration tests (requires MONGODB_URI to point at a disposable database)
itest:
	@echo "Running integration tests..."
	@go test -race -tags=integration ./internal/database -v

# Static checks
vet:
	@go vet ./...

fmt:
	@test -z "$$(gofmt -l .)" || (echo "Files need formatting:"; gofmt -l .; exit 1)

# Vulnerability scan. Known unfixed Echo advisories are allow-listed in the script.
vuln:
	@./scripts/govulncheck.sh

# Regenerate Swagger documentation
swagger:
	@go run github.com/swaggo/swag/cmd/swag@v1.16.6 init -g cmd/api/main.go -o docs

# Build the production Docker image
docker-build:
	@docker build --target prod -t gordian .

# Run the production image with the local .env file
docker-run:
	@test -f .env || (echo "Missing .env; copy .env.example and configure it first"; exit 1)
	@port="$${PORT:-10000}"; docker run --rm --env-file .env -e PORT="$$port" -p "$$port:$$port" gordian

# Clean the binary
clean:
	@echo "Cleaning..."
	@rm -f main

# Live Reload
watch:
	@if command -v air > /dev/null; then \
            air; \
            echo "Watching...";\
        else \
            read -p "Go's 'air' is not installed on your machine. Do you want to install it? [Y/n] " choice; \
            if [ "$$choice" != "n" ] && [ "$$choice" != "N" ]; then \
                go install github.com/air-verse/air@latest; \
                air; \
                echo "Watching...";\
            else \
                echo "You chose not to install air. Exiting..."; \
                exit 1; \
            fi; \
        fi

.PHONY: all build run test itest vet fmt vuln swagger clean watch docker-build docker-run
