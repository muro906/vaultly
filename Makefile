.DEFAULT_GOAL := help

COMPOSE ?= docker compose
BACKEND  := backend
FRONTEND := frontend

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

## --- Local stack ----------------------------------------------------------

.PHONY: up
up: ## Start the full stack (postgres + api + web) in the background
	$(COMPOSE) up -d --build

.PHONY: down
down: ## Stop the stack
	$(COMPOSE) down

.PHONY: clean
clean: ## Stop the stack and delete its data volume
	$(COMPOSE) down -v

.PHONY: logs
logs: ## Tail logs from all services
	$(COMPOSE) logs -f

.PHONY: db
db: ## Start only PostgreSQL (for running the API on the host)
	$(COMPOSE) up -d postgres

## --- Backend --------------------------------------------------------------

.PHONY: run
run: ## Run the API on the host
	cd $(BACKEND) && go run ./cmd/api

.PHONY: migrate
migrate: ## Apply all pending database migrations
	cd $(BACKEND) && go run ./cmd/migrate up

.PHONY: migrate-down
migrate-down: ## Roll back the most recent migration
	cd $(BACKEND) && go run ./cmd/migrate down 1

.PHONY: sqlc
sqlc: ## Regenerate type-safe query code from internal/db/queries
	cd $(BACKEND) && go tool sqlc generate

.PHONY: test
test: ## Run backend unit tests and frontend tests
	cd $(BACKEND) && go test ./...
	cd $(FRONTEND) && npm test -- --run

.PHONY: test-integration
test-integration: ## Run backend integration tests (starts a throwaway PostgreSQL container)
	cd $(BACKEND) && go test -tags=integration -count=1 ./...

.PHONY: lint
lint: ## Vet the backend and type-check the frontend
	cd $(BACKEND) && go vet ./...
	cd $(FRONTEND) && npx tsc --noEmit

.PHONY: fmt
fmt: ## Format Go sources
	cd $(BACKEND) && go fmt ./...

## --- Frontend -------------------------------------------------------------

.PHONY: web
web: ## Run the Next.js dev server on the host
	cd $(FRONTEND) && npm run dev

.PHONY: build
build: ## Production-build both applications
	cd $(BACKEND) && go build -o bin/api ./cmd/api
	cd $(FRONTEND) && npm run build

## --- Helpers --------------------------------------------------------------

.PHONY: keys
keys: ## Print a freshly generated master key and JWT secret
	@echo "VAULTLY_MASTER_KEY=$$(openssl rand -base64 32)"
	@echo "JWT_SECRET=$$(openssl rand -base64 48)"
