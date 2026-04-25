.PHONY: build up down logs ps restart shell-backend shell-frontend \
        dev-backend dev-frontend mock pull deploy clean reset-ports

COMPOSE = docker compose
BACKEND_CONTAINER = homelab-backend
FRONTEND_CONTAINER = homelab-frontend

# Run with mock data (no real integrations needed)
mock:
	BACKEND_MOCK=true $(COMPOSE) up -d --build

# Build all images
build:
	$(COMPOSE) build

# Start all services
up:
	$(COMPOSE) up -d

# Start with proxy + openvas profiles
up-full:
	$(COMPOSE) --profile proxy --profile openvas up -d

# Stop all services
down:
	$(COMPOSE) down

# Stop and remove volumes (destructive)
down-volumes:
	$(COMPOSE) down -v

# Stream logs
logs:
	$(COMPOSE) logs -f

logs-backend:
	$(COMPOSE) logs -f $(BACKEND_CONTAINER)

logs-frontend:
	$(COMPOSE) logs -f $(FRONTEND_CONTAINER)

# Status
ps:
	$(COMPOSE) ps

# Restart a service: make restart svc=backend
restart:
	$(COMPOSE) restart $(svc)

# Shell access
shell-backend:
	docker exec -it $(BACKEND_CONTAINER) /bin/bash

shell-frontend:
	docker exec -it $(FRONTEND_CONTAINER) /bin/sh

# Local development (no Docker)
dev-backend:
	cd backend && uvicorn main:socket_app --host 0.0.0.0 --port 8000 --reload

dev-frontend:
	cd frontend && npm run dev

# Pull latest upstream images
pull:
	$(COMPOSE) pull

# Deploy to remote server
deploy:
	bash deploy.sh

# Remove .env.bak files
clean:
	find . -name "*.bak" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# Show help
help:
	@echo "Available targets:"
	@echo "  mock           Run with mock data (no real integrations)"
	@echo "  build          Build all Docker images"
	@echo "  up             Start services"
	@echo "  up-full        Start all services including proxy/vault/openvas"
	@echo "  down           Stop services"
	@echo "  logs           Stream all logs"
	@echo "  ps             Show service status"
	@echo "  dev-backend    Run backend locally with hot-reload"
	@echo "  dev-frontend   Run frontend locally with Vite"
	@echo "  deploy         Deploy to remote server via deploy.sh"
