# Dev entrypoints. Everything a reviewer needs lives in `make up`.
#
# Requirements: Docker (compose v2.20+ for the observability overlay),
# uv (https://docs.astral.sh/uv/) for `make test`, openssl for key
# generation (Git Bash ships it; ship without if you create .env yourself).

COMPOSE           = docker compose
COMPOSE_OBS       = $(COMPOSE) -f docker-compose.observability.yml
COMPOSE_PROD      = $(COMPOSE) -f docker-compose.prod.yml

.PHONY: help up down test metrics logs prod-up prod-down clean

help:             ## list targets
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*## "}; {printf "  %-10s %s\n", $$1, $$2}'

up: .env          ## start Redis + API on loopback (creates .env with fresh secrets if missing)
	$(COMPOSE) up -d --build
	@echo ""
	@echo "  API      http://127.0.0.1:8000"
	@echo "  Swagger  http://127.0.0.1:8000/docs"

down:             ## stop the base stack
	$(COMPOSE) down

test: .env        ## run the test suite against the running dev Redis (starts it if needed)
	$(COMPOSE) up -d redis
	uv run pytest -q

metrics:          ## add Prometheus + Grafana, dashboard pre-provisioned (includes base stack)
	$(COMPOSE_OBS) up -d
	@echo ""
	@echo "  Grafana    http://127.0.0.1:3000  (opens straight onto the CAPTCHA dashboard)"
	@echo "  Prometheus http://127.0.0.1:9090"

logs:             ## tail API logs
	$(COMPOSE) logs -f api

prod-up: .env     ## start the production-shaped overlay (requires CAPTCHA_REDIS_PASSWORD in .env)
	$(COMPOSE_PROD) up -d --build

prod-down:
	$(COMPOSE_PROD) down

clean:            ## stop stacks and remove their containers and volumes
	$(COMPOSE) down -v
	$(COMPOSE_OBS) down -v

# First clone -> working .env: sample copied, both placeholder secrets
# above matches each secret by its variable name, giving the internal
# API key and the JWT secret two DIFFERENT generated values. Edit .env
# by hand if you'd rather.
.env: .env.sample
	@cp .env.sample .env
	@sed -i "s/^\(CAPTCHA_INTERNAL_API_KEY=\).*/\1$$(openssl rand -hex 32)/" .env
	@sed -i "s/^\(CAPTCHA_JWT_SECRET=\).*/\1$$(openssl rand -hex 32)/" .env
	@echo "Generated .env with two different fresh random secrets (rotate whenever)."
