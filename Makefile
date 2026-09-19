
ifndef BVERSION
BVERSION := $(shell read -p "Enter version to build: " v < /dev/tty > /dev/tty && echo $$v)
endif


ifndef GITHUB_TOKEN
  ifndef GITEA_TOKEN
	$(error GITHUB_TOKEN and GITEA_TOKEN are not set. Please set it in the environment or in a .env file)
  endif
endif

.PHONY: binary docker helm


all: binary docker helm

docker:
	@echo "Building containers for version $(BVERSION)"
	cd deploy && \
	FALLBCK_VERSION=$(BVERSION) docker compose build --no-cache --pull && \
	FALLBCK_VERSION=$(BVERSION) docker compose --profile=k8s build --no-cache --pull && \
	FALLBCK_VERSION=$(BVERSION) docker compose --profile=db-agent build --no-cache --pull && \
	docker compose push && \
	docker compose --profile=k8s push && \
	docker compose --profile=db-agent push

binary:
	@echo "Building binary for version $(BVERSION)"
	git tag -a "v$(BVERSION)" -m "Release v$(BVERSION)" && \
	goreleaser release --clean

helm:
	@echo "Building helm chart for version $(BVERSION)"
	helm package deploy/helm/fallbck-k8s-agent --version $(BVERSION) --app-version $(BVERSION) && \
	helm push fallbck-k8s-agent-$(BVERSION).tgz oci://oci.fi/helm