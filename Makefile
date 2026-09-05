
ifndef BVERSION
BVERSION := $(shell read -p "Enter version to build: " v < /dev/tty > /dev/tty && echo $$v)
endif

.PHONY: all docker binary


all: docker binary

docker:
	cd deploy && \
	FALLBCK_VERSION=$(BVERSION) docker compose build --no-cache --pull && \
	FALLBCK_VERSION=$(BVERSION) docker compose --profile=k8s build --no-cache --pull && \
	docker compose push && \
	docker compose --profile=k8s push

binary:
	@echo "Building binary for version $(BVERSION)"
	git tag -a "v$(BVERSION)" -m "Release v$(BVERSION)" && \
	goreleaser release --clean
