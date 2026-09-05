.PHONY: all docker binary

all: read-version docker binary

read-version:
	@read -p "Enter version to build: " VERSION && echo $$VERSION

docker: read-version
    cd deploy && \
		FALLBCK_VERSION=$$VERSION docker compose build --no-cache --pull && \
		FALLBCK_VERSION=$$VERSION docker compose --profile=k8s build --no-cache --pull && \
		docker compose push && \
		docker compose --profile=k8s push

	@echo $$VERSION

binary: read-version
	git tag -a $$VERSION -m "Release $$VERSION" && \
	goreleaser release --clean
