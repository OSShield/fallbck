
ifndef BVERSION
BVERSION := $(shell read -p "Enter version to build: " v < /dev/tty > /dev/tty && echo $$v)
endif


ifndef GITHUB_TOKEN
ifndef GITEA_TOKEN
$(error GITHUB_TOKEN and GITEA_TOKEN are not set. Please set it in the environment or in a .env file)
endif
endif

.PHONY: binary helm


all: binary helm

# also builds and pushes the oci.fi/fallbck/* images (dockers_v2)
binary:
	@echo "Building binaries and images for version $(BVERSION)"
	git tag -a "v$(BVERSION)" -m "Release v$(BVERSION)" && \
	goreleaser release --clean && \
	git push github main v$(BVERSION)

helm:
	@echo "Building helm chart for version $(BVERSION)"
	helm package deploy/helm/fallbck-k8s-agent --version $(BVERSION) --app-version $(BVERSION) && \
	helm push fallbck-k8s-agent-$(BVERSION).tgz oci://oci.fi/helm
