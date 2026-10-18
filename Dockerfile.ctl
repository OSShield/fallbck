# syntax=docker/dockerfile:1
# fallbck-ctl: admin CLI. Authenticate with FALLBCK_API_KEY (created in the Web UI).
# Built by GoReleaser (dockers_v2) from the prebuilt $TARGETPLATFORM/fallbck-ctl.

FROM alpine:3.24

RUN apk add --no-cache ca-certificates tzdata

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/fallbck-ctl /usr/local/bin/fallbck-ctl

ENV FALLBCK_SERVER_URL=http://fallbck-server:8080

ENTRYPOINT ["/usr/local/bin/fallbck-ctl"]
