FROM golang:1.26.10-alpine@sha256:9ce231b28998b32e116927c61aa5c406183061d4f3f2d61b292c88e7f6bdf7ca AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=secret,id=demo_ca \
    if [ -s /run/secrets/demo_ca ]; then cat /run/secrets/demo_ca >> /etc/ssl/certs/ca-certificates.crt; fi \
    && go mod download
COPY main.go ./
COPY cmd/ cmd/
COPY internal/ internal/

FROM hashicorp/vault:1.19.4@sha256:b5f675b0bf681568cd7354c697fe4ce953024312d6d23ee7216deda60c192bad AS vault
FROM postgres:16-bookworm@sha256:bb3e1a57e5407e0a5280b4211980a5e537f4abd234a87014ac979849a78dd825
COPY --from=vault /bin/vault /usr/local/bin/vault
COPY --from=build /usr/local/go /usr/local/go
COPY --from=build --chown=postgres:postgres /go/pkg/mod /go/pkg/mod
COPY --from=build --chown=postgres:postgres /src /src
COPY --chown=postgres:postgres examples/ /src/examples/
ENV PATH="/usr/local/go/bin:${PATH}" GOMODCACHE=/go/pkg/mod GOCACHE=/tmp/go-build GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local CGO_ENABLED=0
USER postgres
WORKDIR /src
ENTRYPOINT ["bash", "/src/examples/credential-proxy/demo.sh"]
