FROM golang:1.26.10-alpine@sha256:9ce231b28998b32e116927c61aa5c406183061d4f3f2d61b292c88e7f6bdf7ca AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=secret,id=build_ca \
    if [ -s /run/secrets/build_ca ]; then cat /run/secrets/build_ca >> /etc/ssl/certs/ca-certificates.crt; fi \
    && go mod download
COPY main.go ./
COPY cmd/ cmd/
COPY internal/ internal/
COPY examples/playground/app/ examples/playground/app/
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 go build -trimpath -o /agent-vault . \
    && CGO_ENABLED=0 go build -trimpath -o /playground ./examples/playground/app
FROM hashicorp/vault:1.19.4@sha256:b5f675b0bf681568cd7354c697fe4ce953024312d6d23ee7216deda60c192bad AS vault
FROM postgres:16-bookworm@sha256:bb3e1a57e5407e0a5280b4211980a5e537f4abd234a87014ac979849a78dd825
COPY --from=vault /bin/vault /usr/local/bin/vault
COPY --from=build /agent-vault /playground /usr/local/bin/
RUN useradd --uid 65532 --home-dir /root --no-create-home playground \
    && mkdir -p /state /public /audit /inbox /status /control /story /root \
    && for role in operator database broker vault relay payments logs attacker baseline sandbox; do mkdir -p /state/$role; done \
    && chown -R 65532:65532 /state /public /audit /inbox /status /control /story /root \
    && chmod 700 /root \
    && ln -s /usr/local/bin/playground /usr/local/bin/request
USER 65532:65532
WORKDIR /root
ENTRYPOINT ["playground"]
