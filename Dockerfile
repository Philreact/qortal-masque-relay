# syntax=docker/dockerfile:1

FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/qortal-masque-relay ./cmd/qortal-masque-relay

FROM python:3.12-slim-bookworm
RUN pip install --no-cache-dir rns==1.5.2 \
    && useradd --system --uid 10001 --create-home relay \
    && mkdir -p /data/relay /data/reticulum \
    && chown -R relay:relay /data
COPY --from=build /out/qortal-masque-relay /usr/local/bin/qortal-masque-relay
COPY scripts/masque_relay_discovery.py /usr/local/lib/qortal/masque_relay_discovery.py
COPY scripts/masque_discovery_codec.py /usr/local/lib/qortal/masque_discovery_codec.py
USER relay
VOLUME ["/data/relay", "/data/reticulum"]
ENTRYPOINT ["qortal-masque-relay", "--python", "python3", "--discovery-script", "/usr/local/lib/qortal/masque_relay_discovery.py"]
