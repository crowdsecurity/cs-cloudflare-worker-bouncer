ARG GOVERSION=1.21.5

# Stage 1: Build stage
FROM golang:${GOVERSION}-alpine AS build

WORKDIR /go/src/cs-cloudflare-worker-bouncer

RUN apk add --update --no-cache make git
COPY . .

# Run make build to compile the Go application
RUN make build

# Stage 2: Final stage
FROM alpine:latest

# Copy the compiled binary and configuration file from the build stage
COPY --from=build /go/src/cs-cloudflare-worker-bouncer/crowdsec-cloudflare-worker-bouncer-*/crowdsec-cloudflare-worker-bouncer /usr/local/bin/crowdsec-cloudflare-worker-bouncer
COPY --from=build /go/src/cs-cloudflare-worker-bouncer/config/crowdsec-cloudflare-worker-bouncer.yaml /etc/crowdsec/bouncers/crowdsec-cloudflare-worker-bouncer.yaml

# Define the entrypoint for the container
ENTRYPOINT ["/usr/local/bin/crowdsec-cloudflare-worker-bouncer", "-c", "/etc/crowdsec/bouncers/crowdsec-cloudflare-worker-bouncer.yaml"]
