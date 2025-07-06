FROM golang:alpine AS builder

ARG BASE="github.com/prep"
ARG MODULE="$BASE/kubeacme"

ARG COMMIT_HASH="unknown"
ARG REVISION="0"

WORKDIR $GOPATH/src/$MODULE

# Install the required tools.
RUN apk add --update --no-cache git

# Copy the go.mod and go.sum files first. This approach leverages Docker caching.
COPY --link go.mod go.sum ./

# Download the Go modules.
RUN go mod download

# Copy the code into the container.
COPY --link . .

# Build the binary.
ENV CGO_ENABLED=0
RUN go build -o /go/bin/main \
    -ldflags "-s -w -X main.CommitHash=${COMMIT_HASH} -X main.Revision=${REVISION}" \
    ./cmd/kubeacme && go clean -cache -testcache -fuzzcache

###############################################################################

FROM scratch

# Copy the certificates and binary over.
COPY --link --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --link --from=builder /go/bin/main /kubeacme

EXPOSE 8080
ENTRYPOINT ["/kubeacme"]