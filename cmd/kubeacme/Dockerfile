FROM golang:alpine AS builder

ARG BASE="github.com/prep"
ARG MODULE="$BASE/kubeacme"

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
RUN go build -o /go/bin/main \
    -ldflags "-s -w -X main.CommitHash=`git rev-parse --short HEAD` -X main.Revision=`git rev-list --count HEAD`" \
    ./cmd/kubeacme && go clean -cache -testcache -fuzzcache

###############################################################################

FROM scratch

# Copy the certificates and binary over.
COPY --link --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --link --from=builder /go/bin/main /go/bin/main

EXPOSE 8080
ENTRYPOINT ["/go/bin/main"]