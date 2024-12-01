# this dockerfile should be built from the root of the repository like:
# docker build . -f cmd/tunnel-server/Dockerfile
FROM golang:1.23-bullseye AS builder
WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build the application
RUN go build -o /opt/tunnel-server ./cmd/tunnel-server

# Use a minimal image for running the application
FROM debian:bullseye-slim

# Copy the compiled binary
COPY --from=builder /opt/tunnel-server /opt/tunnel-server

# Command to run the binary
CMD ["/opt/tunnel-server"]
