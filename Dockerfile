# Build stage
FROM golang:1.25 AS builder
WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /scoper ./cmd/scoper

# Runtime stage
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /scoper /scoper
USER nonroot:nonroot
ENTRYPOINT ["/scoper"]
