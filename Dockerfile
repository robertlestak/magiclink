FROM golang:1.24.3-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o magiclink ./cmd/server

# Use a small image for the final stage
FROM alpine:3.17

RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/magiclink .

# Copy the web UI files
COPY --from=builder /app/web /app/web

# Expose HTTP
EXPOSE 8080

# Set default environment variables
ENV HTTP_ADDR=:8080
ENV LOG_LEVEL=info

# Run the service
ENTRYPOINT ["/app/magiclink"]