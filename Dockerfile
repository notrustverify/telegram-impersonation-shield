FROM golang:1.20-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY *.go ./

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o /username-detector

# Use a minimal alpine image
FROM alpine:latest

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /username-detector /app/username-detector

# Copy the usernames file
COPY usernames.txt /app/usernames.txt

# Copy .env.example for reference
COPY .env.example /app/.env.example

# Run the binary
CMD ["/app/username-detector"] 