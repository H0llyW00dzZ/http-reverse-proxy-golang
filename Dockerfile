# Use the official Golang image to create a build artifact.
# This is based on Debian and sets the GOPATH to /go.
# https://hub.docker.com/_/golang
FROM golang:1.21.3 as builder

# Create and change to the app directory.
WORKDIR /api

# Retrieve application dependencies.
# This allows the container build to reuse cached dependencies.
COPY go.mod go.sum ./
RUN go mod download

# Copy local code to the container image.
COPY . .

# Build the binary.
RUN CGO_ENABLED=0 GOOS=linux go build -mod=readonly -v -o /go/bin/http-reverse-proxy-golang

# Use the Google Distroless image for a minimal container.
FROM gcr.io/distroless/static

# Copy the binary to the production image from the builder stage.
COPY --from=builder /go/bin/http-reverse-proxy-golang /

# Run the binary on container startup.
CMD ["/http-reverse-proxy-golang"]
