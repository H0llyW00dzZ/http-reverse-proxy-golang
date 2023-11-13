# Use the official Golang image to create a build artifact.
# This is based on Debian and sets the GOPATH to /go.
# https://hub.docker.com/_/golang
FROM golang:1.21.3 as builder

# Create and change to the app directory.
WORKDIR /api/

# Retrieve application dependencies.
# This allows the container build to reuse cached dependencies.
COPY go.mod go.sum ./
RUN go mod download

# Copy local code to the container image.
COPY . .

# Build the binary.
RUN CGO_ENABLED=0 GOOS=linux go build -mod=readonly -v -o /go/bin/go-reverse-proxy

# Use a minimal base image for the final container.
FROM scratch

# Copy the binary to the production image from the builder stage.
COPY --from=builder /go/bin/go-reverse-proxy /

# Run the binary on container startup.
CMD ["/go-reverse-proxy"]
