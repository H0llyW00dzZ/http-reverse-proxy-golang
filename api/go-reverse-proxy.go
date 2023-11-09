package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

// Define global variables to store command-line arguments.
var (
	apiTargetURL     string
	maxRequestSize   int64
	requestRateLimit float64
	concurrencyLimit int
	serverPort       int
	blockedPath      string
	certFile         string
	keyFile          string
	allowedMethods   string
)

func main() {
	// Parse command-line flags to configure the server.
	flag.StringVar(&apiTargetURL, "apiTargetURL", "https://api.github.com", "API target URL")
	// Example : 10*1024*1024 = 10 megabytes
	flag.Int64Var(&maxRequestSize, "maxRequestSize", 10*1024*1024, "Maximum request size")
	flag.Float64Var(&requestRateLimit, "requestRateLimit", 100, "Request rate limit (requests per second)")
	flag.IntVar(&concurrencyLimit, "concurrencyLimit", 10, "Concurrency limit (maximum concurrent requests)")
	flag.IntVar(&serverPort, "serverPort", 8080, "Server port")
	flag.StringVar(&blockedPath, "blockedPath", "gor00t", "Path to be blocked with a fake network response")
	flag.StringVar(&certFile, "certFile", "", "Path to the TLS certificate file")
	flag.StringVar(&keyFile, "keyFile", "", "Path to the TLS private key file")
	// eg Usage : -allowedMethods="GET,POST,PUT,DELETE"
	flag.StringVar(&allowedMethods, "allowedMethods", "GET, POST, OPTIONS", "Allowed HTTP methods for CORS requests")
	flag.Parse()

	// Create a new logger instance with the desired configuration.
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		ForceColors: true,
	})

	// Set the logger output to os.Stdout.
	logger.SetOutput(os.Stdout)

	// Initialize rate limiter and concurrency limiter based on command-line arguments.
	requestRateLimiter := rate.NewLimiter(rate.Limit(requestRateLimit), concurrencyLimit)
	concurrencyLimiter := make(chan struct{}, concurrencyLimit)

	// Set up the HTTP handler for the proxy functionality.
	http.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		// Limit the maximum request size.
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

		// Check if the request exceeds the rate limit.
		if !requestRateLimiter.Allow() {
			logger.Warnf("[Visitor] Request rate limit exceeded (User-Agent: %s)", r.UserAgent())
			http.Error(w, "Request rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// Acquire a concurrency limiter slot.
		concurrencyLimiter <- struct{}{}
		defer func() { <-concurrencyLimiter }()

		// Log the incoming request.
		logger.Infof("[Middleware] Received request: %s %s (User-Agent: %s)", r.Method, r.URL.Path, r.UserAgent())

		// Handle the request by either blocking it or proxying it.
		handleProxy(w, r, logger)
	})

	// Create a new HTTP server instance with custom TLS settings.
	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", serverPort),
		Handler:   nil, // Default ServeMux is used.
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}

	// Start the server in a new goroutine, allowing the main goroutine to listen for exit signals.
	go func() {
		if certFile != "" && keyFile != "" {
			logger.Infof("HTTPS server starting on port %d...", serverPort)
			err := server.ListenAndServeTLS(certFile, keyFile)
			if err != nil && err != http.ErrServerClosed {
				logger.Fatal(err)
			}
		} else {
			logger.Infof("HTTP server starting on port %d...", serverPort)
			err := server.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				logger.Fatal(err)
			}
		}
	}()

	// Block the main goroutine until an exit signal is received, then gracefully shut down the server.
	waitForExitSignal(server, logger)
}

// handleProxy decides whether to block the request or to proxy it to the target URL.
func handleProxy(w http.ResponseWriter, r *http.Request, logger *logrus.Logger) {
	logger.Infof("[Visitor] Received request: %s %s (User-Agent: %s)", r.Method, r.URL.Path, r.UserAgent())

	// Handle CORS requests for all paths.
	if r.Header.Get("Origin") != "" {
		// Set CORS headers.
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", allowedMethods)
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	}

	// Check if the request path matches the blocked path and lacks CORS headers.
	if strings.TrimPrefix(r.URL.Path, "/api/") == blockedPath && r.Header.Get("no-cors") == "" && r.Header.Get("cors") == "" {
		// Handle the blocked path with a custom response.
		switch r.Method {
		case http.MethodGet:
			// Send a stream of frames as a response.
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			// Define the binary animation frames
			frames := []string{
				"Hello ",
				"visitor! ",
				"This is from Golang.\n",
				"00000000 ",
				"10000000 ",
				"11000000 ",
				"11100000\n",
				"11110000 ",
				"11111000 ",
				"11111100 ",
				"11111110\n",
				"11111111 ",
				"11111110 ",
				"11111100 ",
				"11111000\n",
				"11110000 ",
				"11100000 ",
				"11000000 ",
				"10000000 ",
			}

			// Send the frames in a loop with a delay between each iteration
			for _, frame := range frames {
				time.Sleep(200 * time.Millisecond)
				if _, err := w.Write([]byte(frame)); err != nil {
					return // Stop if we cannot write to the response.
				}
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}
			}
		default:
			// Block non-GET methods. 🏴‍☠️
			logger.Warnf("[Visitor] Method not allowed for path: %s (User-Agent: %s)", r.URL.Path, r.UserAgent())
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	// If the request is not blocked, create a reverse proxy to the target URL.
	proxyURL, err := url.Parse(apiTargetURL)
	if err != nil {
		http.Error(w, "Failed to parse target URL", http.StatusInternalServerError)
		return
	}
	proxy := httputil.NewSingleHostReverseProxy(proxyURL)
	r.URL.Path = strings.TrimPrefix(r.URL.Path, "/api/")
	r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
	r.Header.Set("X-Forwarded-For", r.RemoteAddr)
	r.Host = proxyURL.Host
	proxy.ServeHTTP(w, r)
}

// waitForExitSignal listens for OS signals and triggers a graceful shutdown of the server.
func waitForExitSignal(server *http.Server, logger *logrus.Logger) {
	exitChan := make(chan os.Signal, 1)
	signal.Notify(exitChan, os.Interrupt, syscall.SIGTERM)
	<-exitChan

	// Create a context with a timeout for the server shutdown.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Attempt to gracefully shut down the server.
	logger.Info("Shutting down server...")
	if err := server.Shutdown(ctx); err != nil {
		logger.Errorf("Server shutdown error: %v", err)
	} else {
		logger.Info("Server gracefully stopped")
	}
}
