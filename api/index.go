package main

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

var (
	apiTargetURL     string = "https://api.github.com"              // Set the default target URL here
	maxRequestSize   int64  = 10 * 1024 * 1024                      // 10 MB
	requestRateLimit        = rate.NewLimiter(rate.Limit(100), 100) // 100 requests per second
	concurrencyLimit        = make(chan struct{}, 10)               // 10 concurrent requests
)

func main() {
	// Create a new logger instance with the desired configuration.
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		ForceColors: true,
	})

	// Set the logger output to os.Stdout.
	logger.SetOutput(os.Stdout)

	// The API will be proxied to the specified target URL.
	http.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		// Set the maximum request size limit
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

		// Check if the request rate exceeds the limit
		if !requestRateLimit.Allow() {
			http.Error(w, "Request rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// Acquire a semaphore slot
		concurrencyLimit <- struct{}{}
		defer func() { <-concurrencyLimit }()

		// Handle the request
		handleProxy(w, r, logger)
	})

	// Start the server.
	logger.Info("Starting HTTP server ...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		logger.Error(err)
	}
}

func handleProxy(w http.ResponseWriter, r *http.Request, logger *logrus.Logger) {
	logger.Infof("Received request: %s %s", r.Method, r.URL.Path)

	// Create a new reverse proxy.
	proxyURL, err := url.Parse(apiTargetURL)
	if err != nil {
		http.Error(w, "Failed to parse target URL", http.StatusInternalServerError)
		return
	}
	proxy := httputil.NewSingleHostReverseProxy(proxyURL)

	// Modify the request's URL to remove the "/api" prefix.
	r.URL.Path = r.URL.Path[len("/api"):]

	// Set the necessary headers for the proxy.
	r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
	r.Header.Set("X-Forwarded-For", r.RemoteAddr)
	r.Host = proxyURL.Host

	// Proxy the request.
	proxy.ServeHTTP(w, r)
}
