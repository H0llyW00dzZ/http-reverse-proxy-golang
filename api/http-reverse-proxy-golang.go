package main

import (
	"flag"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

var (
	apiTargetURL     string
	maxRequestSize   int64
	requestRateLimit float64
	concurrencyLimit int
)

func main() {
	// Parse command-line flags
	flag.StringVar(&apiTargetURL, "apiTargetURL", "https://api.github.com", "API target URL")
	flag.Int64Var(&maxRequestSize, "maxRequestSize", 10*1024*1024, "Maximum request size")
	flag.Float64Var(&requestRateLimit, "requestRateLimit", 100, "Request rate limit (requests per second)")
	flag.IntVar(&concurrencyLimit, "concurrencyLimit", 10, "Concurrency limit (maximum concurrent requests)")
	flag.Parse()

	// Create a new logger instance with the desired configuration.
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		ForceColors: true,
	})

	// Set the logger output to os.Stdout.
	logger.SetOutput(os.Stdout)

	// Create a rate limiter based on the request rate limit
	requestRateLimiter := rate.NewLimiter(rate.Limit(requestRateLimit), concurrencyLimit)

	// Create a semaphore for concurrency limiting
	concurrencyLimiter := make(chan struct{}, concurrencyLimit)

	// The API will be proxied to the specified target URL.
	http.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		// Set the maximum request size limit
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

		// Check if the request rate exceeds the limit
		if !requestRateLimiter.Allow() {
			http.Error(w, "Request rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// Acquire a semaphore slot
		concurrencyLimiter <- struct{}{}
		defer func() { <-concurrencyLimiter }()

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
