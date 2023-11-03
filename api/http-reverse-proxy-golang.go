package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

var (
	apiTargetURL     string
	maxRequestSize   int64
	requestRateLimit float64
	concurrencyLimit int
	serverPort       int
	blockedPath      string
	certFile         string
	keyFile          string
)

func main() {
	// Parse command-line flags
	flag.StringVar(&apiTargetURL, "apiTargetURL", "https://api.github.com", "API target URL")
	flag.Int64Var(&maxRequestSize, "maxRequestSize", 10*1024*1024, "Maximum request size")
	flag.Float64Var(&requestRateLimit, "requestRateLimit", 100, "Request rate limit (requests per second)")
	flag.IntVar(&concurrencyLimit, "concurrencyLimit", 10, "Concurrency limit (maximum concurrent requests)")
	flag.IntVar(&serverPort, "serverPort", 8080, "Server port")
	flag.StringVar(&blockedPath, "blockedPath", "/api/gor00t", "Path to be blocked with a fake network response")
	flag.StringVar(&certFile, "certFile", "", "Path to the TLS certificate file")
	flag.StringVar(&keyFile, "keyFile", "", "Path to the TLS private key file")
	flag.Parse()

	// Create a new logger instance with the desired configuration.
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		ForceColors: true,
	})

	// Set the logger output to os.Stdout.
	logger.SetOutput(os.Stdout)

	// Log the starting of the HTTP server
	logger.Info("Starting HTTP server ...")

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
			logger.Warnf("[Visitor] Request rate limit exceeded (User-Agent: %s)", r.UserAgent())
			http.Error(w, "Request rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// Acquire a semaphore slot
		concurrencyLimiter <- struct{}{}
		defer func() { <-concurrencyLimiter }()

		// Handle the request
		handleProxy(w, r, logger)
	})

	// Create a server instance with custom settings
	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", serverPort),
		Handler:   nil, // Use default handler (Mux)
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}

	// Start the server with or without TLS
	if certFile != "" && keyFile != "" {
		logger.Infof("HTTPS server started successfully on port %d", serverPort)
		err := server.ListenAndServeTLS(certFile, keyFile)
		if err != nil {
			logger.Error(err)
		}
	} else {
		logger.Infof("HTTP server started successfully on port %d", serverPort)
		err := server.ListenAndServe()
		if err != nil {
			logger.Error(err)
		}
	}

	// Wait for a signal to exit
	waitForExitSignal()
}

func handleProxy(w http.ResponseWriter, r *http.Request, logger *logrus.Logger) {
	logger.Infof("[Visitor] : Received request: %s %s (User-Agent: %s)", r.Method, r.URL.Path, r.UserAgent())

	// Add your custom logic here to send a fake network response to the client
	// when there is an incoming connection from the client.
	if r.Method == http.MethodGet && r.URL.Path == blockedPath && (r.Header.Get("no-cors") == "" && r.Header.Get("cors") == "") {
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
			time.Sleep(200 * time.Millisecond) // Adjust the delay as needed
			w.Write([]byte(frame))
			w.(http.Flusher).Flush()
		}

		return
	}

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

func waitForExitSignal() {
	// Wait for a signal to exit (e.g., Ctrl+C)
	exitChan := make(chan os.Signal, 1)
	signal.Notify(exitChan, os.Interrupt, syscall.SIGTERM)
	<-exitChan
}
