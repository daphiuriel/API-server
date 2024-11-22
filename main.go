package main

import (
    "bytes"
	"encoding/json"
	"strings"
    "time"
	"log"        // For logging errors or messages
	"net/http"   // For creating the HTTP server
	"os"         // For reading environment variables
	"github.com/joho/godotenv" // For loading .env files
	"api_sec"    // Import your package where the API functions are defined
)

// Log middleware to capture request and response
func logRequestAndResponse(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Step 1: Capture request data
		reqBodyLen := r.ContentLength
		reqHeaders := r.Header
		reqURL := r.URL.String()
		reqQueryParams := r.URL.RawQuery

		// Step 2: Capture response data using custom ResponseWriter
		resRecorder := &responseRecorder{ResponseWriter: w}
		next(resRecorder, r)

		// Determine the status class based on the response code
		statusClass := getStatusClass(resRecorder.statusCode)

		// Prepare the log data in the required JSON format
		logData := map[string]interface{}{
			"req": map[string]interface{}{
				"url":          reqURL,
				"qs_params":    reqQueryParams,
				"headers":      reqHeaders,
				"req_body_len": reqBodyLen,
			},
			"rsp": map[string]interface{}{
				"status_class": statusClass,
				"rsp_body_len": resRecorder.bodyLen,
			},
		}

		// Step 3: Write log to a file (access.log)
		logFile, err := os.OpenFile("access.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
		if err != nil {
			log.Fatal("Error opening log file:", err)
		}
		defer logFile.Close()

		// Log in JSON format
		log.SetOutput(logFile)
		logJSON, err := json.Marshal(logData)
		if err != nil {
			log.Println("Error marshalling log data:", err)
		} else {
			log.Println(string(logJSON)) // Output log to file
		}
	}
}

// Custom response recorder to capture response status and body length
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	bodyLen    int
}

func (rw *responseRecorder) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *responseRecorder) Write(p []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(p)
	rw.bodyLen += n
	return n, err
}

// Determine the status class based on the status code
func getStatusClass(statusCode int) string {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return "2xx"
	case statusCode >= 300 && statusCode < 400:
		return "3xx"
	case statusCode >= 400 && statusCode < 500:
		return "4xx"
	case statusCode >= 500 && statusCode < 600:
		return "5xx"
	default:
		return "unknown"
	}
}

func main() {
    // Step 1: Load environment variables
    // .env file typically contains sensitive keys like JWT_SECRET.
    // This step loads them so we can use them in the application.
    err := godotenv.Load()
    if err != nil {
        log.Println("No .env file found")
    }

    // Step 2: Define the API routes
    // Use `http.HandleFunc` to map each endpoint (URL) to its respective function.
    http.HandleFunc("/register", logRequestAndResponse(api_sec.Register)) // Maps /register to Register function
    http.HandleFunc("/login", logRequestAndResponse(api_sec.Login)) // Maps /login to Login function

    // Step 3: Secure routes using middleware
    // Middleware wraps the route handlers and adds extra functionality like authentication.
    http.HandleFunc("/accounts", logRequestAndResponse(api_sec.Auth(api_sec.AccountsHandler))) // Protects /accounts
    http.HandleFunc("/balance", logRequestAndResponse(api_sec.Auth(api_sec.BalanceHandler))) // Protects /balance

    // Step 4: Start the HTTP server
    // This listens on port 8080 (as specified in the examples) and serves the API.
    log.Println("Starting server on http://localhost:8080")
    err = http.ListenAndServe(":8080", nil) // Start the server on port 8080
    if err != nil {
        log.Fatal("Server failed to start:", err)
    }
}
