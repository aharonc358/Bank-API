package middleware

import (
	"encoding/json"
	models "f5_proj/models"
	"log"
	"net/http"
	"os"
	"time"
)

var logFile *os.File

func InitLogFile(filePath string) error {
	var err error
	logFile, err = os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	return nil
}

func headersToString(headers http.Header) string {
	var result string
	for key, values := range headers {
		for _, value := range values {
			result += key + ": " + value + "\n"
		}
	}
	return result
}

func LogRequestResponse(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		rec := &responseRecorder{ResponseWriter: w}

		reqURL := r.URL.String()
		qParams := r.URL.Query().Encode()
		headers := headersToString(r.Header)
		reqBodyLen := r.ContentLength

		next.ServeHTTP(rec, r)
		duration := time.Since(start)

		statusClass := "2xx"
		if rec.statusCode >= 400 && rec.statusCode < 500 {
			statusClass = "4xx"
		} else if rec.statusCode >= 500 {
			statusClass = "5xx"
		}

		logEntry := models.LogEntry{
			Req: models.RequestLog{
				URL:        reqURL,
				QSParams:   qParams,
				Headers:    headers,
				ReqBodyLen: reqBodyLen,
			},
			Rsp: models.ResponseLog{
				StatusClass: statusClass,
				RspBodyLen:  rec.size,
			},
		}

		log.Printf("Request to %s completed in %v", reqURL, duration)
		logJSON, err := json.Marshal(logEntry)
		if err != nil {
			log.Printf("Error marshaling log entry: %v", err)
			return
		}

		logFile.WriteString(string(logJSON) + "\n")
	})
}

type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	size       int
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *responseRecorder) Write(p []byte) (n int, err error) {
	n, err = r.ResponseWriter.Write(p)
	r.size += n
	return
}
