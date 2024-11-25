package main

import (
	logger "f5_proj/middleware"
	api_sec "f5_proj/pkg"
	"log"
)

func main() {
	err := logger.InitLogFile("api_logs.json")
	if err != nil {
		log.Fatalf("Failed to initialize log file: %v", err)
	}
	server := api_sec.NewAPIServer(":8080")
	server.Run()
}
