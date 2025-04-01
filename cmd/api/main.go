package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/mAmineChniti/Gordian/internal/database"
	"github.com/mAmineChniti/Gordian/internal/server"
)

func gracefulShutdown(apiServer *http.Server, done chan bool, stopCleanup chan struct{}) {
	// Create context that listens for the interrupt signal from the OS.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Listen for the interrupt signal.
	<-ctx.Done()

	log.Println("Shutting down gracefully, press Ctrl+C again to force")

	// Stop the periodic cleanup
	close(stopCleanup)

	// The context is used to inform the server it has 5 seconds to finish
	// the request it is currently handling
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := apiServer.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown with error: %v", err)
	}

	log.Println("Server exiting")

	// Notify the main goroutine that the shutdown is complete
	done <- true
}

func main() {
	// Create a done channel to signal when the shutdown is complete
	done := make(chan bool, 1)

	// Initialize database service
	dbService := database.New()

	// Create a stop channel for periodic cleanup
	stopCleanup := make(chan struct{})

	// Start periodic unconfirmed users cleanup
	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()

		// Initial cleanup
		if err := dbService.DeleteUnconfirmedUsers(); err != nil {
			log.Printf("Initial unconfirmed users cleanup error: %v", err)
		}

		for {
			select {
			case <-ticker.C:
				if err := dbService.DeleteUnconfirmedUsers(); err != nil {
					log.Printf("Periodic unconfirmed users cleanup error: %v", err)
				}
			case <-stopCleanup:
				return
			}
		}
	}()

	server := server.NewServer()

	log.Printf("Starting server on port %s", server.Addr)

	// Run graceful shutdown in a separate goroutine
	go gracefulShutdown(server, done, stopCleanup)

	err := server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		panic(fmt.Sprintf("http server error: %s", err))
	}

	// Wait for the graceful shutdown to complete
	<-done
	log.Println("Graceful shutdown complete.")
}
