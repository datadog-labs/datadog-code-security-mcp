// Package main demonstrates a simple Go application for SBOM testing
package main

import (
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func main() {
	// Initialize logger
	log := logrus.New()
	log.Info("Starting SBOM test application")

	// Create Gin router
	r := gin.Default()

	// Simple health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "healthy",
		})
	})

	// Run server
	log.Info("Server starting on :8080")
	if err := r.Run(":8080"); err != nil {
		log.WithError(err).Fatal("Failed to start server")
	}
}
