package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func ginMiddleware(middleware func(http.Handler) http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Create an http.Handler that calls Gin's next middleware
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Gin uses c.Writer and c.Request
			c.Request = r
			c.Next()
		}))

		// Run the middleware
		handler.ServeHTTP(c.Writer, c.Request)
	}
}
