// Package main demonstrates SECURE code patterns for E2E testing
// This file should NOT trigger any security vulnerabilities
package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// getUserByID demonstrates SAFE parameterized SQL query
// Uses placeholders to prevent SQL injection
func getUserByID(db *sql.DB, userID int) (*sql.Row, error) {
	// SAFE: Using parameterized query with placeholder
	query := "SELECT id, username, email FROM users WHERE id = ?"

	row := db.QueryRow(query, userID)
	return row, nil
}

// getUserByEmail demonstrates SAFE prepared statement
func getUserByEmail(db *sql.DB, email string) (*sql.Rows, error) {
	// SAFE: Using prepared statement
	stmt, err := db.Prepare("SELECT id, username FROM users WHERE email = ?")
	if err != nil {
		return nil, fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	rows, err := stmt.Query(email)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}

	return rows, nil
}

// renderUserProfile demonstrates SAFE HTML rendering
// Uses html/template for automatic escaping
func renderUserProfile(username, bio string) (string, error) {
	// SAFE: Using html/template which auto-escapes
	tmpl := template.Must(template.New("profile").Parse(`
		<div class="profile">
			<h1>{{.Username}}</h1>
			<p>{{.Bio}}</p>
		</div>
	`))

	var result strings.Builder
	data := struct {
		Username string
		Bio      string
	}{
		Username: username,
		Bio:      bio,
	}

	if err := tmpl.Execute(&result, data); err != nil {
		return "", fmt.Errorf("template execution failed: %w", err)
	}

	return result.String(), nil
}

// readUserFile demonstrates SAFE file path handling
// Validates and sanitizes file paths to prevent traversal
func readUserFile(baseDir, filename string) ([]byte, error) {
	// SAFE: Clean and validate the path
	cleanBase := filepath.Clean(baseDir)
	cleanFile := filepath.Clean(filename)

	// Construct the full path
	fullPath := filepath.Join(cleanBase, cleanFile)

	// SAFE: Verify the path is within the base directory
	if !strings.HasPrefix(fullPath, cleanBase) {
		return nil, fmt.Errorf("invalid path: attempted directory traversal")
	}

	// SAFE: Additional validation - no parent directory references
	if strings.Contains(cleanFile, "..") {
		return nil, fmt.Errorf("invalid filename: contains parent directory reference")
	}

	// Read the file
	content, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return content, nil
}

// writeUserFile demonstrates SAFE file writing with validation
func writeUserFile(baseDir, filename string, content []byte) error {
	// SAFE: Validate and sanitize paths
	cleanBase := filepath.Clean(baseDir)
	cleanFile := filepath.Clean(filename)

	// Ensure filename doesn't contain path separators
	if strings.ContainsAny(cleanFile, "/\\") {
		return fmt.Errorf("invalid filename: contains path separators")
	}

	fullPath := filepath.Join(cleanBase, cleanFile)

	// SAFE: Verify within base directory
	if !strings.HasPrefix(fullPath, cleanBase) {
		return fmt.Errorf("invalid path: outside base directory")
	}

	// Write with safe permissions
	if err := os.WriteFile(fullPath, content, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// getAPIKey demonstrates SAFE credential handling
// Uses environment variables instead of hardcoding
func getAPIKey() (string, error) {
	// SAFE: Read from environment variable
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		return "", fmt.Errorf("API_KEY environment variable not set")
	}
	return apiKey, nil
}

// connectDatabase demonstrates SAFE database connection
// Uses environment variables for credentials
func connectDatabase() (*sql.DB, error) {
	// SAFE: Get connection string from environment
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("DATABASE_URL not set")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	return db, nil
}

// Config demonstrates SAFE configuration management
type Config struct {
	DatabaseURL string
	APIKey      string
	JWTSecret   string
}

// LoadConfig demonstrates SAFE configuration loading
func LoadConfig() (*Config, error) {
	// SAFE: All sensitive values from environment
	return &Config{
		DatabaseURL: os.Getenv("DATABASE_URL"),
		APIKey:      os.Getenv("API_KEY"),
		JWTSecret:   os.Getenv("JWT_SECRET"),
	}, nil
}

func main() {
	// SAFE: Proper error handling
	db, err := connectDatabase()
	if err != nil {
		log.Fatalf("Database connection failed: %v", err)
	}
	defer db.Close()

	// SAFE: Using parameterized queries
	row, err := getUserByID(db, 42)
	if err != nil {
		log.Printf("Query failed: %v", err)
		return
	}

	var id int
	var username, email string
	if err := row.Scan(&id, &username, &email); err != nil {
		log.Printf("Scan failed: %v", err)
		return
	}

	// SAFE: Using template engine for HTML
	html, err := renderUserProfile(username, "Software Engineer")
	if err != nil {
		log.Printf("Render failed: %v", err)
		return
	}

	fmt.Println(html)
}
