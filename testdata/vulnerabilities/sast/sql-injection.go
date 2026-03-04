// Package main demonstrates a SQL injection vulnerability for E2E testing
package main

import (
	"database/sql"
	"fmt"
	"log"
)

// getUserByName demonstrates SQL injection vulnerability
// This function concatenates user input directly into the SQL query
func getUserByName(db *sql.DB, username string) (*sql.Rows, error) {
	// VULNERABLE: SQL injection - user input directly concatenated into query
	query := "SELECT id, username, email FROM users WHERE username = '" + username + "'"

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}

	return rows, nil
}

// getPasswordHash demonstrates another SQL injection pattern
func getPasswordHash(db *sql.DB, userID string) (string, error) {
	// VULNERABLE: SQL injection via string formatting
	query := fmt.Sprintf("SELECT password_hash FROM users WHERE id = %s", userID)

	var hash string
	err := db.QueryRow(query).Scan(&hash)
	if err != nil {
		return "", err
	}

	return hash, nil
}

func main() {
	db, err := sql.Open("postgres", "user=test dbname=test")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Example usage that could be exploited
	// Input like "admin' OR '1'='1" would bypass authentication
	rows, _ := getUserByName(db, "admin")
	defer rows.Close()
}
