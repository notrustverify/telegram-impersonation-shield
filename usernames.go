package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

// LoadUsernamesFromFile loads a list of usernames from a file
// Each username should be on a separate line
func LoadUsernamesFromFile(filePath string) ([]string, error) {
	var usernames []string

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// Skip empty lines and comments
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Remove @ symbol if present
		line = strings.TrimPrefix(line, "@")

		// Normalize the username by removing spaces and converting to lowercase
		normalized := normalizeName(line)

		// Only add if it's a valid username
		if isValidUsername(normalized) {
			usernames = append(usernames, normalized)
		} else {
			log.Printf("WARNING: Invalid username in file: %s", line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return usernames, nil
}

// SaveUsernameToFile adds a username to the usernames file
func SaveUsernameToFile(filePath string, username string) error {
	// Remove @ symbol if present
	username = strings.TrimPrefix(username, "@")

	// Normalize the username
	normalized := normalizeName(username)

	// Check if it's valid
	if !isValidUsername(normalized) {
		return fmt.Errorf("invalid username format: %s", username)
	}

	// Check if the file exists
	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		// Create file with header
		file, err := os.Create(filePath)
		if err != nil {
			return fmt.Errorf("failed to create usernames file: %v", err)
		}
		defer file.Close()

		file.WriteString("# List of usernames to check for similarity\n")
		file.WriteString("# Each line is a username, lines starting with # are comments\n\n")
	}

	// Check if username already exists in the file
	existingUsernames, err := LoadUsernamesFromFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to load existing usernames: %v", err)
	}

	for _, existing := range existingUsernames {
		if existing == normalized {
			return fmt.Errorf("username '%s' already exists in the list", username)
		}
	}

	// Append the new username to the file
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open usernames file for appending: %v", err)
	}
	defer file.Close()

	_, err = file.WriteString(normalized + "\n")
	if err != nil {
		return fmt.Errorf("failed to write username to file: %v", err)
	}

	log.Printf("Added username '%s' to protected list in %s", normalized, filePath)
	return nil
}

// RemoveUsernameFromFile removes a username from the usernames file
func RemoveUsernameFromFile(filePath string, username string) error {
	// Remove @ symbol if present
	username = strings.TrimPrefix(username, "@")

	// Normalize the username
	normalized := normalizeName(username)

	// Load existing usernames
	existingUsernames, err := LoadUsernamesFromFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to load existing usernames: %v", err)
	}

	// Check if username exists in the list
	found := false
	for _, existing := range existingUsernames {
		if existing == normalized {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("username '%s' not found in the protected list", username)
	}

	// Read the entire file
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			// Keep comments and empty lines
			lines = append(lines, line)
		} else {
			// Check if this is the username we want to remove
			lineNormalized := normalizeName(strings.TrimPrefix(trimmed, "@"))
			if lineNormalized != normalized {
				// Keep all other usernames
				lines = append(lines, line)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %v", err)
	}

	// Write the modified contents back to the file
	if err := os.WriteFile(filePath, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to write updated file: %v", err)
	}

	log.Printf("Removed username '%s' from protected list in %s", normalized, filePath)
	return nil
}
