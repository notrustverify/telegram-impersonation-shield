package main

import (
	"bufio"
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
