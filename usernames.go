package main

import (
	"bufio"
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
		username := strings.TrimSpace(scanner.Text())
		if username != "" && !strings.HasPrefix(username, "#") {
			usernames = append(usernames, username)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return usernames, nil
}
