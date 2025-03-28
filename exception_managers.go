package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
)

// ExceptionManagersAuth handles authorization for exception management
type ExceptionManagersAuth struct {
	AuthorizedUsers map[int64]bool
	mutex           sync.RWMutex
	filePath        string
}

// NewExceptionManagersAuth creates a new authorization manager
func NewExceptionManagersAuth(filePath string) *ExceptionManagersAuth {
	auth := &ExceptionManagersAuth{
		AuthorizedUsers: make(map[int64]bool),
		filePath:        filePath,
	}
	auth.LoadAuthorizedUsers()
	return auth
}

// LoadAuthorizedUsers loads authorized users from file
func (a *ExceptionManagersAuth) LoadAuthorizedUsers() error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Clear existing authorized users
	a.AuthorizedUsers = make(map[int64]bool)

	// Check if file exists
	if _, err := os.Stat(a.filePath); os.IsNotExist(err) {
		log.Printf("Authorized users file does not exist: %s, creating empty file", a.filePath)
		// Create empty file with comment
		file, err := os.Create(a.filePath)
		if err != nil {
			log.Printf("Failed to create authorized users file: %v", err)
			return err
		}
		defer file.Close()

		file.WriteString("# Authorized users for exception management - one user ID per line\n")
		file.WriteString("# Users listed here can add/remove exceptions\n\n")
		return nil
	}

	// Open file
	file, err := os.Open(a.filePath)
	if err != nil {
		log.Printf("Failed to open authorized users file: %v", err)
		return err
	}
	defer file.Close()

	// Read line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Skip comments and empty lines
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		// Parse user ID
		userID, err := strconv.ParseInt(strings.TrimSpace(line), 10, 64)
		if err != nil {
			log.Printf("Invalid user ID in authorized users file: %s", line)
			continue
		}

		// Add to authorized users
		a.AuthorizedUsers[userID] = true
	}

	log.Printf("Loaded %d authorized users from file", len(a.AuthorizedUsers))
	return nil
}

// SaveAuthorizedUsers saves authorized users to file
func (a *ExceptionManagersAuth) SaveAuthorizedUsers() error {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	// Create file
	file, err := os.Create(a.filePath)
	if err != nil {
		log.Printf("Failed to create authorized users file: %v", err)
		return err
	}
	defer file.Close()

	// Write header
	file.WriteString("# Authorized users for exception management - one user ID per line\n")
	file.WriteString("# Users listed here can add/remove exceptions\n\n")

	// Write user IDs
	for userID := range a.AuthorizedUsers {
		file.WriteString(fmt.Sprintf("%d\n", userID))
	}

	log.Printf("Saved %d authorized users to file", len(a.AuthorizedUsers))
	return nil
}

// AddAuthorizedUser adds a user ID to authorized users
func (a *ExceptionManagersAuth) AddAuthorizedUser(userID int64) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.AuthorizedUsers[userID] = true
	return a.SaveAuthorizedUsers()
}

// RemoveAuthorizedUser removes a user ID from authorized users
func (a *ExceptionManagersAuth) RemoveAuthorizedUser(userID int64) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	delete(a.AuthorizedUsers, userID)
	return a.SaveAuthorizedUsers()
}

// IsAuthorized checks if a user ID is authorized to manage exceptions
func (a *ExceptionManagersAuth) IsAuthorized(userID int64) bool {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	return a.AuthorizedUsers[userID]
}

// ListAuthorizedUsers returns a list of authorized user IDs
func (a *ExceptionManagersAuth) ListAuthorizedUsers() []int64 {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	var result []int64
	for userID := range a.AuthorizedUsers {
		result = append(result, userID)
	}
	return result
}
