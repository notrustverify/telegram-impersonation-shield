package main

import (
	"bufio"
	"log"
	"os"
	"strings"
	"sync"
)

// ExceptionsManager handles exceptions for usernames that should be ignored
// in similarity checks
type ExceptionsManager struct {
	Exceptions map[string]bool // Map of usernames to ignore
	FilePath   string
	mutex      sync.RWMutex // Mutex for thread safety
}

// NewExceptionsManager creates a new exceptions manager
func NewExceptionsManager(filePath string) *ExceptionsManager {
	manager := &ExceptionsManager{
		Exceptions: make(map[string]bool),
		FilePath:   filePath,
	}

	// Load exceptions from file if it exists
	manager.LoadExceptions()

	return manager
}

// LoadExceptions loads exceptions from the file
func (em *ExceptionsManager) LoadExceptions() error {
	// Check if exceptions file exists
	if _, err := os.Stat(em.FilePath); os.IsNotExist(err) {
		log.Printf("Exceptions file not found: %s. Starting with empty exceptions list.", em.FilePath)
		return nil
	}

	file, err := os.Open(em.FilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	em.mutex.Lock()
	defer em.mutex.Unlock()

	// Clear existing exceptions
	em.Exceptions = make(map[string]bool)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		username := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if username != "" && !strings.HasPrefix(username, "#") {
			// Convert to lowercase for case-insensitive comparison
			em.Exceptions[strings.ToLower(username)] = true
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	log.Printf("Loaded %d exceptions from %s", len(em.Exceptions), em.FilePath)
	return nil
}

// SaveExceptions saves the current exceptions to the file
func (em *ExceptionsManager) SaveExceptions() error {
	em.mutex.RLock()
	defer em.mutex.RUnlock()

	file, err := os.Create(em.FilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write a header comment
	file.WriteString("# List of username exceptions\n")
	file.WriteString("# These usernames will be ignored in similarity checks\n")
	file.WriteString("# One username per line, lines starting with # are comments\n\n")

	// Write all exceptions
	for username := range em.Exceptions {
		file.WriteString(username + "\n")
	}

	log.Printf("Saved %d exceptions to %s", len(em.Exceptions), em.FilePath)
	return nil
}

// AddException adds a username to the exceptions list and saves to file
func (em *ExceptionsManager) AddException(username string) error {
	// Convert to lowercase for case-insensitive comparison
	username = strings.ToLower(strings.TrimSpace(username))

	// Skip empty usernames
	if username == "" {
		return nil
	}

	em.mutex.Lock()
	em.Exceptions[username] = true
	em.mutex.Unlock()

	return em.SaveExceptions()
}

// RemoveException removes a username from the exceptions list and saves to file
func (em *ExceptionsManager) RemoveException(username string) error {
	// Convert to lowercase for case-insensitive comparison
	username = strings.ToLower(strings.TrimSpace(username))

	em.mutex.Lock()
	delete(em.Exceptions, username)
	em.mutex.Unlock()

	return em.SaveExceptions()
}

// IsExcepted checks if a username is in the exceptions list
func (em *ExceptionsManager) IsExcepted(username string) bool {
	// Convert to lowercase for case-insensitive comparison
	username = strings.ToLower(strings.TrimSpace(username))

	em.mutex.RLock()
	defer em.mutex.RUnlock()

	return em.Exceptions[username]
}

// ListExceptions returns a slice of all exceptions
func (em *ExceptionsManager) ListExceptions() []string {
	em.mutex.RLock()
	defer em.mutex.RUnlock()

	exceptions := make([]string, 0, len(em.Exceptions))
	for username := range em.Exceptions {
		exceptions = append(exceptions, username)
	}

	return exceptions
}
