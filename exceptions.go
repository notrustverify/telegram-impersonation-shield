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

// ExceptionsManager handles exceptions for usernames that should be ignored
// in similarity checks
type ExceptionsManager struct {
	Exceptions map[int64]bool // Map of user IDs to ignore
	filePath   string
	mutex      sync.RWMutex // Mutex for thread safety
}

// NewExceptionsManager creates a new ExceptionsManager and loads exceptions from the specified file
func NewExceptionsManager(filePath string) *ExceptionsManager {
	em := &ExceptionsManager{
		Exceptions: make(map[int64]bool),
		filePath:   filePath,
	}
	em.LoadExceptions()
	return em
}

// LoadExceptions loads exceptions from the file
func (em *ExceptionsManager) LoadExceptions() {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	// Clear existing exceptions
	em.Exceptions = make(map[int64]bool)

	// Check if file exists
	if _, err := os.Stat(em.filePath); os.IsNotExist(err) {
		log.Printf("Exceptions file not found: %s", em.filePath)
		return
	}

	// Open file
	file, err := os.Open(em.filePath)
	if err != nil {
		log.Printf("Error opening exceptions file: %v", err)
		return
	}
	defer file.Close()

	// Read line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments and empty lines
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		// Parse user ID
		userID, err := strconv.ParseInt(line, 10, 64)
		if err != nil {
			log.Printf("Error parsing user ID from line '%s': %v", line, err)
			continue
		}

		em.Exceptions[userID] = true
	}

	log.Printf("Loaded %d user ID exceptions from %s", len(em.Exceptions), em.filePath)
}

// SaveExceptions saves the current exceptions to the file
func (em *ExceptionsManager) SaveExceptions() error {
	em.mutex.RLock()
	defer em.mutex.RUnlock()

	// Create or truncate file
	file, err := os.Create(em.filePath)
	if err != nil {
		return fmt.Errorf("error creating exceptions file: %v", err)
	}
	defer file.Close()

	// Write header comment
	_, err = fmt.Fprintf(file, "# List of user IDs to ignore in similarity checks\n")
	if err != nil {
		return fmt.Errorf("error writing header: %v", err)
	}

	// Write each user ID
	for userID := range em.Exceptions {
		_, err = fmt.Fprintf(file, "%d\n", userID)
		if err != nil {
			return fmt.Errorf("error writing user ID: %v", err)
		}
	}

	log.Printf("Saved %d user ID exceptions to %s", len(em.Exceptions), em.filePath)
	return nil
}

// AddException adds a user ID to the exceptions list
func (em *ExceptionsManager) AddException(userID int64) error {
	em.mutex.Lock()
	em.Exceptions[userID] = true
	em.mutex.Unlock()
	return em.SaveExceptions()
}

// RemoveException removes a user ID from the exceptions list
func (em *ExceptionsManager) RemoveException(userID int64) error {
	em.mutex.Lock()
	delete(em.Exceptions, userID)
	em.mutex.Unlock()
	return em.SaveExceptions()
}

// IsExcepted checks if a user ID is in the exceptions list
func (em *ExceptionsManager) IsExcepted(userID int64) bool {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	return em.Exceptions[userID]
}

// ListExceptions returns a slice of all excepted user IDs
func (em *ExceptionsManager) ListExceptions() []int64 {
	em.mutex.RLock()
	defer em.mutex.RUnlock()

	exceptions := make([]int64, 0, len(em.Exceptions))
	for userID := range em.Exceptions {
		exceptions = append(exceptions, userID)
	}
	return exceptions
}
