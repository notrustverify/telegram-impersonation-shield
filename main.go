package main

import (
	"bufio"
	"fmt"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// loadEnvFile loads environment variables from a .env file if it exists
func loadEnvFile(filePath string) {
	// Check if .env file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return
	}

	// Open .env file
	file, err := os.Open(filePath)
	if err != nil {
		return
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

		// Parse KEY=VALUE format
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Only set if environment variable is not already set
		if os.Getenv(key) == "" {
			os.Setenv(key, value)
		}
	}
}

// KnownUsernames is a list of usernames to compare against
var KnownUsernames = []string{
	"alephium",
	"alph_official",
	"alphofficial",
	"alephium_org",
	"alph_foundation",
	// Add more usernames as needed
}

// normalizeName removes spaces and converts to lowercase for comparison
func normalizeName(name string) string {
	// Remove all spaces and convert to lowercase
	return strings.ToLower(strings.ReplaceAll(name, " ", ""))
}

// JaroWinkler calculates the Jaro-Winkler similarity between two strings
// Returns a value between 0 (completely different) and 1 (identical)
func JaroWinkler(s1, s2 string) float64 {
	// Convert to lowercase for case-insensitive comparison
	s1 = normalizeName(s1)
	s2 = normalizeName(s2)

	// If strings are identical, return 1.0
	if s1 == s2 {
		return 1.0
	}

	// Get the lengths of the strings
	len1 := len(s1)
	len2 := len(s2)

	// The maximum distance between two characters to be considered matching
	matchDistance := int(math.Max(float64(len1), float64(len2))/2.0) - 1
	if matchDistance < 0 {
		matchDistance = 0
	}

	// Arrays to track which characters in each string are matched
	matches1 := make([]bool, len1)
	matches2 := make([]bool, len2)

	// Count of matching characters
	matchCount := 0

	// Find matching characters within the matchDistance
	for i := 0; i < len1; i++ {
		start := int(math.Max(0, float64(i-matchDistance)))
		end := int(math.Min(float64(len2-1), float64(i+matchDistance)))

		for j := start; j <= end; j++ {
			// If already matched or characters don't match, skip
			if matches2[j] || s1[i] != s2[j] {
				continue
			}

			// Mark as matched and increase counter
			matches1[i] = true
			matches2[j] = true
			matchCount++
			break
		}
	}

	// If no matches, return 0
	if matchCount == 0 {
		return 0.0
	}

	// Count transpositions
	transpositions := 0
	k := 0
	for i := 0; i < len1; i++ {
		if !matches1[i] {
			continue
		}

		// Find the next matched character in s2
		for !matches2[k] {
			k++
		}

		// If characters don't match, it's a transposition
		if s1[i] != s2[k] {
			transpositions++
		}
		k++
	}

	// Calculate Jaro similarity
	transpositions = transpositions / 2
	jaroSimilarity := (float64(matchCount)/float64(len1) +
		float64(matchCount)/float64(len2) +
		float64(matchCount-transpositions)/float64(matchCount)) / 3.0

	// Calculate Jaro-Winkler
	// The prefix scale is how much to boost the score if the strings have a common prefix
	prefixScale := 0.1
	prefixLength := 0
	maxPrefixLength := 4

	// Count matching characters at the beginning
	for i := 0; i < int(math.Min(float64(len1), float64(len2))); i++ {
		if s1[i] == s2[i] {
			prefixLength++
		} else {
			break
		}
		if prefixLength == maxPrefixLength {
			break
		}
	}

	// Calculate final Jaro-Winkler similarity
	jaroWinklerSimilarity := jaroSimilarity + float64(prefixLength)*prefixScale*(1.0-jaroSimilarity)
	return jaroWinklerSimilarity
}

// SimilarUsernameResult stores a similar username and its similarity score
type SimilarUsernameResult struct {
	Username   string
	Similarity float64
}

// FindSimilarUsernamesWithExceptions checks a username but ignores exceptions
// Returns early after finding the first match
func FindSimilarUsernamesWithExceptions(username string, threshold float64, exceptions *ExceptionsManager) []SimilarUsernameResult {
	var results []SimilarUsernameResult

	// Normalize input username
	usernameLower := normalizeName(username)

	for _, knownUsername := range KnownUsernames {
		// Known usernames are already normalized during loading
		knownUsernameLower := knownUsername
		similarity := JaroWinkler(usernameLower, knownUsernameLower)

		if similarity >= threshold { // Exclude exact matches
			// Return immediately with this single result
			return []SimilarUsernameResult{
				{
					Username:   knownUsername, // Keep original case for display
					Similarity: similarity,
				},
			}
		}
	}

	return results
}

// MuteUser restricts a user from sending messages in a group
func MuteUser(bot *tgbotapi.BotAPI, chatID int64, userID int64, duration time.Duration) error {
	untilDate := time.Now().Add(duration).Unix()

	chatPermissions := tgbotapi.ChatPermissions{
		CanSendMessages:       false,
		CanSendMediaMessages:  false,
		CanSendPolls:          false,
		CanSendOtherMessages:  false,
		CanAddWebPagePreviews: false,
		CanChangeInfo:         false,
		CanInviteUsers:        false,
		CanPinMessages:        false,
	}

	restrictConfig := tgbotapi.RestrictChatMemberConfig{
		ChatMemberConfig: tgbotapi.ChatMemberConfig{
			ChatID: chatID,
			UserID: userID,
		},
		UntilDate:   untilDate,
		Permissions: &chatPermissions,
	}

	_, err := bot.Request(restrictConfig)
	return err
}

// RecentlyCheckedUser tracks when a user was last checked to avoid spamming
type RecentlyCheckedUser struct {
	Username  string
	CheckedAt time.Time
}

// AdminInfo stores admin username and first name for similarity checks
type AdminInfo struct {
	Username  string
	FirstName string
	LastName  string
	UserID    int64
}

// BotSettings for the bot
type BotSettings struct {
	SimilarityThreshold float64
	AutoMuteEnabled     bool
	AutoMuteThreshold   float64
	MuteDuration        time.Duration
	CheckCooldown       time.Duration // How long to wait before checking the same user again
	DeleteMessages      bool          // Whether to delete messages from users with similar usernames
	AuditGroupID        int64         // Group ID to send audit messages to
	RecentlyChecked     map[int64]RecentlyCheckedUser
	Mutex               sync.RWMutex
	// Cache for admin usernames by chat ID
	AdminInfo        map[int64][]AdminInfo
	AdminCacheMutex  sync.RWMutex
	AdminCacheTime   map[int64]time.Time
	AdminCacheExpiry time.Duration // How long to keep admin cache before refreshing
	// Exceptions manager
	Exceptions *ExceptionsManager
	// Exception Managers Auth
	ExceptionAuth *ExceptionManagersAuth
	// Warning cooldown settings
	WarningCooldown time.Duration       // How long to wait before sending another warning in the same chat
	LastWarningSent map[int64]time.Time // Track when the last warning was sent for each chat
	WarningMutex    sync.RWMutex
}

// IsRecentlyChecked determines if a user was recently checked
func (s *BotSettings) IsRecentlyChecked(userID int64) bool {
	// If cooldown is set to 0, disable cooldown system entirely
	if s.CheckCooldown <= 0 {
		log.Printf("DEBUG: Cooldown system is disabled, all messages will be checked")
		return false
	}

	s.Mutex.RLock()
	defer s.Mutex.RUnlock()

	if recent, exists := s.RecentlyChecked[userID]; exists {
		timeSince := time.Since(recent.CheckedAt)
		log.Printf("DEBUG: User ID %d (@%s) was last checked %.1f minutes ago (cooldown: %.1f minutes)",
			userID, recent.Username, timeSince.Minutes(), s.CheckCooldown.Minutes())
		return timeSince < s.CheckCooldown
	}
	log.Printf("DEBUG: User ID %d has not been checked before", userID)
	return false
}

// MarkUserAsChecked records when a user was last checked
func (s *BotSettings) MarkUserAsChecked(userID int64, username string) {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	s.RecentlyChecked[userID] = RecentlyCheckedUser{
		Username:  username,
		CheckedAt: time.Now(),
	}
	log.Printf("DEBUG: Marked user ID %d (@%s) as checked at %s",
		userID, username, time.Now().Format(time.RFC3339))
}

// CleanupOldChecks removes entries older than the cooldown period
func (s *BotSettings) CleanupOldChecks() {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	before := len(s.RecentlyChecked)

	for userID, checked := range s.RecentlyChecked {
		timeSince := time.Since(checked.CheckedAt)
		if timeSince > s.CheckCooldown {
			log.Printf("DEBUG: Removing user ID %d (@%s) from cooldown list (last checked %.1f minutes ago)",
				userID, checked.Username, timeSince.Minutes())
			delete(s.RecentlyChecked, userID)
		}
	}

	after := len(s.RecentlyChecked)
	if before != after {
		log.Printf("DEBUG: Cleanup removed %d users from cooldown list, %d remaining",
			before-after, after)
	}
}

// BanUser kicks a user from a group permanently
func BanUser(bot *tgbotapi.BotAPI, chatID int64, userID int64) error {
	banConfig := tgbotapi.BanChatMemberConfig{
		ChatMemberConfig: tgbotapi.ChatMemberConfig{
			ChatID: chatID,
			UserID: userID,
		},
		UntilDate: 0, // 0 means banned forever
	}

	_, err := bot.Request(banConfig)
	return err
}

// DeleteMessage deletes a message from a chat
func DeleteMessage(bot *tgbotapi.BotAPI, chatID int64, messageID int) error {
	deleteConfig := tgbotapi.DeleteMessageConfig{
		ChatID:    chatID,
		MessageID: messageID,
	}
	_, err := bot.Request(deleteConfig)
	return err
}

// IsWarningOnCooldown checks if a warning can be sent for a chat
func (s *BotSettings) IsWarningOnCooldown(chatID int64) bool {
	s.WarningMutex.RLock()
	defer s.WarningMutex.RUnlock()

	if lastWarning, exists := s.LastWarningSent[chatID]; exists {
		timeSince := time.Since(lastWarning)
		log.Printf("DEBUG: Last warning in chat %d was sent %.1f minutes ago (cooldown: %.1f minutes)",
			chatID, timeSince.Minutes(), s.WarningCooldown.Minutes())
		return timeSince < s.WarningCooldown
	}
	log.Printf("DEBUG: No previous warning found for chat %d", chatID)
	return false
}

// MarkWarningSent records when a warning was sent for a chat
func (s *BotSettings) MarkWarningSent(chatID int64) {
	s.WarningMutex.Lock()
	defer s.WarningMutex.Unlock()

	s.LastWarningSent[chatID] = time.Now()
	log.Printf("DEBUG: Marked warning as sent for chat %d at %s",
		chatID, time.Now().Format(time.RFC3339))
}

// CleanupOldWarnings removes entries older than the cooldown period
func (s *BotSettings) CleanupOldWarnings() {
	s.WarningMutex.Lock()
	defer s.WarningMutex.Unlock()

	before := len(s.LastWarningSent)

	for chatID, lastWarning := range s.LastWarningSent {
		timeSince := time.Since(lastWarning)
		if timeSince > s.WarningCooldown {
			log.Printf("DEBUG: Removing chat %d from warning cooldown list (last warning %.1f minutes ago)",
				chatID, timeSince.Minutes())
			delete(s.LastWarningSent, chatID)
		}
	}

	after := len(s.LastWarningSent)
	if before != after {
		log.Printf("DEBUG: Cleanup removed %d chats from warning cooldown list, %d remaining",
			before-after, after)
	}
}

func main() {
	// Try to load from .env file first
	loadEnvFile(".env")

	// Get the bot token from environment variable
	botToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	if botToken == "" {
		log.Fatal("TELEGRAM_BOT_TOKEN environment variable is not set")
	}

	// Try to load usernames from file
	usernamesFile := "usernames.txt"
	if _, err := os.Stat(usernamesFile); err == nil {
		log.Printf("Loading usernames from %s", usernamesFile)
		usernames, err := LoadUsernamesFromFile(usernamesFile)
		if err != nil {
			log.Printf("Error loading usernames from file: %v. Using default list.", err)
		} else if len(usernames) > 0 {
			KnownUsernames = usernames
			log.Printf("Loaded %d usernames from file", len(usernames))
		}
	} else {
		log.Printf("Usernames file not found: %s. Using default list.", usernamesFile)
	}

	bot, err := tgbotapi.NewBotAPI(botToken)
	if err != nil {
		log.Fatal(err)
	}

	bot.Debug = true
	log.Printf("Authorized on account %s (ID: %d)", bot.Self.UserName, bot.Self.ID)

	// Set up update configuration
	updateConfig := tgbotapi.NewUpdate(0)
	updateConfig.Timeout = 60
	updateConfig.AllowedUpdates = []string{"message", "my_chat_member", "chat_member"}

	// Get updates channel
	updates := bot.GetUpdatesChan(updateConfig)

	// Initialize exception managers auth
	exceptionAuth := NewExceptionManagersAuth("exception_managers.txt")

	// Bot settings
	settings := BotSettings{
		SimilarityThreshold: 0.8,              // Default threshold for similarity detection
		AutoMuteEnabled:     false,            // Default auto-mute is disabled
		AutoMuteThreshold:   0.9,              // Higher threshold for auto-mute (very similar usernames)
		MuteDuration:        24 * time.Hour,   // Default mute duration: 24 hours
		CheckCooldown:       30 * time.Minute, // Don't check the same user more often than this
		DeleteMessages:      true,             // Default to deleting messages
		AuditGroupID:        0,                // Default to 0 (disabled)
		RecentlyChecked:     make(map[int64]RecentlyCheckedUser),
		AdminInfo:           make(map[int64][]AdminInfo),
		AdminCacheTime:      make(map[int64]time.Time),
		AdminCacheExpiry:    1 * time.Hour, // Default to refresh admin cache every hour
		Exceptions:          NewExceptionsManager("exceptions.txt"),
		ExceptionAuth:       exceptionAuth,
		WarningCooldown:     10 * time.Minute, // Default warning cooldown: 10 minutes
		LastWarningSent:     make(map[int64]time.Time),
	}

	// Set similarity threshold from env or default to 0.8
	if thresholdStr := os.Getenv("SIMILARITY_THRESHOLD"); thresholdStr != "" {
		if t, err := strconv.ParseFloat(thresholdStr, 64); err == nil && t >= 0 && t <= 1 {
			settings.SimilarityThreshold = t
			log.Printf("Using similarity threshold from environment: %.2f", settings.SimilarityThreshold)
		}
	}

	// Set auto-mute threshold from env or use default
	if thresholdStr := os.Getenv("AUTO_MUTE_THRESHOLD"); thresholdStr != "" {
		if t, err := strconv.ParseFloat(thresholdStr, 64); err == nil && t >= 0 && t <= 1 {
			settings.AutoMuteThreshold = t
			log.Printf("Using auto-mute threshold from environment: %.2f", settings.AutoMuteThreshold)
		}
	}

	// Set auto-mute enabled from env or use default
	if enabledStr := os.Getenv("AUTO_MUTE_ENABLED"); enabledStr != "" {
		if enabledStr == "true" || enabledStr == "1" || enabledStr == "yes" {
			settings.AutoMuteEnabled = true
			log.Printf("Auto-mute is enabled")
		}
	}

	// Set mute duration from env or use default
	if durationStr := os.Getenv("MUTE_DURATION_HOURS"); durationStr != "" {
		if hours, err := strconv.ParseFloat(durationStr, 64); err == nil && hours > 0 {
			settings.MuteDuration = time.Duration(hours * float64(time.Hour))
			log.Printf("Using mute duration from environment: %.1f hours", hours)
		}
	}

	// Set check cooldown from env or use default
	if cooldownStr := os.Getenv("CHECK_COOLDOWN_MINUTES"); cooldownStr != "" {
		if minutes, err := strconv.ParseFloat(cooldownStr, 64); err == nil && minutes >= 0 {
			settings.CheckCooldown = time.Duration(minutes * float64(time.Minute))
			if minutes == 0 {
				log.Printf("Cooldown system is disabled. All messages will be checked.")
			} else {
				log.Printf("Using check cooldown from environment: %.1f minutes", minutes)
			}
		}
	}

	// Set delete messages from env or use default
	if deleteStr := os.Getenv("DELETE_MESSAGES"); deleteStr != "" {
		if deleteStr == "true" || deleteStr == "1" || deleteStr == "yes" {
			settings.DeleteMessages = true
			log.Printf("Message deletion is enabled")
		} else if deleteStr == "false" || deleteStr == "0" || deleteStr == "no" {
			settings.DeleteMessages = false
			log.Printf("Message deletion is disabled")
		}
	}

	// Set audit group ID from env or use default
	if auditGroupStr := os.Getenv("AUDIT_GROUP_ID"); auditGroupStr != "" {
		if auditGroupID, err := strconv.ParseInt(auditGroupStr, 10, 64); err == nil && auditGroupID != 0 {
			settings.AuditGroupID = auditGroupID
			log.Printf("Using audit group ID: %d", settings.AuditGroupID)
		}
	}

	// Set admin cache expiry from env or use default
	if expiryStr := os.Getenv("ADMIN_CACHE_EXPIRY_HOURS"); expiryStr != "" {
		if hours, err := strconv.ParseFloat(expiryStr, 64); err == nil && hours > 0 {
			settings.AdminCacheExpiry = time.Duration(hours * float64(time.Hour))
			log.Printf("Using admin cache expiry from environment: %.1f hours", hours)
		}
	}

	// Start a goroutine to periodically clean up old checked users
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			settings.CleanupOldChecks()
		}
	}()

	// Start a goroutine to periodically clean up old warning entries
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			settings.CleanupOldWarnings()
		}
	}()

	// Start a goroutine to periodically refresh admin caches
	go func() {
		// Use half the cache expiry time as the refresh interval to ensure we refresh before expiration
		refreshInterval := settings.AdminCacheExpiry / 2
		if refreshInterval < 10*time.Minute {
			refreshInterval = 10 * time.Minute // Minimum 10 minutes to avoid too frequent refreshes
		}

		ticker := time.NewTicker(refreshInterval)
		defer ticker.Stop()

		for range ticker.C {
			// Refresh all cached admin lists
			settings.AdminCacheMutex.Lock()
			chatIDs := make([]int64, 0, len(settings.AdminInfo))
			for chatID := range settings.AdminInfo {
				chatIDs = append(chatIDs, chatID)
			}
			settings.AdminCacheMutex.Unlock()

			// Update each chat's admin list
			for _, chatID := range chatIDs {
				log.Printf("Refreshing admin cache for chat ID %d", chatID)
				settings.UpdateAdminCache(bot, chatID)
			}
		}
	}()

	// Main loop: Process updates
	for update := range updates {
		// Process chat join/group membership
		if update.MyChatMember != nil {
			if update.MyChatMember.Chat.IsGroup() || update.MyChatMember.Chat.IsSuperGroup() {
				log.Printf("DEBUG: Bot status changed in chat %s (ID: %d)",
					update.MyChatMember.Chat.Title, update.MyChatMember.Chat.ID)

				// Check current status
				if update.MyChatMember.NewChatMember.Status == "administrator" {
					log.Printf("INFO: Bot was promoted to admin in chat %s", update.MyChatMember.Chat.Title)
					CheckBotPermissions(bot, update.MyChatMember.Chat.ID)
				} else if update.MyChatMember.NewChatMember.Status == "member" {
					log.Printf("WARNING: Bot is a regular member in chat %s - some features will not work",
						update.MyChatMember.Chat.Title)
				} else if update.MyChatMember.NewChatMember.Status == "left" ||
					update.MyChatMember.NewChatMember.Status == "kicked" {
					log.Printf("INFO: Bot was removed from chat %s", update.MyChatMember.Chat.Title)
				}
			}
		}

		// Check if this is a new group the bot was added to
		if update.Message != nil && update.Message.NewChatMembers != nil {
			for _, newMember := range update.Message.NewChatMembers {
				if newMember.ID == bot.Self.ID {
					log.Printf("INFO: Bot was added to group %s (ID: %d)",
						update.Message.Chat.Title, update.Message.Chat.ID)

					// Send welcome message
					welcomeMsg := tgbotapi.NewMessage(update.Message.Chat.ID,
						fmt.Sprintf("👋 Hello! I've been added to %s.\n\n"+
							"I'll help protect this group from username impersonators.\n\n"+
							"Please make me an admin so I can restrict suspicious users.\n\n"+
							"Type /help for available commands.", update.Message.Chat.Title))

					_, err := bot.Send(welcomeMsg)
					if err != nil {
						log.Printf("ERROR: Failed to send welcome message: %v", err)
					}

					// Check permissions
					CheckBotPermissions(bot, update.Message.Chat.ID)
				}
			}
		}

		// Process messages with commands or text
		if update.Message != nil {
			// Debug log for all incoming messages
			log.Printf("DEBUG: Received message from user ID %d, username: @%s, first name: %s, chat ID: %d, chat type: %s, text: %s",
				update.Message.From.ID,
				update.Message.From.UserName,
				update.Message.From.FirstName,
				update.Message.Chat.ID,
				update.Message.Chat.Type,
				update.Message.Text)

			// Check user if they have username or first name - only in group chats
			if update.Message.From != nil && (update.Message.Chat.IsGroup() || update.Message.Chat.IsSuperGroup()) {
				log.Printf("DEBUG: Preparing to check user ID %d for impersonation in group chat", update.Message.From.ID)

				// Don't check too frequently
				if !settings.IsRecentlyChecked(update.Message.From.ID) {
					log.Printf("DEBUG: User ID %d passed cooldown check", update.Message.From.ID)

					// Skip checks for admins using the cached admin list
					if settings.IsUserAdmin(bot, update.Message.Chat.ID, update.Message.From.ID) {
						log.Printf("DEBUG: User ID %d (@%s) is an admin, skipping username check",
							update.Message.From.ID, update.Message.From.UserName)
						// DON'T continue here - that would skip command processing entirely!
						// We want to skip similarity checking but still process commands
						log.Printf("DEBUG: Admin user will skip similarity checks but still process commands")
						// Mark as checked for admin users too
						settings.MarkUserAsChecked(update.Message.From.ID, update.Message.From.UserName)
					} else {
						log.Printf("DEBUG: User ID %d is not an admin, proceeding with check", update.Message.From.ID)

						// Only check non-admins
						// Check username/first name and auto-mute if necessary
						if update.Message.From.UserName != "" || update.Message.From.FirstName != "" {
							log.Printf("DEBUG: STARTING similarity check for user ID %d", update.Message.From.ID)
							checkAndMuteUser(bot, &settings, update.Message.Chat.ID, update.Message.From.ID,
								update.Message.From.UserName, update.Message.From.FirstName, update.Message.From.LastName, false, update.Message.Text, update.Message.MessageID, update.Message.Chat.Title)
							log.Printf("DEBUG: COMPLETED similarity check for user ID %d", update.Message.From.ID)
						}
					}
				} else {
					log.Printf("DEBUG: User ID %d (@%s) was recently checked, skipping due to cooldown",
						update.Message.From.ID, update.Message.From.UserName)
				}
			} else if update.Message.From == nil {
				log.Printf("DEBUG: Message has no From field, cannot check user")
			} else {
				log.Printf("DEBUG: Message not in a group chat, skipping impersonation check")
			}

			// Process commands
			if update.Message != nil && update.Message.IsCommand() {
				// Call the HandleCommand function from commands.go
				if HandleCommand(bot, &settings, &update) {
					// Command was handled, continue to next update
					continue
				}
			} else {
				// Instead, just log that we received a text message but ignoring it
				log.Printf("DEBUG: Received text message, not a command - ignoring")
			}
		}
	}
}

// checkAndMuteUser checks a username for similarity and mutes the user if necessary
// isNewUser indicates if this is a user who just joined (triggers different notification message)
func checkAndMuteUser(bot *tgbotapi.BotAPI, settings *BotSettings, chatID int64, userID int64, username string, firstName string, lastName string, isNewUser bool, messageText string, replyToMessageID int, chatTitle string) {
	var similarUsernames []SimilarUsernameResult
	var similarFirstNames []SimilarUsernameResult
	var similarToAdmins []SimilarUsernameResult
	var hasSimilarities bool

	// First check if the user is in exceptions list
	if settings.Exceptions.IsExcepted(userID) {
		log.Printf("DEBUG: User ID %d is in exceptions list, skipping similarity check", userID)
		return
	}

	// Build full name from first and last name if available
	var fullName string
	if firstName != "" && lastName != "" {
		fullName = firstName + " " + lastName
	} else if firstName != "" {
		fullName = firstName
	} else if lastName != "" {
		fullName = lastName
	}

	// Get admin list for additional checking
	adminInfo := settings.GetAdminInfo(bot, chatID)

	// First check username if available
	if username != "" {
		// First check against admin usernames and first names (priority check)
		log.Printf("DEBUG: Checking username @%s against admin names with threshold %.2f",
			username, settings.SimilarityThreshold)

		for _, admin := range adminInfo {
			// Skip if admin is in exceptions list
			if settings.Exceptions.IsExcepted(admin.UserID) {
				continue
			}

			// Check against admin username if available
			if admin.Username != "" {
				adminUsernameLower := normalizeName(admin.Username)
				similarity := JaroWinkler(username, adminUsernameLower)
				if similarity >= settings.SimilarityThreshold && similarity < 1.0 { // Exclude exact matches
					similarToAdmins = append(similarToAdmins, SimilarUsernameResult{
						Username:   "@" + admin.Username, // Keep original case for display
						Similarity: similarity,
					})
					// Break after finding the first admin similarity
					break
				}
			}

			// Skip further checks if we already found a similar admin
			if len(similarToAdmins) > 0 {
				break
			}

			// Check against admin first name if available
			if admin.FirstName != "" {
				adminFirstNameLower := normalizeName(admin.FirstName)
				adminLastNameLower := ""
				if admin.LastName != "" {
					adminLastNameLower = normalizeName(admin.LastName)
				}

				// Build normalized admin full name
				adminFullName := adminFirstNameLower
				if adminLastNameLower != "" {
					adminFullName += adminLastNameLower // No spaces since normalizeName removes them
				}

				// Normalize the user's full name for comparison
				normalizedFullName := normalizeName(fullName)

				// Check full name similarity
				fullNameSimilarity := JaroWinkler(normalizedFullName, adminFullName)
				if fullNameSimilarity >= settings.SimilarityThreshold {
					similarToAdmins = append(similarToAdmins, SimilarUsernameResult{
						Username:   admin.FirstName + " " + admin.LastName + " (full name)", // First name, no @ symbol
						Similarity: fullNameSimilarity,
					})
					// Break after finding the first admin similarity
					break
				}
			}
		}

		// Only check against known usernames if no admin matches were found
		if len(similarToAdmins) == 0 {
			log.Printf("DEBUG: No admin similarities found, checking username @%s against %d known usernames with threshold %.2f",
				username, len(KnownUsernames), settings.SimilarityThreshold)

			// Check for similar usernames in known usernames list
			similarUsernames = FindSimilarUsernamesWithExceptions(username, settings.SimilarityThreshold, settings.Exceptions)
		}

		hasSimilarities = len(similarUsernames) > 0 || len(similarToAdmins) > 0

		if len(similarToAdmins) > 0 {
			log.Printf("DEBUG: Found %d admin identifiers similar to @%s", len(similarToAdmins), username)
			for _, result := range similarToAdmins {
				log.Printf("DEBUG: Similar admin identifier: %s (%.2f%% similarity)",
					result.Username, result.Similarity*100)
			}
		}

		if len(similarUsernames) > 0 {
			log.Printf("DEBUG: Found %d similar usernames for @%s", len(similarUsernames), username)
			for _, result := range similarUsernames {
				log.Printf("DEBUG: Similar username: %s (%.2f%% similarity)",
					result.Username, result.Similarity*100)
			}
		}

		if !hasSimilarities {
			log.Printf("DEBUG: No similar usernames found for @%s", username)
		}
	}

	// Only check full name if username is not available or had no matches
	if !hasSimilarities && fullName != "" {
		log.Printf("DEBUG: Checking full name '%s' as fallback", fullName)

		// First check against admin usernames and first names (priority check)
		for _, admin := range adminInfo {
			// Skip if admin is in exceptions list
			if settings.Exceptions.IsExcepted(admin.UserID) {
				continue
			}

			// Skip further checks if we already found a similar admin
			if len(similarToAdmins) > 0 {
				break
			}

			// Check against admin first name if available
			if admin.FirstName != "" {
				adminFirstNameLower := normalizeName(admin.FirstName)
				adminLastNameLower := ""
				if admin.LastName != "" {
					adminLastNameLower = normalizeName(admin.LastName)
				}

				// Build normalized admin full name
				adminFullName := adminFirstNameLower
				if adminLastNameLower != "" {
					adminFullName += adminLastNameLower // No spaces since normalizeName removes them
				}

				// Normalize the user's full name for comparison
				normalizedFullName := normalizeName(fullName)

				// Check full name similarity
				fullNameSimilarity := JaroWinkler(normalizedFullName, adminFullName)
				if fullNameSimilarity >= settings.SimilarityThreshold {
					similarToAdmins = append(similarToAdmins, SimilarUsernameResult{
						Username:   admin.FirstName + " " + admin.LastName + " (full name)",
						Similarity: fullNameSimilarity,
					})
					// Break after finding the first admin similarity
					break
				}
			}
		}

		// Only check against known usernames if no admin matches were found
		if len(similarToAdmins) == 0 {
			// Check full name against known usernames
			similarFirstNames = FindSimilarUsernamesWithExceptions(fullName, settings.SimilarityThreshold, settings.Exceptions)
		}

		hasSimilarities = len(similarFirstNames) > 0 || len(similarToAdmins) > 0

		if len(similarToAdmins) > 0 {
			log.Printf("DEBUG: Found %d admin identifiers similar to full name '%s'", len(similarToAdmins), fullName)
			for _, result := range similarToAdmins {
				log.Printf("DEBUG: Similar admin identifier: %s (%.2f%% similarity)",
					result.Username, result.Similarity*100)
			}
		}

		if len(similarFirstNames) > 0 {
			log.Printf("DEBUG: Found %d similar names for full name '%s'", len(similarFirstNames), fullName)
			for i, result := range similarFirstNames {
				log.Printf("DEBUG: Similar name #%d: %s (%.2f%% similarity)",
					i+1, result.Username, result.Similarity*100)
			}
		}

		if !hasSimilarities {
			log.Printf("DEBUG: No similar names found for full name '%s'", fullName)
		}
	}

	if hasSimilarities {
		// Mark this user as checked to avoid spamming
		settings.MarkUserAsChecked(userID, username)

		// Delete the message if enabled and it's not a new user (i.e., it's a message)
		if settings.DeleteMessages && !isNewUser && replyToMessageID > 0 {
			err := DeleteMessage(bot, chatID, replyToMessageID)
			if err != nil {
				log.Printf("ERROR: Failed to delete message from user with similar username: %v", err)
			} else {
				log.Printf("DEBUG: Deleted message %d from user with similar username", replyToMessageID)
			}
		}

		// Build notification message
		var notificationText string
		var userIdentifier string

		// Determine how to identify the user in the message
		if username != "" {
			userIdentifier = fmt.Sprintf("@*%s* - ID: `%d`", username, userID)
		} else if fullName != "" {
			userIdentifier = fmt.Sprintf("*%s* - ID: `%d`", fullName, userID)
		} else {
			userIdentifier = fmt.Sprintf("User ID: `%d`", userID)
		}

		if isNewUser {
			notificationText = fmt.Sprintf("New user %s", userIdentifier)
		} else {
			notificationText = fmt.Sprintf("User %s", userIdentifier)
		}

		// Username similarities
		if len(similarUsernames) > 0 {
			notificationText += " has similar username to official accounts:\n\n"
			for _, result := range similarUsernames {
				notificationText += fmt.Sprintf("*%s* - Similarity: %.2f%%\n",
					result.Username, result.Similarity*100)
			}
		}

		// Admin username/firstname similarities
		if len(similarToAdmins) > 0 {
			if len(similarUsernames) > 0 {
				notificationText += "\nAND similar to group admins:\n"
			} else {
				notificationText += " has similar username to group admins:\n"
			}

			for _, result := range similarToAdmins {
				// Find the admin info to get their user ID
				var adminUserID int64
				for _, admin := range adminInfo {
					if strings.TrimPrefix(result.Username, "@") == admin.Username || result.Username == admin.FirstName {
						adminUserID = admin.UserID
						break
					}
				}

				// Simplify the formatting to make it more reliable with Markdown
				adminName := strings.TrimPrefix(result.Username, "@")
				if adminUserID > 0 {
					notificationText += fmt.Sprintf("*%s* - ID: `%d` - Similarity: %.2f%%\n",
						adminName, adminUserID, result.Similarity*100)
				} else {
					notificationText += fmt.Sprintf("*%s* - Similarity: %.2f%%\n",
						adminName, result.Similarity*100)
				}
			}
		}

		// First name similarities (should only happen if username was empty)
		if len(similarFirstNames) > 0 {
			notificationText += "\nhas similar first name to:\n"
			for _, result := range similarFirstNames {
				notificationText += fmt.Sprintf("*%s* - Similarity: %.2f%%\n",
					result.Username, result.Similarity*100)
			}
		}

		// Add deletion info to notification if applicable
		if settings.DeleteMessages && !isNewUser && replyToMessageID > 0 {
			notificationText += "\n\n🗑️ The message has been deleted to prevent potential scams."
		}

		notificationText += fmt.Sprintf("\n\n🚨 Warning 🚨\n\n" +
			"📱 Protect Your Wallet:\n" +
			"NEVER share your seed phrase or private key\n" +
			"NEVER enter your seed in ANY recovery tools\n" +
			"AVOID connecting to unknown dApps\n" +
			"DON'T sign transactions you don't understand\n\n" +
			"💬 Communication Safety:\n" +
			"IGNORE unsolicited direct messages\n" +
			"DON'T DM people who ask you to message them\n" +
			"VERIFY admin status from the group member list\n" +
			"CONTACT admins directly from the member list, not via messages\n\n" +
			"🔍 Impersonation Warning:\n" +
			"Check for EXACT username matches - even ONE character difference means it's fake\n" +
			"Official team members will NEVER ask for funds or private information\n\nUse /checkscam to validate admins")

		// Check if auto-mute should be triggered
		var autoMuteTriggered bool
		var highestSimilarity float64
		var mostSimilarUsername string
		var isSimilarFirstName bool
		var isSimilarToAdmin bool

		if settings.AutoMuteEnabled {
			// Check username similarities
			for _, result := range similarUsernames {
				if result.Similarity > highestSimilarity {
					highestSimilarity = result.Similarity
					mostSimilarUsername = result.Username
					isSimilarFirstName = false
					isSimilarToAdmin = false
				}

				if result.Similarity >= settings.AutoMuteThreshold {
					autoMuteTriggered = true
				}
			}

			// Check admin similarities
			for _, result := range similarToAdmins {
				if result.Similarity > highestSimilarity {
					highestSimilarity = result.Similarity
					mostSimilarUsername = result.Username
					isSimilarFirstName = false
					isSimilarToAdmin = true
				}

				if result.Similarity >= settings.AutoMuteThreshold {
					autoMuteTriggered = true
				}
			}

			// Check first name similarities
			for _, result := range similarFirstNames {
				if result.Similarity > highestSimilarity {
					highestSimilarity = result.Similarity
					mostSimilarUsername = result.Username
					isSimilarFirstName = true
					isSimilarToAdmin = false
				}

				if result.Similarity >= settings.AutoMuteThreshold {
					autoMuteTriggered = true
				}
			}
		}

		if autoMuteTriggered {
			log.Printf("DEBUG: Auto-mute triggered for user ID %d with similarity %.2f%% to %s",
				userID, highestSimilarity*100, mostSimilarUsername)

			// Try to auto-mute the user
			err := MuteUser(bot, chatID, userID, settings.MuteDuration)
			if err != nil {
				log.Printf("DEBUG: Failed to mute user with ID %d: %v", userID, err)
				log.Printf("Failed to mute user with ID %d: %v", userID, err)
				notificationText += "\n❌ Failed to auto-mute user due to insufficient permissions."
			} else {
				log.Printf("DEBUG: Successfully muted user ID %d for %.1f hours",
					userID, settings.MuteDuration.Hours())

				muteHours := settings.MuteDuration.Hours()
				if isSimilarFirstName {
					notificationText += fmt.Sprintf(
						"\n🔇 User has been automatically muted for %.1f hours due to first name similarity.",
						muteHours)
				} else if isSimilarToAdmin {
					notificationText += fmt.Sprintf(
						"\n🔇 User has been automatically muted for %.1f hours due to username similarity.",
						muteHours)
				} else {
					notificationText += fmt.Sprintf(
						"\n🔇 User has been automatically muted for %.1f hours due to username similarity.",
						muteHours)
				}
			}
		} else if hasSimilarities && settings.AutoMuteEnabled {
			log.Printf("DEBUG: Similarities found but below auto-mute threshold of %.2f",
				settings.AutoMuteThreshold)
		}

		// Create message config
		// Check if warning is on cooldown for this chat

		msg := tgbotapi.NewMessage(chatID, notificationText)
		msg.ParseMode = "Markdown"

		// Log a truncated version of the message for debugging
		if len(notificationText) > 50 {
			log.Printf("DEBUG: Sending notification message with Markdown (first 50 chars): %s...", notificationText[:50])
		} else {
			log.Printf("DEBUG: Sending notification message with Markdown: %s", notificationText)
		}

		// Send notification to the chat
		if !settings.IsWarningOnCooldown(chatID) {
			_, err := bot.Send(msg)
			if err != nil {
				log.Printf("ERROR: Failed to send similarity notification: %v", err)
			} else {
				// Mark warning as sent for this chat if notification was successful
				settings.MarkWarningSent(chatID)
			}
		}

		// If audit group is configured, send a copy there too
		if settings.AuditGroupID != 0 {
			var err error
			// Verify the audit group exists and is accessible
			chat, err := bot.GetChat(tgbotapi.ChatInfoConfig{ChatConfig: tgbotapi.ChatConfig{ChatID: settings.AuditGroupID}})
			if err != nil {
				log.Printf("ERROR: Failed to access audit group %d: %v", settings.AuditGroupID, err)
				return
			}
			log.Printf("DEBUG: Successfully verified audit group: %s (ID: %d)", chat.Title, chat.ID)

			// Create a concise audit message with only similarity information
			var auditText strings.Builder
			fmt.Fprintf(&auditText, "🔍 Audit from chat %s (ID: %d):\n\n", chatTitle, chatID)

			// Add user identifier
			if username != "" {
				fmt.Fprintf(&auditText, "Scammer: @*%s* - ID: `%d`\n", username, userID)
			} else if fullName != "" {
				fmt.Fprintf(&auditText, "Scammer: *%s* - ID: `%d`\n", fullName, userID)
			} else {
				fmt.Fprintf(&auditText, "User ID: `%d`\n", userID)
			}

			// Add username similarities
			if len(similarUsernames) > 0 {
				auditText.WriteString("\nSimilar to official accounts:\n")
				for _, result := range similarUsernames {
					fmt.Fprintf(&auditText, "- *%s* - Similarity: %.2f%%\n",
						result.Username, result.Similarity*100)
				}
			}

			// Add admin similarities
			if len(similarToAdmins) > 0 {
				auditText.WriteString("\nSimilar to group admins:\n")
				for _, result := range similarToAdmins {
					// Find the admin info to get their user ID
					var adminUserID int64
					for _, admin := range adminInfo {
						if strings.TrimPrefix(result.Username, "@") == admin.Username || result.Username == admin.FirstName {
							adminUserID = admin.UserID
							break
						}
					}

					adminName := strings.TrimPrefix(result.Username, "@")
					if adminUserID > 0 {
						fmt.Fprintf(&auditText, "- *%s* - ID: `%d` - Similarity: %.2f%%\n",
							adminName, adminUserID, result.Similarity*100)
					} else {
						fmt.Fprintf(&auditText, "- *%s* - Similarity: %.2f%%\n",
							adminName, result.Similarity*100)
					}
				}
			}

			// Add first name similarities
			if len(similarFirstNames) > 0 {
				auditText.WriteString("\nSimilar first name to:\n")
				for _, result := range similarFirstNames {
					fmt.Fprintf(&auditText, "- *%s* - Similarity: %.2f%%\n",
						result.Username, result.Similarity*100)
				}
			}

			// Add action taken
			if autoMuteTriggered {
				auditText.WriteString(fmt.Sprintf("\nAction: Auto-muted for %.1f hours\n", settings.MuteDuration.Hours()))
			}
			if settings.DeleteMessages && !isNewUser && replyToMessageID > 0 {
				auditText.WriteString("Action: Message deleted\n")
			}

			auditMsg := tgbotapi.NewMessage(settings.AuditGroupID, auditText.String())
			auditMsg.ParseMode = "Markdown"

			// Log audit message for debugging
			auditMsgContent := auditText.String()
			if len(auditMsgContent) > 50 {
				log.Printf("DEBUG: Sending audit message (first 50 chars): %s...", auditMsgContent[:50])
			} else {
				log.Printf("DEBUG: Sending audit message: %s", auditMsgContent)
			}

			_, err = bot.Send(auditMsg)
			if err != nil {
				log.Printf("ERROR: Failed to send audit notification: %v", err)

				// Try with HTML mode instead of Markdown as a fallback
				auditMsg.ParseMode = "HTML"
				// Convert basic Markdown to HTML
				htmlText := strings.ReplaceAll(auditMsgContent, "*", "<b>")
				htmlText = strings.ReplaceAll(htmlText, "*", "</b>")
				htmlText = strings.ReplaceAll(htmlText, "`", "<code>")
				htmlText = strings.ReplaceAll(htmlText, "`", "</code>")
				auditMsg.Text = htmlText

				_, err = bot.Send(auditMsg)
				if err != nil {
					log.Printf("ERROR: Failed to send audit notification with HTML fallback: %v", err)

					// Last resort: send without formatting
					auditMsg.ParseMode = ""
					auditMsg.Text = strings.ReplaceAll(auditMsgContent, "*", "")
					auditMsg.Text = strings.ReplaceAll(auditMsg.Text, "`", "")
					_, err = bot.Send(auditMsg)
					if err != nil {
						log.Printf("ERROR: Failed to send even plain text audit notification: %v", err)
					} else {
						log.Printf("DEBUG: Sent audit notification as plain text (no formatting)")
					}
				} else {
					log.Printf("DEBUG: Sent audit notification with HTML formatting instead of Markdown")
				}
			}
		}
	}
}

// GetAdminInfo returns admin information for a chat, using cache when available
func (s *BotSettings) GetAdminInfo(bot *tgbotapi.BotAPI, chatID int64) []AdminInfo {
	s.AdminCacheMutex.RLock()

	// Check if we have a cached admin list that's not too old
	if adminList, exists := s.AdminInfo[chatID]; exists {
		lastUpdated := s.AdminCacheTime[chatID]
		if time.Since(lastUpdated) < s.AdminCacheExpiry {
			s.AdminCacheMutex.RUnlock()
			log.Printf("DEBUG: Using cached admin info for chat %d, %d admins",
				chatID, len(adminList))
			return adminList
		}
	}
	s.AdminCacheMutex.RUnlock()

	// Need to update the cache
	return s.UpdateAdminCache(bot, chatID)
}

// UpdateAdminCache refreshes the admin info cache for a specific chat
func (s *BotSettings) UpdateAdminCache(bot *tgbotapi.BotAPI, chatID int64) []AdminInfo {
	var adminInfo []AdminInfo

	// Get chat admins
	chatAdminConfig := tgbotapi.ChatAdministratorsConfig{
		ChatConfig: tgbotapi.ChatConfig{
			ChatID: chatID,
		},
	}

	admins, err := bot.GetChatAdministrators(chatAdminConfig)
	if err != nil {
		log.Printf("Failed to get chat admins for similarity check: %v", err)
		return adminInfo
	}

	// Extract usernames and first names
	for _, admin := range admins {
		info := AdminInfo{
			Username:  admin.User.UserName,
			FirstName: admin.User.FirstName,
			LastName:  admin.User.LastName,
			UserID:    admin.User.ID,
		}

		// Only add if we have at least one piece of identifying information
		if info.Username != "" || info.FirstName != "" || info.LastName != "" {
			adminInfo = append(adminInfo, info)
			log.Printf("DEBUG: Added admin info - UserID: %d, Username: @%s, FirstName: %s, LastName: %s",
				info.UserID, info.Username, info.FirstName, info.LastName)
		}
	}

	// Update the cache
	s.AdminCacheMutex.Lock()
	s.AdminInfo[chatID] = adminInfo
	s.AdminCacheTime[chatID] = time.Now()
	s.AdminCacheMutex.Unlock()

	log.Printf("DEBUG: Updated admin cache for chat %d, found %d admins",
		chatID, len(adminInfo))

	return adminInfo
}

// Define a function to check if a string looks like a valid Telegram username
func isValidUsername(s string) bool {
	// Telegram usernames must be 5-32 characters long
	if len(s) < 5 || len(s) > 32 {
		return false
	}

	// Usernames must be alphanumeric with underscores
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_') {
			return false
		}
	}

	return true
}

// IsUserAdmin checks if a user is an admin in a chat, using the cached admin list when possible
func (s *BotSettings) IsUserAdmin(bot *tgbotapi.BotAPI, chatID int64, userID int64) bool {
	// Get admin info from cache (or update if needed)
	adminInfo := s.GetAdminInfo(bot, chatID)

	// Check if user is in the admin list
	for _, admin := range adminInfo {
		if admin.UserID == userID {
			log.Printf("DEBUG: User ID %d is an admin, confirmed from cache", userID)
			return true
		}
	}

	return false
}

// Check if the bot is an admin
func IsBotAdmin(bot *tgbotapi.BotAPI, chatID int64) bool {
	chatMember, err := bot.GetChatMember(tgbotapi.GetChatMemberConfig{
		ChatConfigWithUser: tgbotapi.ChatConfigWithUser{
			ChatID: chatID,
			UserID: bot.Self.ID,
		},
	})

	if err != nil {
		log.Printf("ERROR: Failed to check bot admin status: %v", err)
		return false
	}

	return chatMember.IsAdministrator() || chatMember.IsCreator()
}

// Check if the bot has necessary permissions
func CheckBotPermissions(bot *tgbotapi.BotAPI, chatID int64) {
	// Get bot's current permissions in the chat
	botMember, err := bot.GetChatMember(tgbotapi.GetChatMemberConfig{
		ChatConfigWithUser: tgbotapi.ChatConfigWithUser{
			ChatID: chatID,
			UserID: bot.Self.ID,
		},
	})

	if err != nil {
		log.Printf("ERROR: Failed to get bot permissions: %v", err)
		return
	}

	// Check if the bot is an admin
	if !botMember.IsAdministrator() && !botMember.IsCreator() {
		log.Printf("WARNING: Bot is not an admin in chat %d - some features will not work", chatID)
		return
	}

	// For administrators, check specific permissions
	if botMember.IsAdministrator() {
		log.Printf("DEBUG: Bot permissions in chat %d:", chatID)

		if botMember.CanRestrictMembers {
			log.Printf("DEBUG: ✅ Bot can restrict members")
		} else {
			log.Printf("WARNING: ❌ Bot cannot restrict members - auto-mute will not work")
		}

		if botMember.CanDeleteMessages {
			log.Printf("DEBUG: ✅ Bot can delete messages")
		} else {
			log.Printf("DEBUG: ❌ Bot cannot delete messages")
		}

		if botMember.CanInviteUsers {
			log.Printf("DEBUG: ✅ Bot can invite users")
		} else {
			log.Printf("DEBUG: ❌ Bot cannot invite users")
		}
	}
}

// GetUserIDFromUsername attempts to get a user's ID from their username
func GetUserIDFromUsername(bot *tgbotapi.BotAPI, username string) (int64, error) {
	// Remove @ symbol if present
	username = strings.TrimPrefix(username, "@")

	// This is a limitation of the Telegram Bot API - we cannot get a user's ID
	// just from their username without having them in a group with the bot
	return 0, fmt.Errorf("unable to get user ID from username. Please use @userinfobot to get the user's ID")
}
