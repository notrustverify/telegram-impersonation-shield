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

// Record start time for uptime tracking
var startTime = time.Now()

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

// JaroWinkler calculates the Jaro-Winkler similarity between two strings
// Returns a value between 0 (completely different) and 1 (identical)
func JaroWinkler(s1, s2 string) float64 {
	// Convert to lowercase for case-insensitive comparison
	s1 = strings.ToLower(s1)
	s2 = strings.ToLower(s2)

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

// FindSimilarUsernames checks a username against known usernames and returns matches above the threshold
func FindSimilarUsernames(username string, threshold float64) []SimilarUsernameResult {
	var results []SimilarUsernameResult

	// Convert input username to lowercase
	usernameLower := strings.ToLower(username)

	for _, knownUsername := range KnownUsernames {
		// Convert known username to lowercase for comparison
		knownUsernameLower := strings.ToLower(knownUsername)
		similarity := JaroWinkler(usernameLower, knownUsernameLower)
		if similarity >= threshold && similarity < 1.0 { // Exclude exact matches
			results = append(results, SimilarUsernameResult{
				Username:   knownUsername, // Keep original case for display
				Similarity: similarity,
			})
		}
	}

	return results
}

// FindSimilarUsernamesWithExceptions checks a username but ignores exceptions
func FindSimilarUsernamesWithExceptions(username string, threshold float64, exceptions *ExceptionsManager) []SimilarUsernameResult {
	var results []SimilarUsernameResult

	// Convert input username to lowercase
	usernameLower := strings.ToLower(username)

	for _, knownUsername := range KnownUsernames {
		// Convert known username to lowercase for comparison
		knownUsernameLower := strings.ToLower(knownUsername)
		similarity := JaroWinkler(usernameLower, knownUsernameLower)
		if similarity >= threshold && similarity < 1.0 { // Exclude exact matches
			results = append(results, SimilarUsernameResult{
				Username:   knownUsername, // Keep original case for display
				Similarity: similarity,
			})
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
	AdminInfo       map[int64][]AdminInfo
	AdminCacheMutex sync.RWMutex
	AdminCacheTime  map[int64]time.Time
	// Exceptions manager
	Exceptions *ExceptionsManager
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

// ScanGroupForSuspiciousUsernames reports users with suspicious usernames
func ScanGroupForSuspiciousUsernames(bot *tgbotapi.BotAPI, settings *BotSettings, message *tgbotapi.Message) {
	chatID := message.Chat.ID

	// Send initial status message
	statusMsg := tgbotapi.NewMessage(chatID, fmt.Sprintf("🔍 Starting scan of usernames and first names in %s...", message.Chat.Title))
	sentMsg, err := bot.Send(statusMsg)
	if err != nil {
		log.Printf("Failed to send initial status message: %v", err)
		return
	}

	// Get admins from cache - more efficient than direct API calls
	admins := settings.GetAdminInfo(bot, chatID)
	if len(admins) == 0 {
		log.Printf("Failed to get chat admins or no admins found")
		editMsg := tgbotapi.NewEditMessageText(chatID, sentMsg.MessageID,
			fmt.Sprintf("❌ Failed to scan group: Could not retrieve admin list"))
		bot.Send(editMsg)
		return
	}

	var suspiciousCount int
	var suspiciousAdmins []string

	// Check admin usernames and first names
	for _, admin := range admins {
		var foundSimilarities bool
		var info strings.Builder
		var userIdentifier string

		// Skip if admin is in exceptions list
		if settings.Exceptions.IsExcepted(admin.UserID) {
			log.Printf("DEBUG: Admin user ID %d is in exceptions list, skipping similarity check", admin.UserID)
			continue
		}

		// Check username first if available
		if admin.Username != "" {
			userIdentifier = "@" + admin.Username
			similarUsernames := FindSimilarUsernames(admin.Username, settings.SimilarityThreshold)

			if len(similarUsernames) > 0 {
				foundSimilarities = true
				suspiciousCount++

				// Format the similar usernames
				fmt.Fprintf(&info, "%s (ID: %d) has similar username to: ",
					userIdentifier, admin.UserID)

				var similarities []string
				for _, similar := range similarUsernames {
					similarities = append(similarities, fmt.Sprintf("%s (%.1f%%)",
						similar.Username, similar.Similarity*100))
				}

				fmt.Fprintf(&info, "%s", strings.Join(similarities, ", "))
			}
		} else if admin.FirstName != "" {
			// Only check first name if username is not available
			userIdentifier = admin.FirstName
			similarFirstNames := FindSimilarUsernames(admin.FirstName, settings.SimilarityThreshold)

			if len(similarFirstNames) > 0 {
				foundSimilarities = true
				suspiciousCount++

				fmt.Fprintf(&info, "%s (ID: %d) has similar first name to: ",
					userIdentifier, admin.UserID)

				var similarities []string
				for _, similar := range similarFirstNames {
					similarities = append(similarities, fmt.Sprintf("%s (%.1f%%)",
						similar.Username, similar.Similarity*100))
				}

				fmt.Fprintf(&info, "%s", strings.Join(similarities, ", "))
			}
		}

		if foundSimilarities {
			suspiciousAdmins = append(suspiciousAdmins, info.String())
		}
	}

	// Update the status message with results
	resultText := fmt.Sprintf("✅ Admin scan complete!\n\nFound %d suspicious admin users\n\n", suspiciousCount)

	if len(suspiciousAdmins) > 0 {
		resultText += "📋 Suspicious Admin Users:\n\n"
		for i, info := range suspiciousAdmins {
			resultText += fmt.Sprintf("%d. %s\n\n", i+1, info)
		}
	} else {
		resultText += "✅ No suspicious admin users found!\n\n"
	}

	resultText += "\n⚠️ Note: Telegram does not allow bots to get a complete list of all members. " +
		"The bot can only check members it has seen sending messages or joining the group.\n\n" +
		"To check a specific user, use the /checkuser @username command."

	// Update the status message
	editMsg := tgbotapi.NewEditMessageText(chatID, sentMsg.MessageID, resultText)
	bot.Send(editMsg)
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

	// Get updates channel
	updates := bot.GetUpdatesChan(updateConfig)

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
		Exceptions:          NewExceptionsManager("exceptions.txt"),
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

	// Start a goroutine to periodically clean up old checked users
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			settings.CleanupOldChecks()
		}
	}()

	// Start a goroutine to periodically refresh admin caches
	go func() {
		ticker := time.NewTicker(30 * time.Minute)
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

		// Check new users joining the chat
		if update.Message != nil && update.Message.NewChatMembers != nil {
			log.Printf("DEBUG: New chat members detected in chat ID %d", update.Message.Chat.ID)

			for _, newUser := range update.Message.NewChatMembers {
				log.Printf("DEBUG: New user joined - ID: %d, Username: @%s, First Name: %s",
					newUser.ID, newUser.UserName, newUser.FirstName)

				// Check if user has a username or first name to check
				if newUser.UserName == "" && newUser.FirstName == "" {
					log.Printf("DEBUG: New user ID %d has no username or first name, skipping", newUser.ID)
					continue
				}

				// If user has no username, log that we're checking first name
				if newUser.UserName == "" && newUser.FirstName != "" {
					log.Printf("DEBUG: New user ID %d has no username, checking first name '%s' instead",
						newUser.ID, newUser.FirstName)
				}

				// Skip checks for admins using the cached admin list
				if update.Message.Chat.IsGroup() || update.Message.Chat.IsSuperGroup() {
					if settings.IsUserAdmin(bot, update.Message.Chat.ID, newUser.ID) {
						log.Printf("DEBUG: New user ID %d (@%s) is an admin, skipping check",
							newUser.ID, newUser.UserName)
						continue
					}
				}

				// Process non-admin new users
				var displayName string
				if newUser.UserName != "" {
					displayName = "@" + newUser.UserName
				} else {
					displayName = newUser.FirstName
				}
				log.Printf("DEBUG: Checking new user %s (ID: %d) for similarity", displayName, newUser.ID)

				// Check username and auto-mute if necessary
				checkAndMuteUser(bot, &settings, update.Message.Chat.ID, newUser.ID, newUser.UserName, newUser.FirstName, true, "", 0, update.Message.Chat.Title)
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

			// Check user if they have username or first name
			if update.Message.From != nil {
				log.Printf("DEBUG: Preparing to check user ID %d for impersonation", update.Message.From.ID)

				// Don't check too frequently
				if !settings.IsRecentlyChecked(update.Message.From.ID) {
					log.Printf("DEBUG: User ID %d passed cooldown check", update.Message.From.ID)

					// Skip checks for admins using the cached admin list
					if update.Message.Chat.IsGroup() || update.Message.Chat.IsSuperGroup() {
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
									update.Message.From.UserName, update.Message.From.FirstName, false, update.Message.Text, update.Message.MessageID, update.Message.Chat.Title)
								log.Printf("DEBUG: COMPLETED similarity check for user ID %d", update.Message.From.ID)
							}
						}
					} else {
						log.Printf("DEBUG: Not a group chat, proceeding with check regardless of admin status")
						// Check private chat messages too
						if update.Message.From.UserName != "" || update.Message.From.FirstName != "" {
							checkAndMuteUser(bot, &settings, update.Message.Chat.ID, update.Message.From.ID,
								update.Message.From.UserName, update.Message.From.FirstName, false, update.Message.Text, update.Message.MessageID, update.Message.Chat.Title)
						}
					}
				} else {
					log.Printf("DEBUG: User ID %d (@%s) was recently checked, skipping due to cooldown",
						update.Message.From.ID, update.Message.From.UserName)
				}
			} else {
				log.Printf("DEBUG: Message has no From field, cannot check user")
			}

			// Process commands
			if update.Message != nil && update.Message.IsCommand() {
				// Get the command and any arguments
				command := update.Message.Command()
				args := update.Message.CommandArguments()

				log.Printf("DEBUG: Received command /%s from user %d (%s) in chat %d (args: '%s')",
					command, update.Message.From.ID, update.Message.From.UserName,
					update.Message.Chat.ID, args)

				// Dump full message details for debugging
				log.Printf("DEBUG: Full message: Chat type: %s, IsGroup: %v, IsSuperGroup: %v, IsPrivate: %v",
					update.Message.Chat.Type,
					update.Message.Chat.IsGroup(),
					update.Message.Chat.IsSuperGroup(),
					update.Message.Chat.IsPrivate())

				// Check if user is an admin in a group chat
				isAdmin := true // Default to true for private chats
				if update.Message.Chat.IsGroup() || update.Message.Chat.IsSuperGroup() {
					isAdmin = settings.IsUserAdmin(bot, update.Message.Chat.ID, update.Message.From.ID)
					log.Printf("DEBUG: User %d (%s) is admin in chat %d: %v",
						update.Message.From.ID, update.Message.From.UserName, update.Message.Chat.ID, isAdmin)

					// If not admin and not using start/help, silently ignore
					if !isAdmin && command != "start" && command != "help" {
						log.Printf("DEBUG: Non-admin user %d tried to use command /%s in group %d",
							update.Message.From.ID, command, update.Message.Chat.ID)

						continue
					}
				}

				// Extra debug for the most common commands
				if command == "start" || command == "help" {
					log.Printf("DEBUG: Processing common command /%s", command)
				}

				// Now process the commands
				switch command {
				case "start":
					startText := "👋 Hello! I'm a Telegram Bot that helps prevent username impersonation attacks.\n\n" +
						"I'll monitor your group for users with usernames too similar to those you want to protect.\n\n" +
						"Add me to your group and make me an admin to get started.\n\n" +
						"Type /help for more information on how to use me."

					msg := tgbotapi.NewMessage(update.Message.Chat.ID, startText)
					log.Printf("DEBUG: Sending start message to chat %d", update.Message.Chat.ID)

					sentMsg, err := bot.Send(msg)
					if err != nil {
						log.Printf("ERROR: Failed to send start message: %v", err)

						// Detailed error info for debugging
						if strings.Contains(err.Error(), "forbidden") {
							log.Printf("ERROR: Bot doesn't have permission to send messages in this chat")
						} else if strings.Contains(err.Error(), "chat not found") {
							log.Printf("ERROR: Chat not found - chat ID: %d", update.Message.Chat.ID)
						} else if strings.Contains(err.Error(), "bot was blocked") {
							log.Printf("ERROR: Bot was blocked by the user")
						}
					} else {
						log.Printf("DEBUG: Start message sent successfully (ID: %d)", sentMsg.MessageID)
					}

				case "help":
					helpText := "📋 **Commands**:\n" +
						"- `/add [username]` - Add a username to the protected list\n" +
						"- `/remove [username]` - Remove a username from the protected list\n" +
						"- `/list` - Show all protected usernames\n" +
						"- `/check [username]` - Check if a username is similar to protected ones\n" +
						"- `/scangroup` - Scan all admins in the group for suspicious usernames\n" +
						"- `/removeall [threshold]` - Remove all non-admin users with suspicious usernames\n" +
						"- `/threshold [value]` - Set similarity threshold (0.1-0.9, default: 0.75)\n" +
						"- `/automute [on/off]` - Enable/disable automatic muting\n" +
						"- `/cooldown [minutes]` - Set how often the same user is checked (0 = always)\n" +
						"- `/addexception [user_id]` - Add user ID to exceptions list (ignored in checks)\n" +
						"- `/removeexception [user_id]` - Remove user ID from exceptions list\n" +
						"- `/listexceptions` - Show all user IDs in exceptions list\n" +
						"- `/deletemessages [on/off]` - Enable/disable automatic message deletion\n\n" +
						"ℹ️ **Note**: Most commands only work for admins in group chats.\n\n" +
						"ℹ️ **Getting User IDs**:\n" +
						"To get a user's ID:\n" +
						"1. Message @userinfobot\n" +
						"2. Forward a message from the user\n" +
						"3. The bot will show you the user's ID\n\n" +
						"🔒 Add me to a group as an admin to enable full protection!"

					msg := tgbotapi.NewMessage(update.Message.Chat.ID, helpText)
					msg.ParseMode = "Markdown"
					log.Printf("DEBUG: Sending help message to chat %d", update.Message.Chat.ID)

					sentMsg, err := bot.Send(msg)
					if err != nil {
						log.Printf("ERROR: Failed to send help message: %v", err)

						// Try sending without markdown if that might be the issue
						if strings.Contains(err.Error(), "can't parse entities") {
							log.Printf("DEBUG: Trying to send help message without markdown")
							msg.ParseMode = ""
							sentMsg, err = bot.Send(msg)
							if err != nil {
								log.Printf("ERROR: Failed to send help message without markdown: %v", err)
							} else {
								log.Printf("DEBUG: Help message sent successfully without markdown (ID: %d)", sentMsg.MessageID)
							}
						} else if strings.Contains(err.Error(), "forbidden") {
							log.Printf("ERROR: Bot doesn't have permission to send messages in this chat")
						}
					} else {
						log.Printf("DEBUG: Help message sent successfully (ID: %d)", sentMsg.MessageID)
					}

				case "threshold":
					// Parse threshold value
					args := update.Message.CommandArguments()
					if args == "" {
						msg := tgbotapi.NewMessage(update.Message.Chat.ID,
							fmt.Sprintf("Current threshold is %.2f. Use /threshold [value] to change it.",
								settings.SimilarityThreshold))
						bot.Send(msg)
						continue
					}

					var newThreshold float64
					_, err := fmt.Sscanf(args, "%f", &newThreshold)
					if err != nil || newThreshold < 0 || newThreshold > 1 {
						msg := tgbotapi.NewMessage(update.Message.Chat.ID,
							"Invalid threshold value. Must be between 0 and 1.")
						bot.Send(msg)
						continue
					}

					settings.SimilarityThreshold = newThreshold
					msg := tgbotapi.NewMessage(update.Message.Chat.ID,
						fmt.Sprintf("Threshold set to %.2f", settings.SimilarityThreshold))
					bot.Send(msg)

				case "count":
					msg := tgbotapi.NewMessage(update.Message.Chat.ID,
						fmt.Sprintf("Currently tracking %d usernames for similarity detection.",
							len(KnownUsernames)))
					bot.Send(msg)

				case "automute":
					// Parse automute setting
					args := update.Message.CommandArguments()
					if args == "" {
						status := "disabled"
						if settings.AutoMuteEnabled {
							status = "enabled"
						}
						msg := tgbotapi.NewMessage(update.Message.Chat.ID,
							fmt.Sprintf("Auto-mute is currently %s. Use /automute on or /automute off to change.",
								status))
						bot.Send(msg)
						continue
					}

					args = strings.ToLower(args)
					if args == "on" || args == "enable" || args == "true" || args == "1" {
						settings.AutoMuteEnabled = true
						msg := tgbotapi.NewMessage(update.Message.Chat.ID,
							fmt.Sprintf("Auto-mute enabled. Users with similarity >= %.2f will be automatically muted.",
								settings.AutoMuteThreshold))
						bot.Send(msg)
					} else if args == "off" || args == "disable" || args == "false" || args == "0" {
						settings.AutoMuteEnabled = false
						msg := tgbotapi.NewMessage(update.Message.Chat.ID, "Auto-mute disabled.")
						bot.Send(msg)
					} else {
						msg := tgbotapi.NewMessage(update.Message.Chat.ID,
							"Invalid value. Use 'on' or 'off' to enable or disable auto-mute.")
						bot.Send(msg)
					}

				case "mutethreshold":
					// Parse mute threshold value
					args := update.Message.CommandArguments()
					if args == "" {
						msg := tgbotapi.NewMessage(update.Message.Chat.ID,
							fmt.Sprintf("Current auto-mute threshold is %.2f. Use /mutethreshold [value] to change it.",
								settings.AutoMuteThreshold))
						bot.Send(msg)
						continue
					}

					var newThreshold float64
					_, err := fmt.Sscanf(args, "%f", &newThreshold)
					if err != nil || newThreshold < 0 || newThreshold > 1 {
						msg := tgbotapi.NewMessage(update.Message.Chat.ID,
							"Invalid threshold value. Must be between 0 and 1.")
						bot.Send(msg)
						continue
					}

					settings.AutoMuteThreshold = newThreshold
					msg := tgbotapi.NewMessage(update.Message.Chat.ID,
						fmt.Sprintf("Auto-mute threshold set to %.2f", settings.AutoMuteThreshold))
					bot.Send(msg)

				case "muteduration":
					// Parse mute duration in hours
					args := update.Message.CommandArguments()
					if args == "" {
						msg := tgbotapi.NewMessage(update.Message.Chat.ID,
							fmt.Sprintf("Current mute duration is %.1f hours. Use /muteduration [hours] to change it.",
								settings.MuteDuration.Hours()))
						bot.Send(msg)
						continue
					}

					var hours float64
					_, err := fmt.Sscanf(args, "%f", &hours)
					if err != nil || hours <= 0 {
						msg := tgbotapi.NewMessage(update.Message.Chat.ID,
							"Invalid duration. Must be a positive number of hours.")
						bot.Send(msg)
						continue
					}

					settings.MuteDuration = time.Duration(hours * float64(time.Hour))
					msg := tgbotapi.NewMessage(update.Message.Chat.ID,
						fmt.Sprintf("Mute duration set to %.1f hours", hours))
					bot.Send(msg)

				case "mute":
					// Check if the message is a reply to another message
					if update.Message.ReplyToMessage == nil {
						msg := tgbotapi.NewMessage(update.Message.Chat.ID,
							"You must reply to a message from the user you want to mute.")
						bot.Send(msg)
						continue
					}

					// Get the user to mute
					userToMute := update.Message.ReplyToMessage.From
					if userToMute == nil {
						msg := tgbotapi.NewMessage(update.Message.Chat.ID,
							"Cannot identify the user to mute.")
						bot.Send(msg)
						continue
					}

					// Try to mute the user
					err := MuteUser(bot, update.Message.Chat.ID, userToMute.ID, settings.MuteDuration)
					if err != nil {
						log.Printf("Failed to mute user %s: %v", userToMute.UserName, err)
						msg := tgbotapi.NewMessage(update.Message.Chat.ID,
							"Failed to mute user. Make sure the bot has the necessary permissions.")
						bot.Send(msg)
					} else {
						muteHours := settings.MuteDuration.Hours()
						msg := tgbotapi.NewMessage(update.Message.Chat.ID,
							fmt.Sprintf("User @%s has been muted for %.1f hours.",
								userToMute.UserName, muteHours))
						bot.Send(msg)
					}

				case "checkuser":
					// Parse username to check
					args := update.Message.CommandArguments()
					if args == "" {
						msg := tgbotapi.NewMessage(update.Message.Chat.ID,
							"Please specify a username or first name to check. Format: /checkuser username OR /checkuser firstname")
						bot.Send(msg)
						continue
					}

					// Parse input arguments
					parts := strings.Fields(args)
					var username, firstName string

					// First argument is either username or firstname
					firstArg := strings.TrimPrefix(parts[0], "@")

					// Determine if this is likely a username or first name
					if strings.HasPrefix(parts[0], "@") || isValidUsername(firstArg) {
						username = firstArg
					} else {
						// If it doesn't look like a username, treat it as a first name
						firstName = firstArg
					}

					// If there are more arguments and we identified first one as username,
					// treat the rest as a first name
					if len(parts) > 1 && username != "" {
						firstName = strings.Join(parts[1:], " ")
					}

					// Build response message
					var responseText strings.Builder
					var similarUsernames, similarFirstNames []SimilarUsernameResult
					var totalResults int

					// Check username if provided
					if username != "" {
						// Check similarity
						similarUsernames = FindSimilarUsernamesWithExceptions(username, settings.SimilarityThreshold, nil)
						if len(similarUsernames) > 0 {
							totalResults += len(similarUsernames)
							fmt.Fprintf(&responseText, "Found %d similar username(s) for '@%s':\n\n",
								len(similarUsernames), username)

							for i, result := range similarUsernames {
								fmt.Fprintf(&responseText, "%d. %s (%.2f%% similarity)\n",
									i+1, result.Username, result.Similarity*100)
							}
						} else {
							fmt.Fprintf(&responseText, "No similar usernames found for '@%s'\n", username)
						}
					}

					// Check first name only if no username was provided or specifically requested
					if firstName != "" && (username == "" || len(parts) > 1) {
						similarFirstNames = FindSimilarUsernamesWithExceptions(firstName, settings.SimilarityThreshold, nil)
						if len(similarFirstNames) > 0 {
							totalResults += len(similarFirstNames)
							if username != "" {
								fmt.Fprintf(&responseText, "\nAdditionally, found %d similar name(s) for '%s':\n\n",
									len(similarFirstNames), firstName)
							} else {
								fmt.Fprintf(&responseText, "Found %d similar name(s) for '%s':\n\n",
									len(similarFirstNames), firstName)
							}

							for i, result := range similarFirstNames {
								fmt.Fprintf(&responseText, "%d. %s (%.2f%% similarity)\n",
									i+1, result.Username, result.Similarity*100)
							}
						} else if username != "" {
							fmt.Fprintf(&responseText, "\nNo similar names found for '%s'\n", firstName)
						} else {
							fmt.Fprintf(&responseText, "No similar names found for '%s'\n", firstName)
						}
					}

					if totalResults > 0 {
						fmt.Fprintf(&responseText, "\n⚠️ Be careful with similar usernames and names as they might be impersonators!")
					}

					msg := tgbotapi.NewMessage(update.Message.Chat.ID, responseText.String())
					bot.Send(msg)

				case "removeall":
					// Check if this is a group chat
					if !update.Message.Chat.IsGroup() && !update.Message.Chat.IsSuperGroup() {
						msg := tgbotapi.NewMessage(update.Message.Chat.ID,
							"This command only works in groups.")
						bot.Send(msg)
						continue
					}

					// Instead of attempting to scan and remove, explain the limitations
					warningMsg := tgbotapi.NewMessage(update.Message.Chat.ID,
						"⚠️ Limitation: This bot can only detect users when they send messages or join the group.\n\n"+
							"For better protection:\n"+
							"1. Keep the bot as an admin in your group\n"+
							"2. Enable auto-mute with `/automute on`\n"+
							"3. Set an appropriate threshold with `/mutethreshold 0.9`\n\n"+
							"The bot will automatically detect and mute suspicious users as they join or post messages.")
					bot.Send(warningMsg)

				case "debug":
					// Generate debug info
					debugText := "🔍 Bot Debug Information\n\n"

					// Bot info
					debugText += fmt.Sprintf("Bot Username: @%s\n", bot.Self.UserName)
					debugText += fmt.Sprintf("Bot ID: %d\n\n", bot.Self.ID)

					// Settings info
					debugText += fmt.Sprintf("Similarity Threshold: %.2f\n", settings.SimilarityThreshold)
					debugText += fmt.Sprintf("Auto-Mute: %t\n", settings.AutoMuteEnabled)
					debugText += fmt.Sprintf("Auto-Mute Threshold: %.2f\n", settings.AutoMuteThreshold)
					debugText += fmt.Sprintf("Mute Duration: %.1f hours\n", settings.MuteDuration.Hours())
					debugText += fmt.Sprintf("Check Cooldown: %.1f minutes\n\n", settings.CheckCooldown.Minutes())

					// Resource info
					debugText += fmt.Sprintf("Known Usernames: %d\n", len(KnownUsernames))

					// Exceptions info
					settings.Exceptions.mutex.RLock()
					debugText += fmt.Sprintf("Exceptions: %d\n", len(settings.Exceptions.Exceptions))
					// Show up to 5 exceptions as examples
					if len(settings.Exceptions.Exceptions) > 0 {
						debugText += "Example exceptions: "
						count := 0
						for userID := range settings.Exceptions.Exceptions {
							if count > 0 {
								debugText += ", "
							}
							debugText += fmt.Sprintf("%d", userID)
							count++
							if count >= 5 {
								break
							}
						}
						debugText += "\n"
					}
					settings.Exceptions.mutex.RUnlock()
					debugText += "\n"

				case "cooldown":
					// Parse cooldown value
					args := update.Message.CommandArguments()
					if args == "" {
						if settings.CheckCooldown <= 0 {
							msg := tgbotapi.NewMessage(update.Message.Chat.ID,
								"Cooldown system is currently disabled. All messages will be checked. Use /cooldown [minutes] to set a cooldown.")
							bot.Send(msg)
						} else {
							msg := tgbotapi.NewMessage(update.Message.Chat.ID,
								fmt.Sprintf("Current cooldown between checks is %.1f minutes. Use /cooldown [minutes] to change it, or /cooldown 0 to disable.",
									settings.CheckCooldown.Minutes()))
							bot.Send(msg)
						}
						continue
					}

					var minutes float64
					_, err := fmt.Sscanf(args, "%f", &minutes)
					if err != nil || minutes < 0 {
						msg := tgbotapi.NewMessage(update.Message.Chat.ID,
							"Invalid duration. Must be a non-negative number of minutes (0 to disable cooldown).")
						bot.Send(msg)
						continue
					}

					settings.CheckCooldown = time.Duration(minutes * float64(time.Minute))

					var responseMsg string
					if minutes == 0 {
						responseMsg = "Cooldown system disabled. All messages will be checked."
					} else {
						responseMsg = fmt.Sprintf("Cooldown set to %.1f minutes", minutes)
					}

					msg := tgbotapi.NewMessage(update.Message.Chat.ID, responseMsg)
					bot.Send(msg)

				case "addexception":
					// Check if user is admin
					if !isAdmin {
						log.Printf("DEBUG: Non-admin user %d tried to use command /%s in group %d",
							update.Message.From.ID, command, update.Message.Chat.ID)
						continue
					}

					// Parse user ID or username to add as exception
					args := update.Message.CommandArguments()
					if args == "" {
						msg := tgbotapi.NewMessage(update.Message.Chat.ID,
							"Please specify a user ID or username to add as an exception.\n\n"+
								"Format: /addexception [user_id] OR /addexception [username]\n\n"+
								"Note: If using username, the user must be in a group with the bot.\n"+
								"Alternatively, you can get the user's ID using @userinfobot")
						bot.Send(msg)
						continue
					}

					// Try to parse as user ID first
					userID, err := strconv.ParseInt(strings.TrimSpace(args), 10, 64)
					if err != nil {
						// If not a valid user ID, try to get ID from username
						userID, err = GetUserIDFromUsername(bot, args)
						if err != nil {
							msg := tgbotapi.NewMessage(update.Message.Chat.ID,
								"Invalid input. Please provide either:\n"+
									"1. A valid numeric user ID\n"+
									"2. A username (user must be in a group with the bot)\n\n"+
									"To get a user's ID:\n"+
									"1. Message @userinfobot\n"+
									"2. Forward a message from the user\n"+
									"3. The bot will show you the user's ID")
							bot.Send(msg)
							continue
						}
					}

					// Add user ID to exceptions
					err = settings.Exceptions.AddException(userID)
					if err != nil {
						log.Printf("ERROR: Failed to add exception for user ID %d: %v", userID, err)
						msg := tgbotapi.NewMessage(update.Message.Chat.ID,
							fmt.Sprintf("Failed to add exception for user ID %d: %v", userID, err))
						bot.Send(msg)
						continue
					}

					msg := tgbotapi.NewMessage(update.Message.Chat.ID,
						fmt.Sprintf("Added user ID %d to exceptions list. This user will now be ignored in similarity checks.", userID))
					bot.Send(msg)

				case "removeexception":
					// Check if user is admin
					if !isAdmin {
						log.Printf("DEBUG: Non-admin user %d tried to use command /%s in group %d",
							update.Message.From.ID, command, update.Message.Chat.ID)
						continue
					}

					// Parse user ID to remove from exceptions
					args := update.Message.CommandArguments()
					if args == "" {
						msg := tgbotapi.NewMessage(update.Message.Chat.ID,
							"Please specify a user ID to remove from exceptions.\n\n"+
								"Format: /removeexception [user_id]\n\n"+
								"To get a user's ID:\n"+
								"1. Message @userinfobot\n"+
								"2. Forward a message from the user\n"+
								"3. The bot will show you the user's ID")
						bot.Send(msg)
						continue
					}

					// Parse user ID
					userID, err := strconv.ParseInt(strings.TrimSpace(args), 10, 64)
					if err != nil {
						msg := tgbotapi.NewMessage(update.Message.Chat.ID,
							"Invalid user ID. Please provide a valid numeric user ID.\n\n"+
								"To get a user's ID:\n"+
								"1. Message @userinfobot\n"+
								"2. Forward a message from the user\n"+
								"3. The bot will show you the user's ID")
						bot.Send(msg)
						continue
					}

					// Remove user ID from exceptions
					err = settings.Exceptions.RemoveException(userID)
					if err != nil {
						log.Printf("ERROR: Failed to remove exception for user ID %d: %v", userID, err)
						msg := tgbotapi.NewMessage(update.Message.Chat.ID,
							fmt.Sprintf("Failed to remove exception for user ID %d: %v", userID, err))
						bot.Send(msg)
						continue
					}

					msg := tgbotapi.NewMessage(update.Message.Chat.ID,
						fmt.Sprintf("Removed user ID %d from exceptions list. This user will now be checked in similarity checks.", userID))
					bot.Send(msg)

				case "listexceptions":
					// Check if user is admin
					if !isAdmin {
						log.Printf("DEBUG: Non-admin user %d tried to use command /%s in group %d",
							update.Message.From.ID, command, update.Message.Chat.ID)
						continue
					}

					// Get list of exceptions
					exceptions := settings.Exceptions.ListExceptions()

					var responseText string
					if len(exceptions) == 0 {
						responseText = "No user ID exceptions configured. Use /addexception to add users to ignore in similarity checks."
					} else {
						responseText = fmt.Sprintf("📋 Exceptions list (%d users):\n\n", len(exceptions))
						for i, userID := range exceptions {
							responseText += fmt.Sprintf("%d. User ID: %d\n", i+1, userID)
						}
						responseText += "\nThese users are ignored in similarity checks."
					}

					msg := tgbotapi.NewMessage(update.Message.Chat.ID, responseText)
					bot.Send(msg)

				case "deletemessages":
					// Parse delete messages setting
					args := update.Message.CommandArguments()
					if args == "" {
						status := "disabled"
						if settings.DeleteMessages {
							status = "enabled"
						}
						msg := tgbotapi.NewMessage(update.Message.Chat.ID,
							fmt.Sprintf("Message deletion is currently %s. Use /deletemessages on or /deletemessages off to change.",
								status))
						bot.Send(msg)
						continue
					}

					args = strings.ToLower(args)
					if args == "on" || args == "enable" || args == "true" || args == "1" {
						settings.DeleteMessages = true
						msg := tgbotapi.NewMessage(update.Message.Chat.ID,
							"Message deletion enabled. Messages from users with similar usernames will be automatically deleted.")
						bot.Send(msg)
					} else if args == "off" || args == "disable" || args == "false" || args == "0" {
						settings.DeleteMessages = false
						msg := tgbotapi.NewMessage(update.Message.Chat.ID,
							"Message deletion disabled. Messages from users with similar usernames will be kept.")
						bot.Send(msg)
					} else {
						msg := tgbotapi.NewMessage(update.Message.Chat.ID,
							"Invalid value. Use 'on' or 'off' to enable or disable message deletion.")
						bot.Send(msg)
					}

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
func checkAndMuteUser(bot *tgbotapi.BotAPI, settings *BotSettings, chatID int64, userID int64, username string, firstName string, isNewUser bool, messageText string, replyToMessageID int, chatTitle string) {
	var similarUsernames []SimilarUsernameResult
	var similarFirstNames []SimilarUsernameResult
	var similarToAdmins []SimilarUsernameResult
	var hasSimilarities bool

	// First check if the user is in exceptions list
	if settings.Exceptions.IsExcepted(userID) {
		log.Printf("DEBUG: User ID %d is in exceptions list, skipping similarity check", userID)
		return
	}

	// Convert username and firstName to lowercase
	username = strings.ToLower(username)
	firstName = strings.ToLower(firstName)

	// Get admin list for additional checking
	adminInfo := settings.GetAdminInfo(bot, chatID)

	// First check username if available
	if username != "" {
		log.Printf("DEBUG: Checking username @%s against %d known usernames with threshold %.2f",
			username, len(KnownUsernames), settings.SimilarityThreshold)

		// Check for similar usernames
		similarUsernames = FindSimilarUsernamesWithExceptions(username, settings.SimilarityThreshold, nil)

		// Also check similarity against admin usernames and first names
		for _, admin := range adminInfo {
			// Skip if admin is in exceptions list
			if settings.Exceptions.IsExcepted(admin.UserID) {
				continue
			}

			// Check against admin username if available
			if admin.Username != "" {
				adminUsernameLower := strings.ToLower(admin.Username)
				similarity := JaroWinkler(username, adminUsernameLower)
				if similarity >= settings.SimilarityThreshold && similarity < 1.0 { // Exclude exact matches
					similarToAdmins = append(similarToAdmins, SimilarUsernameResult{
						Username:   "@" + admin.Username, // Keep original case for display
						Similarity: similarity,
					})
				}
			}

			// Check against admin first name if available
			if admin.FirstName != "" {
				adminFirstNameLower := strings.ToLower(admin.FirstName)
				similarity := JaroWinkler(username, adminFirstNameLower)
				if similarity >= settings.SimilarityThreshold && similarity < 1.0 { // Exclude exact matches
					similarToAdmins = append(similarToAdmins, SimilarUsernameResult{
						Username:   admin.FirstName, // First name, no @ symbol
						Similarity: similarity,
					})
				}
			}
		}

		hasSimilarities = len(similarUsernames) > 0 || len(similarToAdmins) > 0

		if len(similarUsernames) > 0 {
			log.Printf("DEBUG: Found %d similar usernames for @%s", len(similarUsernames), username)
			for i, result := range similarUsernames {
				log.Printf("DEBUG: Similar username #%d: %s (%.2f%% similarity)",
					i+1, result.Username, result.Similarity*100)
			}
		}

		if len(similarToAdmins) > 0 {
			log.Printf("DEBUG: Found %d admin identifiers similar to @%s", len(similarToAdmins), username)
			for i, result := range similarToAdmins {
				log.Printf("DEBUG: Similar admin identifier #%d: %s (%.2f%% similarity)",
					i+1, result.Username, result.Similarity*100)
			}
		}

		if !hasSimilarities {
			log.Printf("DEBUG: No similar usernames found for @%s", username)
		}
	}

	// Only check first name if username is not available or had no matches
	if !hasSimilarities && firstName != "" {
		log.Printf("DEBUG: Checking first name '%s' as fallback", firstName)

		similarFirstNames = FindSimilarUsernamesWithExceptions(firstName, settings.SimilarityThreshold, nil)

		// Also check similarity against admin usernames and first names
		for _, admin := range adminInfo {
			// Skip if admin is in exceptions list
			if settings.Exceptions.IsExcepted(admin.UserID) {
				continue
			}

			// Check against admin username if available
			if admin.Username != "" {
				adminUsernameLower := strings.ToLower(admin.Username)
				similarity := JaroWinkler(firstName, adminUsernameLower)
				if similarity >= settings.SimilarityThreshold && similarity < 1.0 { // Exclude exact matches
					similarToAdmins = append(similarToAdmins, SimilarUsernameResult{
						Username:   "@" + admin.Username, // Keep original case for display
						Similarity: similarity,
					})
				}
			}

			// Check against admin first name if available
			if admin.FirstName != "" {
				adminFirstNameLower := strings.ToLower(admin.FirstName)
				similarity := JaroWinkler(firstName, adminFirstNameLower)
				if similarity >= settings.SimilarityThreshold && similarity < 1.0 { // Exclude exact matches
					similarToAdmins = append(similarToAdmins, SimilarUsernameResult{
						Username:   admin.FirstName, // First name, no @ symbol
						Similarity: similarity,
					})
				}
			}
		}

		hasSimilarities = len(similarFirstNames) > 0 || len(similarToAdmins) > 0

		if len(similarFirstNames) > 0 {
			log.Printf("DEBUG: Found %d similar names for first name '%s'", len(similarFirstNames), firstName)
			for i, result := range similarFirstNames {
				log.Printf("DEBUG: Similar name #%d: %s (%.2f%% similarity)",
					i+1, result.Username, result.Similarity*100)
			}
		}

		if !hasSimilarities {
			log.Printf("DEBUG: No similar names found for first name '%s'", firstName)
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
			userIdentifier = fmt.Sprintf("@%s (ID: %d)", username, userID)
		} else if firstName != "" {
			userIdentifier = fmt.Sprintf("%s (ID: %d)", firstName, userID)
		} else {
			userIdentifier = fmt.Sprintf("User ID %d", userID)
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
				notificationText += fmt.Sprintf("%s (%.2f%% similarity)\n",
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

				if adminUserID > 0 {
					notificationText += fmt.Sprintf("%s (ID: %d) (%.2f%% similarity)\n",
						strings.TrimPrefix(result.Username, "@"), adminUserID, result.Similarity*100)
				} else {
					notificationText += fmt.Sprintf("%s (%.2f%% similarity)\n",
						strings.TrimPrefix(result.Username, "@"), result.Similarity*100)
				}
			}
		}

		// First name similarities (should only happen if username was empty)
		if len(similarFirstNames) > 0 {
			notificationText += "\nhas similar first name to:\n"
			for _, result := range similarFirstNames {
				notificationText += fmt.Sprintf("%s (%.2f%% similarity)\n",
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
						"\n🔇 User has been automatically muted for %.1f hours due to first name similarity (%.2f%%) with %s.",
						muteHours, highestSimilarity*100, mostSimilarUsername)
				} else if isSimilarToAdmin {
					notificationText += fmt.Sprintf(
						"\n🔇 User has been automatically muted for %.1f hours due to username similarity (%.2f%%) with admin %s.",
						muteHours, highestSimilarity*100, mostSimilarUsername)
				} else {
					notificationText += fmt.Sprintf(
						"\n🔇 User has been automatically muted for %.1f hours due to username similarity (%.2f%%) with %s.",
						muteHours, highestSimilarity*100, mostSimilarUsername)
				}
			}
		} else if hasSimilarities && settings.AutoMuteEnabled {
			log.Printf("DEBUG: Similarities found but below auto-mute threshold of %.2f",
				settings.AutoMuteThreshold)
		}

		// Create message config
		msg := tgbotapi.NewMessage(chatID, notificationText)

		// Send notification to the chat
		_, err := bot.Send(msg)
		if err != nil {
			log.Printf("ERROR: Failed to send similarity notification: %v", err)

			// Check if it might be a permission issue
			if strings.Contains(err.Error(), "forbidden") || strings.Contains(err.Error(), "not enough rights") {
				log.Printf("WARNING: This appears to be a permission issue. Make sure the bot is an admin in the group.")

				// Check bot's admin status
				isAdmin := IsBotAdmin(bot, chatID)
				log.Printf("DEBUG: Bot is admin in chat %d: %v", chatID, isAdmin)

				// Check specific permissions if admin
				if isAdmin {
					CheckBotPermissions(bot, chatID)
				}
			}
		}

		// If audit group is configured, send a copy there too
		if settings.AuditGroupID != 0 {
			// Create a concise audit message with only similarity information
			var auditText strings.Builder
			fmt.Fprintf(&auditText, "🔍 Audit from chat %s (ID: %d):\n\n", chatTitle, chatID)

			// Add user identifier
			if username != "" {
				fmt.Fprintf(&auditText, "Scammer: @%s (ID: %d)\n", username, userID)
			} else if firstName != "" {
				fmt.Fprintf(&auditText, "Scammer: %s (ID: %d)\n", firstName, userID)
			} else {
				fmt.Fprintf(&auditText, "User ID: %d\n", userID)
			}

			// Add username similarities
			if len(similarUsernames) > 0 {
				auditText.WriteString("\nSimilar to official accounts:\n")
				for _, result := range similarUsernames {
					fmt.Fprintf(&auditText, "- %s (%.2f%% similarity)\n",
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

					if adminUserID > 0 {
						fmt.Fprintf(&auditText, "- %s (ID: %d) (%.2f%% similarity)\n",
							strings.TrimPrefix(result.Username, "@"), adminUserID, result.Similarity*100)
					} else {
						fmt.Fprintf(&auditText, "- %s (%.2f%% similarity)\n",
							strings.TrimPrefix(result.Username, "@"), result.Similarity*100)
					}
				}
			}

			// Add first name similarities
			if len(similarFirstNames) > 0 {
				auditText.WriteString("\nSimilar first name to:\n")
				for _, result := range similarFirstNames {
					fmt.Fprintf(&auditText, "- %s (%.2f%% similarity)\n",
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
			_, err = bot.Send(auditMsg)
			if err != nil {
				log.Printf("ERROR: Failed to send audit notification: %v", err)
			}
		}
	}
}

// GetAdminInfo returns admin information for a chat, using cache when available
func (s *BotSettings) GetAdminInfo(bot *tgbotapi.BotAPI, chatID int64) []AdminInfo {
	s.AdminCacheMutex.RLock()

	// Check if we have a cached admin list that's not too old (less than 30 minutes)
	if adminList, exists := s.AdminInfo[chatID]; exists {
		lastUpdated := s.AdminCacheTime[chatID]
		if time.Since(lastUpdated) < 30*time.Minute {
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
			UserID:    admin.User.ID,
		}

		// Only add if we have at least one piece of identifying information
		if info.Username != "" || info.FirstName != "" {
			adminInfo = append(adminInfo, info)
			log.Printf("DEBUG: Added admin info - UserID: %d, Username: @%s, FirstName: %s",
				info.UserID, info.Username, info.FirstName)
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
