package main

import (
	"fmt"
	"log"
	"runtime"
	"strconv"
	"strings"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// HandleCommand processes all bot commands
func HandleCommand(bot *tgbotapi.BotAPI, settings *BotSettings, update *tgbotapi.Update) bool {
	if update.Message == nil || !update.Message.IsCommand() {
		return false
	}

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

			return true
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
		helpText := "📋 **Commands Available to All Users**:\n" +
			"- `/start` - Get basic information about the bot\n" +
			"- `/help` - Show this help message\n\n" +

			"**🔑 Authorized User Commands** (only for users in the file):\n" +
			"- `/addexception [user_id]` - Add user ID to exceptions list (ignored in checks)\n" +
			"- `/rmexception [user_id]` - Remove user ID from exceptions list\n" +
			"- `/listexceptions` - Show all user IDs in exceptions list\n" +
			"- `/add [username]` - Add a username to the protected list\n" +
			"- `/remove [username]` - Remove a username from the protected list\n" +
			"- `/list` - Show all protected usernames\n" +
			"- `/check [username]` - Check if a username is similar to protected ones\n" +
			"- `/scangroup` - Scan all admins in the group for suspicious usernames\n" +
			"- `/removeall [threshold]` - Remove all non-admin users with suspicious usernames\n" +
			"- `/threshold [value]` - Set similarity threshold (0.1-0.9, default: 0.75)\n" +
			"- `/automute [on/off]` - Enable/disable automatic muting\n" +
			"- `/cooldown [minutes]` - Set how often the same user is checked (0 = always)\n" +
			"- `/deletemessages [on/off]` - Enable/disable automatic message deletion\n" +
			"- `/addauthmanager [user_id]` - Add a user who can manage exceptions and use admin commands\n" +
			"- `/removeauthmanager [user_id]` - Remove a user from authorized managers\n" +
			"- `/listauthmanagers` - List all authorized managers\n" +
			"- `/mute [reply to message]` - Mute a user manually\n" +
			"- `/debug` - Show debug information about the bot\n\n" +

			"ℹ️ **Note**: All administration commands can ONLY be used by authorized users listed in the file, not by regular Telegram admins.\n\n" +
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

	case "addexception":
		// Only allow authorized managers to add exceptions
		if !settings.ExceptionAuth.IsAuthorized(update.Message.From.ID) {
			log.Printf("DEBUG: User %d (@%s) tried to use /addexception but is not authorized",
				update.Message.From.ID, update.Message.From.UserName)

			return true
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
			return true
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
				return true
			}
		}

		// Add user ID to exceptions
		err = settings.Exceptions.AddException(userID)
		if err != nil {
			log.Printf("ERROR: Failed to add exception for user ID %d: %v", userID, err)
			msg := tgbotapi.NewMessage(update.Message.Chat.ID,
				fmt.Sprintf("Failed to add exception for user ID %d: %v", userID, err))
			bot.Send(msg)
			return true
		}

		msg := tgbotapi.NewMessage(update.Message.Chat.ID,
			fmt.Sprintf("Added user ID `%d` to exceptions list. This user will now be ignored in similarity checks.", userID))
		msg.ParseMode = "Markdown"
		bot.Send(msg)

	case "rmexception":
		// Only allow authorized managers to remove exceptions
		if !settings.ExceptionAuth.IsAuthorized(update.Message.From.ID) {
			log.Printf("DEBUG: User %d (@%s) tried to use /rmexception but is not authorized",
				update.Message.From.ID, update.Message.From.UserName)

			return true
		}

		// Parse user ID to remove from exceptions
		args := update.Message.CommandArguments()
		if args == "" {
			msg := tgbotapi.NewMessage(update.Message.Chat.ID,
				"Please specify a user ID to remove from exceptions.\n\n"+
					"Format: /rmexception [user_id]\n\n"+
					"To get a user's ID:\n"+
					"1. Message @userinfobot\n"+
					"2. Forward a message from the user\n"+
					"3. The bot will show you the user's ID")
			bot.Send(msg)
			return true
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
			return true
		}

		// Remove user ID from exceptions
		err = settings.Exceptions.RemoveException(userID)
		if err != nil {
			log.Printf("ERROR: Failed to remove exception for user ID %d: %v", userID, err)
			msg := tgbotapi.NewMessage(update.Message.Chat.ID,
				fmt.Sprintf("Failed to remove exception for user ID %d: %v", userID, err))
			bot.Send(msg)
			return true
		}

		msg := tgbotapi.NewMessage(update.Message.Chat.ID,
			fmt.Sprintf("Removed user ID `%d` from exceptions list. This user will now be checked in similarity checks.", userID))
		msg.ParseMode = "Markdown"
		bot.Send(msg)

	case "listexceptions":
		// Only allow authorized managers to list exceptions
		if !settings.ExceptionAuth.IsAuthorized(update.Message.From.ID) {
			log.Printf("DEBUG: User %d (@%s) tried to use /listexceptions but is not authorized",
				update.Message.From.ID, update.Message.From.UserName)

			return true
		}

		// Get list of exceptions
		exceptions := settings.Exceptions.ListExceptions()

		var responseText string
		if len(exceptions) == 0 {
			responseText = "No user ID exceptions configured. Use /addexception to add users to ignore in similarity checks."
		} else {
			responseText = fmt.Sprintf("📋 Exceptions list (%d users):\n\n", len(exceptions))
			for i, userID := range exceptions {
				responseText += fmt.Sprintf("%d. User ID: `%d`\n", i+1, userID)
			}
			responseText += "\nThese users are ignored in similarity checks."
		}

		msg := tgbotapi.NewMessage(update.Message.Chat.ID, responseText)
		msg.ParseMode = "Markdown"
		bot.Send(msg)

	case "addauthmanager":
		// Only allow authorized managers to add other authorized managers
		if !settings.ExceptionAuth.IsAuthorized(update.Message.From.ID) {
			log.Printf("DEBUG: User %d (@%s) tried to use /addauthmanager but is not authorized",
				update.Message.From.ID, update.Message.From.UserName)

			return true
		}

		// Parse user ID to add as authorized manager
		args := update.Message.CommandArguments()
		if args == "" {
			msg := tgbotapi.NewMessage(update.Message.Chat.ID,
				"Please specify a user ID to add as an authorized exception manager.\n\n"+
					"Format: /addauthmanager [user_id]\n\n"+
					"To get a user's ID:\n"+
					"1. Message @userinfobot\n"+
					"2. Forward a message from the user\n"+
					"3. The bot will show you the user's ID")
			bot.Send(msg)
			return true
		}

		// Parse user ID
		userID, err := strconv.ParseInt(strings.TrimSpace(args), 10, 64)
		if err != nil {
			msg := tgbotapi.NewMessage(update.Message.Chat.ID,
				"Invalid user ID. Please provide a valid numeric user ID.")
			bot.Send(msg)
			return true
		}

		// Add user ID to authorized managers
		err = settings.ExceptionAuth.AddAuthorizedUser(userID)
		if err != nil {
			log.Printf("ERROR: Failed to add authorized manager with ID %d: %v", userID, err)
			msg := tgbotapi.NewMessage(update.Message.Chat.ID,
				fmt.Sprintf("Failed to add authorized manager with ID %d: %v", userID, err))
			bot.Send(msg)
			return true
		}

		msg := tgbotapi.NewMessage(update.Message.Chat.ID,
			fmt.Sprintf("Added user ID `%d` to authorized exception managers. This user can now manage exceptions.", userID))
		msg.ParseMode = "Markdown"
		bot.Send(msg)

	case "removeauthmanager":
		// Only allow authorized managers to remove other authorized managers
		if !settings.ExceptionAuth.IsAuthorized(update.Message.From.ID) {
			log.Printf("DEBUG: User %d (@%s) tried to use /removeauthmanager but is not authorized",
				update.Message.From.ID, update.Message.From.UserName)

			return true
		}

		// Parse user ID to remove from authorized managers
		args := update.Message.CommandArguments()
		if args == "" {
			msg := tgbotapi.NewMessage(update.Message.Chat.ID,
				"Please specify a user ID to remove from authorized exception managers.\n\n"+
					"Format: /removeauthmanager [user_id]")
			bot.Send(msg)
			return true
		}

		// Parse user ID
		userID, err := strconv.ParseInt(strings.TrimSpace(args), 10, 64)
		if err != nil {
			msg := tgbotapi.NewMessage(update.Message.Chat.ID,
				"Invalid user ID. Please provide a valid numeric user ID.")
			bot.Send(msg)
			return true
		}

		// Remove user ID from authorized managers
		err = settings.ExceptionAuth.RemoveAuthorizedUser(userID)
		if err != nil {
			log.Printf("ERROR: Failed to remove authorized manager with ID %d: %v", userID, err)
			msg := tgbotapi.NewMessage(update.Message.Chat.ID,
				fmt.Sprintf("Failed to remove authorized manager with ID %d: %v", userID, err))
			bot.Send(msg)
			return true
		}

		msg := tgbotapi.NewMessage(update.Message.Chat.ID,
			fmt.Sprintf("Removed user ID `%d` from authorized exception managers. This user can no longer manage exceptions.", userID))
		msg.ParseMode = "Markdown"
		bot.Send(msg)

	case "listauthmanagers":
		// Only allow authorized managers to list other authorized managers
		if !settings.ExceptionAuth.IsAuthorized(update.Message.From.ID) {
			log.Printf("DEBUG: User %d (@%s) tried to use /listauthmanagers but is not authorized",
				update.Message.From.ID, update.Message.From.UserName)

			return true
		}

		// Get list of authorized managers
		managers := settings.ExceptionAuth.ListAuthorizedUsers()

		var responseText string
		if len(managers) == 0 {
			responseText = "No authorized exception managers configured. Use /addauthmanager to add users who can manage exceptions."
		} else {
			responseText = fmt.Sprintf("📋 Authorized Exception Managers (%d users):\n\n", len(managers))
			for i, userID := range managers {
				responseText += fmt.Sprintf("%d. User ID: `%d`\n", i+1, userID)
			}
			responseText += "\nThese users can manage exceptions."
		}

		msg := tgbotapi.NewMessage(update.Message.Chat.ID, responseText)
		msg.ParseMode = "Markdown"
		bot.Send(msg)

	case "deletemessages":
		// Only allow authorized managers to change message deletion settings
		if !settings.ExceptionAuth.IsAuthorized(update.Message.From.ID) {
			log.Printf("DEBUG: User %d (@%s) tried to use /deletemessages but is not authorized",
				update.Message.From.ID, update.Message.From.UserName)

			return true
		}

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
			return true
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

	case "automute":
		// Only allow authorized managers to change auto-mute settings
		if !settings.ExceptionAuth.IsAuthorized(update.Message.From.ID) {
			log.Printf("DEBUG: User %d (@%s) tried to use /automute but is not authorized",
				update.Message.From.ID, update.Message.From.UserName)

			return true
		}

		// Parse auto-mute setting
		args := update.Message.CommandArguments()
		if args == "" {
			status := "disabled"
			if settings.AutoMuteEnabled {
				status = "enabled"
			}
			msg := tgbotapi.NewMessage(update.Message.Chat.ID,
				fmt.Sprintf("Auto-mute is currently %s. Use /automute on or /automute off to change.\n\nCurrent auto-mute threshold: %.2f",
					status, settings.AutoMuteThreshold))
			bot.Send(msg)
			return true
		}

		args = strings.ToLower(args)
		if args == "on" || args == "enable" || args == "true" || args == "1" {
			settings.AutoMuteEnabled = true
			msg := tgbotapi.NewMessage(update.Message.Chat.ID,
				fmt.Sprintf("Auto-mute enabled. Users with username similarity above %.2f will be automatically muted.",
					settings.AutoMuteThreshold))
			bot.Send(msg)
		} else if args == "off" || args == "disable" || args == "false" || args == "0" {
			settings.AutoMuteEnabled = false
			msg := tgbotapi.NewMessage(update.Message.Chat.ID,
				"Auto-mute disabled. Users with similar usernames will not be automatically muted.")
			bot.Send(msg)
		} else {
			// Check if this is a threshold setting
			threshold, err := strconv.ParseFloat(args, 64)
			if err == nil && threshold >= 0 && threshold <= 1 {
				settings.AutoMuteThreshold = threshold
				msg := tgbotapi.NewMessage(update.Message.Chat.ID,
					fmt.Sprintf("Auto-mute threshold set to %.2f", threshold))
				bot.Send(msg)
			} else {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID,
					"Invalid value. Use 'on' or 'off' to enable or disable auto-mute, or a value between 0 and 1 to set the threshold.")
				bot.Send(msg)
			}
		}

	case "debug":
		// Only allow authorized managers to use debug command
		if !settings.ExceptionAuth.IsAuthorized(update.Message.From.ID) {
			log.Printf("DEBUG: User %d (@%s) tried to use /debug but is not authorized",
				update.Message.From.ID, update.Message.From.UserName)
			return true
		}

		// Create debug info message with bot settings and stats
		var debugInfo strings.Builder

		// Bot version and status
		debugInfo.WriteString("🔍 **Bot Debug Information**\n\n")
		debugInfo.WriteString(fmt.Sprintf("🤖 Bot Username: @%s\n", bot.Self.UserName))
		debugInfo.WriteString(fmt.Sprintf("🆔 Bot ID: `%d`\n", bot.Self.ID))

		// Current settings
		debugInfo.WriteString("\n**Current Settings**:\n")
		debugInfo.WriteString(fmt.Sprintf("• Similarity Threshold: `%.2f`\n", settings.SimilarityThreshold))
		debugInfo.WriteString(fmt.Sprintf("• Auto-Mute: `%t`\n", settings.AutoMuteEnabled))
		debugInfo.WriteString(fmt.Sprintf("• Auto-Mute Threshold: `%.2f`\n", settings.AutoMuteThreshold))
		debugInfo.WriteString(fmt.Sprintf("• Delete Messages: `%t`\n", settings.DeleteMessages))
		debugInfo.WriteString(fmt.Sprintf("• Mute Duration: `%.1f hours`\n", settings.MuteDuration.Hours()))
		debugInfo.WriteString(fmt.Sprintf("• Check Cooldown: `%.1f minutes`\n", settings.CheckCooldown.Minutes()))

		// Protected usernames
		debugInfo.WriteString(fmt.Sprintf("\n**Protected Usernames** (%d):\n", len(KnownUsernames)))
		if len(KnownUsernames) > 0 {
			// Only show a subset if there are many
			maxDisplay := 10
			for i, name := range KnownUsernames {
				if i < maxDisplay {
					debugInfo.WriteString(fmt.Sprintf("• %s\n", name))
				} else {
					debugInfo.WriteString(fmt.Sprintf("(+%d more...)\n", len(KnownUsernames)-maxDisplay))
					break
				}
			}
		} else {
			debugInfo.WriteString("No protected usernames configured.\n")
		}

		// Memory usage information
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)
		debugInfo.WriteString("\n**Memory Usage**:\n")
		debugInfo.WriteString(fmt.Sprintf("• Alloc: `%.2f MB`\n", float64(memStats.Alloc)/1024/1024))
		debugInfo.WriteString(fmt.Sprintf("• System: `%.2f MB`\n", float64(memStats.Sys)/1024/1024))

		// Recently checked users count
		settings.Mutex.RLock()
		recentlyCheckedCount := len(settings.RecentlyChecked)
		settings.Mutex.RUnlock()
		debugInfo.WriteString(fmt.Sprintf("\n**Stats**:\n"))
		debugInfo.WriteString(fmt.Sprintf("• Recently Checked Users: `%d`\n", recentlyCheckedCount))

		// Cache info
		settings.AdminCacheMutex.RLock()
		cachedGroupsCount := len(settings.AdminInfo)
		settings.AdminCacheMutex.RUnlock()
		debugInfo.WriteString(fmt.Sprintf("• Cached Admin Groups: `%d`\n", cachedGroupsCount))

		// Exceptions count
		debugInfo.WriteString(fmt.Sprintf("• Exception Users: `%d`\n", len(settings.Exceptions.ListExceptions())))
		debugInfo.WriteString(fmt.Sprintf("• Authorized Managers: `%d`\n", len(settings.ExceptionAuth.ListAuthorizedUsers())))

		// Send the debug info
		msg := tgbotapi.NewMessage(update.Message.Chat.ID, debugInfo.String())
		msg.ParseMode = "Markdown"
		bot.Send(msg)

	// Additional commands can be added here as needed

	default:
		// Command not recognized, nothing to do
		return false
	}

	return true
}
