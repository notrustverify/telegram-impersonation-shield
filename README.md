# Telegram Username Similarity Detector Bot

A Telegram bot written in Go that detects similar usernames using the Jaro-Winkler similarity algorithm. This bot is useful for identifying potential impersonator accounts and can automatically mute users with suspicious usernames.

## Features

- Detects username similarity using Jaro-Winkler algorithm
- Configurable similarity threshold
- Simple and intuitive interface
- Response shows similarity percentage
- Load usernames from a text file
- Automatic muting of suspicious usernames
- Customizable auto-mute thresholds and duration
- Continuous monitoring of all message authors
- Smart cooldown system to prevent notification spam
- Group scanning to detect suspicious usernames among admins
- Checks first names when usernames are not available, improving impersonator detection
- Automatically checks new users joining the group
- Checks every message sender (configurable cooldown)
- Automatically mute suspicious users (optional)
- Detects similarity to both:
  - Configured list of official usernames
  - Group admin usernames and first names
- Case-insensitive matching for better detection
- Works in multiple groups simultaneously
- Easy to deploy with Docker and Docker Compose

## Setup

### Docker Compose (Recommended)

The easiest way to deploy the bot is using Docker Compose:

1. Clone this repository
2. Create a `.env` file from the template:
   ```bash
   cp .env.example .env
   ```
3. Edit the `.env` file and add your Telegram bot token:
   ```
   TELEGRAM_BOT_TOKEN=your_token_here
   ```
4. Edit `usernames.txt` to add the list of official usernames to protect
5. Start the bot with Docker Compose:
   ```bash
   docker-compose up -d
   ```

The bot will automatically restart if it crashes or if your system reboots.

### Docker Setup (Manual)

If you prefer to use Docker without Compose:

1. Build the Docker image:
   ```bash
   docker build -t username-detector .
   ```

2. Run the container:
   ```bash
   docker run -d --name username-detector \
     -e TELEGRAM_BOT_TOKEN=your_token_here \
     -e SIMILARITY_THRESHOLD=0.8 \
     -e AUTO_MUTE_ENABLED=true \
     -v $(pwd)/usernames.txt:/app/usernames.txt \
     username-detector
   ```

## Usage

### Commands

- `/start` - Start the bot
- `/help` - Show help information
- `/threshold [value]` - Set similarity threshold (0-1)
- `/count` - Show the number of known usernames
- `/automute [on|off]` - Enable/disable auto-mute
- `/mutethreshold [value]` - Set auto-mute threshold (0-1)
- `/muteduration [hours]` - Set mute duration in hours
- `/cooldown [minutes]` - Set cooldown time between checks (0 to disable)
- `/checkuser @username` - Check a specific username
- `/scangroup` - Scan visible group members for suspicious usernames
- `/debug` - Show detailed debug information (admin only)

### Group Scanning

- Use `/scangroup` to scan group admins for similar usernames
- The bot can only see users who send messages or join while the bot is present
- Add the bot as an admin to enable username checks and auto-muting

## Auto-Mute Configuration

Set up auto-muting to automatically restrict users with suspicious usernames:

1. Enable auto-mute with `/automute on`
2. Set auto-mute threshold with `/mutethreshold 0.9`
3. Set mute duration with `/muteduration 24`

## Cooldown System

- The bot will check each user based on the cooldown setting
- Use `/cooldown 30` to set a 30-minute cooldown
- Use `/cooldown 0` to disable the cooldown system and check every message

## Environment Variables

You can configure the bot using environment variables in the Docker Compose file or `.env` file:

- `TELEGRAM_BOT_TOKEN` - Your Telegram bot token
- `SIMILARITY_THRESHOLD` - Minimum similarity to trigger a warning (0-1)
- `AUTO_MUTE_ENABLED` - Enable auto-muting of suspicious users (true/false)
- `AUTO_MUTE_THRESHOLD` - Minimum similarity to trigger auto-mute (0-1)
- `MUTE_DURATION_HOURS` - Duration to mute users for (in hours)
- `CHECK_COOLDOWN_MINUTES` - How often to check the same user (in minutes, 0 to disable)

## How it Works

The bot uses the Jaro-Winkler algorithm to calculate string similarity, which:

1. Gives higher values to strings that match from the beginning
2. Works well for short strings like usernames and first names
3. Returns a similarity score between 0 (completely different) and 1 (identical)

When auto-mute is enabled, any new user joining with a similar username (or first name, if no username) that has a similarity score above the auto-mute threshold will be automatically muted for the configured duration.

## Customizing the Username List

You can add as many usernames as you want to the `usernames.txt` file. The file format is simple:

- One username per line
- Lines starting with `#` are treated as comments
- Empty lines are ignored

This makes it easy to maintain and organize your list of known usernames.

## Running in Production

For production use, you might want to:

1. Use a process manager like systemd, supervisor, or PM2
2. Set up monitoring and restarts
3. Use environment variables or config files for settings

Example systemd service file (`/etc/systemd/system/telegram-bot.service`):

```
[Unit]
Description=Telegram Username Similarity Detector Bot
After=network.target

[Service]
Type=simple
User=botuser
WorkingDirectory=/path/to/bot
ExecStart=/path/to/bot/telegram-username-detector
Restart=always
RestartSec=5
Environment=TELEGRAM_BOT_TOKEN=your_token_here
Environment=AUTO_MUTE_ENABLED=true
Environment=AUTO_MUTE_THRESHOLD=0.9
Environment=MUTE_DURATION_HOURS=24
Environment=CHECK_COOLDOWN_MINUTES=30

[Install]
WantedBy=multi-user.target
```

## License

MIT 