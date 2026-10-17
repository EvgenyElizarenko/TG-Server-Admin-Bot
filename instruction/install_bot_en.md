# TG Server Admin Bot

Installation guide and initial setup for the management Telegram bot on
Linux servers: Ubuntu, Debian, CentOS, Rocky Linux and AlmaLinux.

## Quick one-line install

Run the following command as root or a user with sudo privileges. The
script will download the installer from the official repository and
perform the installation:

```bash
wget -O install_bot.sh \
  https://raw.githubusercontent.com/EvgenyElizarenko/TG-Server-Admin-Bot/refs/heads/main/script's/install_bot.sh && \
  chmod +x install_bot.sh && \
  sudo ./install_bot.sh
```

The installer will automatically:

- install system dependencies: Python 3, `python3-venv`, OpenSSH client, `curl` and `git`;
- create an unprivileged system user `tgbot` with home directory `/home/tgbot`;
- prepare working directories with restrictive permissions;
- place the executable `bot.py`;
- create a Python virtual environment and install `aiogram`, `asyncssh` and `python-dotenv`;
- prompt for the Telegram bot token and administrator Telegram IDs and save them in a private `.env` file;
- create and start a systemd service named `tg-server-bot.service`.

> Before running, make sure you trust the installer's source and download it from the official project repository.

## Step-by-step manual installation

### 1. Install system packages

**Ubuntu / Debian:**

```bash
sudo apt-get update -qq
sudo apt-get install -y python3 python3-venv python3-pip openssh-client curl git
```

**CentOS / Rocky Linux / AlmaLinux:**

```bash
sudo dnf install -y python3 python3-pip openssh-clients curl git
```

### 2. Create user and directories

Create an unprivileged user `tgbot` and working directories:

```bash
sudo useradd -m -s /bin/bash tgbot
sudo mkdir -p /home/tgbot/tg-bot-env/keys

sudo chmod 700 /home/tgbot
sudo chmod 700 /home/tgbot/tg-bot-env
sudo chmod 700 /home/tgbot/tg-bot-env/keys
sudo chown -R tgbot:tgbot /home/tgbot
```

If `tgbot` already exists, do not run `useradd` again. Check owners and permissions before continuing.

### 3. Place bot code

```bash
sudo -u tgbot wget -O /home/tgbot/tg-bot-env/bot.py \
  https://raw.githubusercontent.com/EvgenyElizarenko/TG-Server-Admin-Bot/refs/heads/main/bot.py

sudo chmod 700 /home/tgbot/tg-bot-env/bot.py
```

### 4. Create Python virtual environment

```bash
sudo -u tgbot python3 -m venv /home/tgbot/tg-bot-env/venv
sudo -u tgbot /home/tgbot/tg-bot-env/venv/bin/pip install --upgrade pip
sudo -u tgbot /home/tgbot/tg-bot-env/venv/bin/pip install \
  "aiogram>=3.4.0" \
  "asyncssh>=2.14.0" \
  "python-dotenv>=1.0.0"
```

### 5. Configure the `.env` file

Create the file `/home/tgbot/tg-bot-env/.env`:

```bash
sudo tee /home/tgbot/tg-bot-env/.env > /dev/null <<'EOF'
BOT_TOKEN=INSERT_TOKEN_FROM_BOTFATHER
ADMIN_IDS=123456789,987654321
EOF
```

Replace the example values with the real bot token and administrator Telegram IDs. Provide IDs as comma-separated numbers (without spaces) if that matches the format expected by the bot version you are using.

Restrict access to the file:

```bash
sudo chown tgbot:tgbot /home/tgbot/tg-bot-env/.env
sudo chmod 600 /home/tgbot/tg-bot-env/.env
```

**Do not publish the token or share the `.env` file.** If the token is exposed, revoke it in BotFather and create a new one.

### 6. Initialize service files

```bash
cd /home/tgbot/tg-bot-env

sudo -u tgbot sh -c 'echo "{}" > servers.json'
sudo -u tgbot sh -c 'echo "{}" > users.json'
sudo -u tgbot touch known_hosts audit.log

sudo chown tgbot:tgbot servers.json users.json known_hosts audit.log
sudo chmod 600 servers.json users.json known_hosts audit.log
```

### 7. Create a systemd service

Create `/etc/systemd/system/tg-server-bot.service`:

```bash
sudo tee /etc/systemd/system/tg-server-bot.service > /dev/null <<'EOF'
[Unit]
Description=Telegram Server Admin & Monitoring Bot
After=network.target

[Service]
Type=simple
User=tgbot
Group=tgbot
WorkingDirectory=/home/tgbot/tg-bot-env
ExecStart=/home/tgbot/tg-bot-env/venv/bin/python /home/tgbot/tg-bot-env/bot.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Process security restrictions
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/home/tgbot/tg-bot-env

[Install]
WantedBy=multi-user.target
EOF
```

The service runs as `tgbot`, not as root. Options like `ProtectSystem`, `ProtectHome` and `ReadWritePaths` limit filesystem access. If the bot writes to additional directories, add them explicitly to the service configuration.

### 8. Start and verify

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tg-server-bot.service
```

Check status:

```bash
sudo systemctl status tg-server-bot.service --no-pager
```

View live logs:

```bash
sudo journalctl -u tg-server-bot.service -f
```

Last 100 lines:

```bash
sudo journalctl -u tg-server-bot.service -n 100 --no-pager
```

Restart after changes:

```bash
sudo systemctl restart tg-server-bot.service
```

Stop the service:

```bash
sudo systemctl stop tg-server-bot.service
```

## First steps after startup

1. Open a conversation with the bot in Telegram and send `/start`.
2. Send `/key` to receive a personal Ed25519 public SSH key.
3. On each target server add the received public key to the `authorized_keys` file of the user the bot will connect as (for example, `botadmin`):

```bash
sudo install -d -m 700 -o botadmin -g botadmin /home/botadmin/.ssh
sudo -u botadmin touch /home/botadmin/.ssh/authorized_keys
sudo chmod 600 /home/botadmin/.ssh/authorized_keys
```

Then append the public key as a single line to `/home/botadmin/.ssh/authorized_keys` and verify ownership:

```bash
sudo chown botadmin:botadmin /home/botadmin/.ssh/authorized_keys
```

4. Configure `sudoers` on target servers to grant `botadmin` only the commands required by the bot. Edit rules with `visudo` and avoid granting `NOPASSWD: ALL` unless that matches your security model.

## Troubleshooting

If the bot does not start, first check the journal:

```bash
sudo journalctl -u tg-server-bot.service -n 100 --no-pager
```

Check permissions and presence of required files:

```bash
sudo ls -ld /home/tgbot /home/tgbot/tg-bot-env
sudo ls -l /home/tgbot/tg-bot-env
sudo ls -l /home/tgbot/tg-bot-env/.env
```

Confirm that the token and admin IDs in `.env` are correct and that the virtualenv contains the required packages.

## Directory layout

After installation the working directory should look approximately like:

```text
/home/tgbot/
└── tg-bot-env/
    ├── bot.py
    ├── .env
    ├── venv/
    ├── keys/
    ├── servers.json
    ├── users.json
    ├── known_hosts
    └── audit.log
```

Actual files may vary between versions of the bot and the installer.
