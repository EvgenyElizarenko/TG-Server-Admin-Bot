# TG Server Admin Bot

Installation guide and initial setup for the management Telegram bot on
Linux servers: Ubuntu, Debian, CentOS, Rocky Linux and AlmaLinux.

## Quick one-line install

Run the following command as root or a user with sudo privileges. The
script will download the installer from the official repository and
perform the installation:

```bash
wget -O install_bot.sh \
  'https://raw.githubusercontent.com/EvgenyElizarenko/'\
  'TG-Server-Admin-Bot/refs/heads/main/script'"'"'s/install_bot.sh' && \
  chmod +x install_bot.sh && \
  sudo ./install_bot.sh
```

The installer will automatically:

- install system dependencies: Python 3, `python3-venv`, OpenSSH
  client, `curl` and `git`;
- create an unprivileged system user `tgbot` with home directory
  `/home/tgbot`;
- prepare working directories with restrictive permissions;
- place the executable `bot.py`;
- create a Python virtual environment and install `aiogram`,
  `asyncssh` and `python-dotenv`;
- prompt for the Telegram bot token and administrator Telegram IDs and
  save them in a private `.env` file;
- create and start a systemd service named `tg-server-bot.service`.

> Before running, make sure you trust the installer's source and
> download it from the official project repository.

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

If `tgbot` already exists, do not run `useradd` again. Check owners and
permissions before continuing.

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

### 5. Настройка файла окружения `.env`

Create file content...
