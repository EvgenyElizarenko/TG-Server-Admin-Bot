# TG-Server-Admin-Bot

English version of the README is available. For the Russian README see README.md

Quick links:
- [Installation guide]: (https://github.com/EvgenyElizarenko/TG-Server-Admin-Bot/blob/main/instruction/install_bot_en.md)
- [Managed node setup]: (https://github.com/EvgenyElizarenko/TG-Server-Admin-Bot/blob/main/instruction/setup_node_en.md)

Overview
--------
An asynchronous Telegram bot for centralized monitoring, diagnostics and secure administration of Linux servers and Docker containers. It is intended for operators and administrators who need controlled remote access via Telegram with minimal privileges on target nodes.

Stack
-----
- Language: Python 3.10+
- Framework: Aiogram 3
- SSH: AsyncSSH
- Extras: python-dotenv for configuration via .env

Features
--------
- Generates a personal SSH public key (command /key) for server authorization.
- Add and manage servers through an interactive Telegram dialog (TOFU host key verification).
- Background monitoring of node health and Docker containers.
- Execute predefined administrative actions with least-privilege access on nodes (via a dedicated service user).
- Utilities to temporarily enable root access for 2 minutes and to forcibly disable it.
- Centralized metadata stored in servers.json, users.json, known_hosts, and audit.log.
- Runs as a systemd service (tg-server-bot.service) under an unprivileged user.

Quick start
-----------
Automated one-line install (on the host where the bot will run):

```bash
wget -O install_bot.sh https://raw.githubusercontent.com/EvgenyElizarenko/TG-Server-Admin-Bot/refs/heads/main/script's/install_bot.sh && chmod +x install_bot.sh && sudo ./install_bot.sh
```

Prepare a managed node (run on the target server):

```bash
wget -O setup_node.sh https://raw.githubusercontent.com/EvgenyElizarenko/TG-Server-Admin-Bot/refs/heads/main/script's/setup_node.sh && chmod +x setup_node.sh && sudo ./setup_node.sh
```

Post-install steps
------------------
1. Open the bot in Telegram and send `/start`.
2. Request your personal public key with `/key`.
3. Add the public key to `/home/<botuser>/.ssh/authorized_keys` on the target server.
4. In the bot UI: ➕ Add server — enter name, IP/domain, port and user; verify the host key fingerprint and confirm.
5. Configure sudoers on target servers as described in the setup guide to grant only the commands the bot needs.

Files and layout
----------------
Typical working directory on the bot host:

/home/tgbot/tg-bot-env/
- bot.py
- .env               — BOT_TOKEN, ADMIN_IDS
- venv/              — Python virtual environment
- keys/              — private keys/files (strict permissions)
- servers.json
- users.json
- known_hosts
- audit.log

Security
--------
- The bot runs as an unprivileged `tgbot` user inside a venv.
- Managed node scripts and rights are handled by a separate `botadmin` user with limited sudo privileges.
- The bot token is stored in `.env` with 600 permissions — never publish it.
- TOFU host key verification is used when adding servers.

Where to find details
---------------------
- Installation and initial setup: instruction/install_bot_en.md
- Managed node setup and sudoers examples: instruction/setup_node_en.md

License
-------
See the LICENSE file in this repository.
