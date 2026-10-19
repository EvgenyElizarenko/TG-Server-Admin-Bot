# Setting up a managed node for TG-Server-Admin-Bot

Guide to prepare a target Linux host (Ubuntu, Debian, CentOS, Rocky Linux, AlmaLinux) for secure connections and management by the bot.

---

## Automatic one-click setup (recommended)

For a quick automated setup run the following command on the target server as `root`:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/EvgenyElizarenko/TG-Server-Admin-Bot/refs/heads/main/script%27s/setup_node.sh)"
```

### What the script does
1. Installs required utilities (`curl`, `iproute2`, `vnstat`, `sudo`, `openssh-server`) if needed.
2. Creates a service user `botadmin`.
3. Adds `botadmin` to the `docker` group if Docker is present.
4. Prompts you to paste your personal SSH public key (obtained via the bot with `/key`) and writes it into `~/.ssh/authorized_keys` for `botadmin`.
5. Places management scripts under `/usr/local/sbin/`:
   - `update.sh` — automatic package update script;
   - `root.sh` — enable temporary Root access for 2 minutes;
   - `unroot.sh` — force-disable Root access.
6. Configures restrictive sudo rules in `/etc/sudoers.d/botadmin` and validates syntax with `visudo`.
7. Prints a summary (IP, active SSH port, username) to be copied into the "Add server" wizard in the bot.

---

## Manual step-by-step setup

Perform the manual steps if you prefer fine-grained control over privileges.

---

### Step 1. Install diagnostic utilities

Install packages needed for network, port and resource monitoring.

* **Debian / Ubuntu:**
  ```bash
  sudo apt-get update -qq
  sudo apt-get install -y -qq curl iproute2 vnstat sudo openssh-server
  ```

* **RHEL / Rocky Linux / AlmaLinux:**
  ```bash
  sudo dnf install -y -q curl iproute vnstat sudo openssh-server
  ```

---

### Step 2. Create the system user `botadmin`

Create a dedicated user `botadmin` with `/bin/bash` shell:

```bash
sudo useradd -m -s /bin/bash botadmin
```

If Docker is installed and you need to monitor containers without root, add the user to the `docker` group:

```bash
sudo usermod -aG docker botadmin
```

---

### Step 3. Configure SSH key authentication

1. Obtain your personal public key from the Telegram bot with `/key`.
2. Create `.ssh` in the `botadmin` home and set permissions:
   ```bash
   sudo mkdir -p /home/botadmin/.ssh
   sudo chmod 700 /home/botadmin/.ssh
   ```
3. Append the public key to `authorized_keys`:
   ```bash
   echo "YOUR_PUBLIC_KEY_FROM_BOT" | sudo tee -a /home/botadmin/.ssh/authorized_keys
   ```
4. Set strict permissions and ownership:
   ```bash
   sudo chmod 600 /home/botadmin/.ssh/authorized_keys
   sudo chown -R botadmin:botadmin /home/botadmin/.ssh
   ```

---

### Step 4. Install management scripts

Create `/usr/local/sbin` if missing and place system scripts.

#### 1. Update script (`/usr/local/sbin/update.sh`):
```bash
sudo cat << 'EOF' > /usr/local/sbin/update.sh
#!/usr/bin/env bash
set -e
export DEBIAN_FRONTEND=noninteractive

echo "=== [$(date)] Running package update ==="
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    apt-get dist-upgrade -y
    apt-get autoremove -y
    apt-get clean
elif command -v dnf >/dev/null 2>&1; then
    dnf upgrade -y --refresh
    dnf autoremove -y
    dnf clean all
else
    echo "Unsupported package manager." >&2
    exit 1
fi
echo "=== [$(date)] Update completed successfully ==="
EOF
```

#### 2. Enable temporary Root for 2 minutes (`/usr/local/sbin/root.sh`):
```bash
sudo cat << 'EOF' > /usr/local/sbin/root.sh
#!/usr/bin/env bash
set -e
SSHD_DROPIN="/etc/ssh/sshd_config.d/99-tgbot-temp-root.conf"
mkdir -p /etc/ssh/sshd_config.d

echo "PermitRootLogin yes" > "$SSHD_DROPIN"
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
echo "Root access enabled for 2 minutes..."

(
    sleep 120
    if [ -f "$SSHD_DROPIN" ]; then
        rm -f "$SSHD_DROPIN"
        systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
    fi
) >/dev/null 2>&1 &
EOF
```

#### 3. Disable Root (`/usr/local/sbin/unroot.sh`):
```bash
sudo cat << 'EOF' > /usr/local/sbin/unroot.sh
#!/usr/bin/env bash
set -e
SSHD_DROPIN="/etc/ssh/sshd_config.d/99-tgbot-temp-root.conf"
rm -f "$SSHD_DROPIN"
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
echo "Root access forcibly disabled."
EOF
```

Set permissions on the scripts:
```bash
sudo chmod 750 /usr/local/sbin/update.sh /usr/local/sbin/root.sh /usr/local/sbin/unroot.sh
sudo chown root:root /usr/local/sbin/update.sh /usr/local/sbin/root.sh /usr/local/sbin/unroot.sh
```

---

### Step 5. Configure sudoers

The bot uses the principle of least privilege. Create `/etc/sudoers.d/botadmin`:

```bash
sudo cat << 'EOF' > /etc/sudoers.d/botadmin
botadmin ALL=(ALL) NOPASSWD: \
    /usr/local/sbin/update.sh, \
    /usr/local/sbin/root.sh, \
    /usr/local/sbin/unroot.sh, \
    /usr/bin/systemd-run --unit=tgbot-upgrade --remain-after-exit /usr/local/sbin/update.sh, \
    /usr/bin/systemctl stop tgbot-upgrade, \
    /usr/bin/systemctl reset-failed tgbot-upgrade, \
    /usr/bin/journalctl -u tgbot-upgrade *, \
    /usr/bin/systemctl reboot, \
    /usr/sbin/ufw status numbered, \
    /usr/bin/fail2ban-client *, \
    /usr/bin/ss *, \
    /usr/bin/certbot certificates
EOF
```

> **Important:** verify syntax with `visudo` and set mode `0440`:
```bash
sudo visudo -cf /etc/sudoers.d/botadmin
sudo chmod 440 /etc/sudoers.d/botadmin
```

---

### Step 6. Adding the server via the Telegram bot interface

1. Open your Telegram bot and go to `/start` or `/servers`.
2. Click **➕ Add server**.
3. **Step 1/3:** Enter a server name in Latin characters (e.g., `nl-prod-01` or `vpn-node`).
4. **Step 2/3:** Enter the public IP or domain of the target.
5. **Step 3/3:** Choose port (default `22`, or a custom value like `59856`) and the user account the bot should use (`botadmin` by default).
6. **TOFU verification:** The bot will display the host key fingerprint (SHA256). To verify on the server run:
   ```bash
   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
   ```
   If fingerprints match, press **✅ Trust and verify login** in the bot interface.
7. The server will be added to your list and background monitoring (including Docker container checks) will start.
