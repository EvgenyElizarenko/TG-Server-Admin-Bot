# Setting up a managed node for TG-Server-Admin-Bot

Guide to prepare a target Linux host (Ubuntu, Debian, CentOS, Rocky
Linux, AlmaLinux) for secure connections and management by the bot.

---

## Automatic one-click setup (recommended)

For a quick automated setup, run the following command on the target
server as `root`:

```bash
wget -O setup_node.sh \
  'https://raw.githubusercontent.com/EvgenyElizarenko/'\
  'TG-Server-Admin-Bot/refs/heads/main/script'"'"'s/setup_node.sh' && \
  chmod +x setup_node.sh && \
  sudo ./setup_node.sh
```

### What the script does

1. Installs required utilities (`curl`, `iproute2`, `vnstat`, `sudo`,
   `openssh-server`) if needed.
2. Creates a service user `botadmin`.
3. Adds `botadmin` to the `docker` group if Docker is present.
4. Prompts you to paste your personal SSH public key (obtained via the
   bot with `/key`) and writes it into `~/.ssh/authorized_keys` for
   `botadmin`.
5. Places management scripts under `/usr/local/sbin/`:
   - `update.sh` — automatic package update script;
   - `root.sh` — enable temporary Root access for 2 minutes;
   - `unroot.sh` — force-disable Root access.
6. Configures restrictive sudo rules in `/etc/sudoers.d/botadmin` and
   validates syntax with `visudo`.
7. Prints a summary (IP, active SSH port, username) to be copied into
   the "Add server" wizard in the bot.
