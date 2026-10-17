# Настройка управляемого сервера для TG-Server-Admin-Bot

Инструкция по подготовке целевого Linux-узла (Ubuntu, Debian, CentOS, Rocky Linux, AlmaLinux) для безопасного подключения и управления через Telegram-бота.

---

## ⚡ Автоматическая настройка в 1 клик (рекомендуемый способ)

Для быстрой автоматической настройки выполните следующую команду на подключаемом сервере от имени `root` (или через `sudo`):

```bash
wget -O setup_node.sh https://raw.githubusercontent.com/EvgenyElizarenko/TG-Server-Admin-Bot/refs/heads/main/setup_node.sh && chmod +x setup_node.sh && sudo ./setup_node.sh
```

### Что сделает скрипт:
1. Проверит и установит необходимые системные утилиты (`curl`, `iproute2`, `vnstat`, `sudo`, `openssh-server`).
2. Создаст сервисного пользователя `botadmin`.
3. Добавит `botadmin` в группу `docker` (если Docker установлен на сервере).
4. Запросит ввод вашего персонального SSH-ключа (полученного в Telegram-боте по команде `/key`) и запишет его в `~/.ssh/authorized_keys` с правами `0600`.
5. Разместит системные скрипты управления в `/usr/local/sbin/`:
   * `update.sh` — скрипт автоматического обновления пакетов;
   * `root.sh` — временная активация Root-доступа по таймеру на 2 минуты;
   * `unroot.sh` — принудительное отключение Root-доступа.
6. Сконфигурирует изолированные правила `sudoers` в `/etc/sudoers.d/botadmin` с проверкой синтаксиса через `visudo`.
7. Выведет сводку параметров (IP, активный SSH-порт, имя пользователя) для ввода в мастере добавления сервера в Telegram-боте.

---

## 🛠 Пошаговая ручная настройка

Если вы хотите выполнить настройку вручную или детальнее контролировать предоставляемые права, выполните следующие шаги.

---

### Шаг 1. Установка базовых диагностических утилит

Для корректной работы мониторинга сети, портов и ресурсов установите базовые пакеты:

* **Для Debian / Ubuntu:**
  ```bash
  sudo apt-get update -qq
  sudo apt-get install -y -qq curl iproute2 vnstat sudo openssh-server
  ```

* **Для RHEL / Rocky Linux / AlmaLinux:**
  ```bash
  sudo dnf install -y -q curl iproute vnstat sudo openssh-server
  ```

---

### Шаг 2. Создание системного пользователя botadmin

Создайте отдельного пользователя `botadmin` с командным интерпретатором `bash`:

```bash
sudo useradd -m -s /bin/bash botadmin
```

Если на сервере развернут Docker, добавьте пользователя в группу `docker` для мониторинга контейнеров без root-прав:

```bash
sudo usermod -aG docker botadmin
```

---

### Шаг 3. Настройка авторизации по SSH-ключу

1. Получите персональный открытый ключ в Telegram-боте, отправив команду `/key`.
2. Создайте каталог `.ssh` в домашней папке пользователя `botadmin`:
   ```bash
   sudo mkdir -p /home/botadmin/.ssh
   sudo chmod 700 /home/botadmin/.ssh
   ```
3. Добавьте ваш открытый ключ в файл `authorized_keys`:
   ```bash
   echo "ВАШ_ПУБЛИЧНЫЙ_КЛЮЧ_ИЗ_БОТА" | sudo tee -a /home/botadmin/.ssh/authorized_keys
   ```
4. Назначьте строгие права доступа:
   ```bash
   sudo chmod 600 /home/botadmin/.ssh/authorized_keys
   sudo chown -R botadmin:botadmin /home/botadmin/.ssh
   ```

---

### Шаг 4. Создание служебных скриптов управления

Создайте каталог `/usr/local/sbin` (если он отсутствует) и разместите системные скрипты:

#### 1. Скрипт обновления ОС (`/usr/local/sbin/update.sh`):
```bash
sudo cat << 'EOF' > /usr/local/sbin/update.sh
#!/usr/bin/env bash
set -e
export DEBIAN_FRONTEND=noninteractive

echo "=== [$(date)] Запуск обновления пакетов ==="
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
    echo "Неподдерживаемый пакетный менеджер." >&2
    exit 1
fi
echo "=== [$(date)] Обновление успешно завершено ==="
EOF
```

#### 2. Скрипт включения Root-доступа на 2 минуты (`/usr/local/sbin/root.sh`):
```bash
sudo cat << 'EOF' > /usr/local/sbin/root.sh
#!/usr/bin/env bash
set -e
SSHD_DROPIN="/etc/ssh/sshd_config.d/99-tgbot-temp-root.conf"
mkdir -p /etc/ssh/sshd_config.d

echo "PermitRootLogin yes" > "$SSHD_DROPIN"
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
echo "Root-доступ активирован на 2 минуты..."

(
    sleep 120
    if [ -f "$SSHD_DROPIN" ]; then
        rm -f "$SSHD_DROPIN"
        systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
    fi
) >/dev/null 2>&1 &
EOF
```

#### 3. Скрипт отключения Root-доступа (`/usr/local/sbin/unroot.sh`):
```bash
sudo cat << 'EOF' > /usr/local/sbin/unroot.sh
#!/usr/bin/env bash
set -e
SSHD_DROPIN="/etc/ssh/sshd_config.d/99-tgbot-temp-root.conf"
rm -f "$SSHD_DROPIN"
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
echo "Root-доступ принудительно отключен."
EOF
```

Выдайте необходимые права на созданные скрипты:
```bash
sudo chmod 750 /usr/local/sbin/update.sh /usr/local/sbin/root.sh /usr/local/sbin/unroot.sh
sudo chown root:root /usr/local/sbin/update.sh /usr/local/sbin/root.sh /usr/local/sbin/unroot.sh
```

---

### Шаг 5. Конфигурация прав sudoers

Для обеспечения безопасности бот использует принцип минимально необходимых привилегий. Пользователю `botadmin` разрешается вызывать только строго оговоренные бинарники без запроса пароля.

Создайте файл `/etc/sudoers.d/botadmin`:

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

> **Важно:** проверьте синтаксис файла через `visudo` и установите корректные права `0440`:
```bash
sudo visudo -cf /etc/sudoers.d/botadmin
sudo chmod 440 /etc/sudoers.d/botadmin
```

---

### Шаг 6. Добавление сервера в интерфейсе Telegram-бота

1. Откройте вашего Telegram-бота и перейдите в меню `/start` или `/servers`.
2. Нажмите кнопку **➕ Добавить сервер**.
3. **Шаг 1/3:** Введите имя сервера латиницей (например: `nl-prod-01` или `vpn-node`).
4. **Шаг 2/3:** Введите публичный IP-адрес или домен целевого сервера.
5. **Шаг 3/3:** Выберите порт подключения (стандартный `22`, кастомный `59856` или введите вручную) и пользователя `botadmin`.
6. **Верификация TOFU:** Бот покажет алгоритм и `SHA256`-отпечаток ключа хоста.
   * Для сверки выполните на целевом сервере команду:
     ```bash
     ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
     ```
   * Если отпечатки совпадают, нажмите **✅ Доверять и проверить вход**.
7. Сервер появится в списке ваших серверов, запустится фоновый мониторинг состояния и Docker-контейнеров.