#!/usr/bin/env bash
set -euo pipefail

# ================= КОНФИГУРАЦИЯ ПО УМОЛЧАНИЮ =================
BOT_USER="botadmin"
SSH_PUB_KEY="${1:-}" # Можно передать ключ первым аргументом: ./setup_node.sh "ssh-ed25519 AAAA..."
# =============================================================

if [ "$(id -u)" -ne 0 ]; then
    echo "❌ Ошибка: скрипт должен быть запущен с правами root!" >&2
    exit 1
fi

echo "=== [1/6] Проверка SSH-ключа ==="
if [ -z "$SSH_PUB_KEY" ]; then
    echo -n "Вставьте ваш публичный SSH-ключ из бота (команда /key): "
    read -r SSH_PUB_KEY
fi

if [[ ! "$SSH_PUB_KEY" =~ ^ssh-(ed25519|rsa) ]]; then
    echo "❌ Ошибка: передан некорректный формат публичного SSH-ключа!" >&2
    exit 1
fi

echo "=== [2/6] Установка базовых утилит ==="
if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq sudo curl iproute2 vnstat ufw >/dev/null
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q sudo curl iproute vnstat >/dev/null
fi

# Включаем сбор статистики vnstat, если служба присутствует
systemctl enable --now vnstat 2>/dev/null || true

echo "=== [3/6] Создание пользователя ${BOT_USER} ==="
if ! id -u "$BOT_USER" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$BOT_USER"
    echo "Пользователь ${BOT_USER} создан."
fi

# Добавляем в группы управления
usermod -aG sudo "$BOT_USER" 2>/dev/null || usermod -aG wheel "$BOT_USER" 2>/dev/null || true
if getent group docker >/dev/null 2>&1; then
    usermod -aG docker "$BOT_USER"
fi

# Настройка authorized_keys
USER_HOME=$(eval echo "~${BOT_USER}")
mkdir -p "${USER_HOME}/.ssh"
chmod 0700 "${USER_HOME}/.ssh"
echo "$SSH_PUB_KEY" > "${USER_HOME}/.ssh/authorized_keys"
chmod 0600 "${USER_HOME}/.ssh/authorized_keys"
chown -R "${BOT_USER}:${BOT_USER}" "${USER_HOME}/.ssh"

# Беспарольный sudo для botadmin
cat << 'EOF' > "/etc/sudoers.d/99-tgbot-${BOT_USER}"
botadmin ALL=(ALL) NOPASSWD: ALL
EOF
chmod 0440 "/etc/sudoers.d/99-tgbot-${BOT_USER}"

echo "=== [4/6] Установка системных скриптов бота ==="

# 1. Скрипт обновления ОС (/usr/local/sbin/update.sh)
cat << 'EOF' > /usr/local/sbin/update.sh
#!/usr/bin/env bash
set -e
export DEBIAN_FRONTEND=noninteractive
if command -v apt-get >/dev/null 2>&1; then
    apt-get update && apt-get dist-upgrade -y && apt-get autoremove -y && apt-get clean
elif command -v dnf >/dev/null 2>&1; then
    dnf upgrade -y && dnf autoremove -y
fi
exit 0
EOF
chmod 0750 /usr/local/sbin/update.sh

# 2. Скрипт закрытия root-доступа (/usr/local/sbin/unroot.sh)
cat << 'EOF' > /usr/local/sbin/unroot.sh
#!/usr/bin/env bash
sed -i -E 's/^#?[[:space:]]*PermitRootLogin[[:space:]]+.*/PermitRootLogin no/' /etc/ssh/sshd_config
if [ -d /etc/ssh/sshd_config.d ]; then
    rm -f /etc/ssh/sshd_config.d/99-tgbot-root.conf
fi
systemctl reload ssh || systemctl reload sshd
echo "Root-доступ по SSH отключен."
EOF
chmod 0750 /usr/local/sbin/unroot.sh

# 3. Скрипт временного включения root на 2 минуты (/usr/local/sbin/root.sh)
cat << 'EOF' > /usr/local/sbin/root.sh
#!/usr/bin/env bash
mkdir -p /etc/ssh/sshd_config.d
echo "PermitRootLogin yes" > /etc/ssh/sshd_config.d/99-tgbot-root.conf
systemctl reload ssh || systemctl reload sshd
echo "Root-доступ включен на 120 секунд."

# Планируем автоматический откат через фоновый таймер systemd
systemd-run --on-active=120s --unit=tgbot-unroot-timer /usr/local/sbin/unroot.sh >/dev/null 2>&1 || {
    ( sleep 120 && /usr/local/sbin/unroot.sh ) >/dev/null 2>&1 &
}
EOF
chmod 0750 /usr/local/sbin/root.sh

echo "=== [5/6] Определение текущего SSH-порта ==="
# Удаляем старый принудительный конфиг смены порта, если он остался от прошлых запусков
rm -f /etc/ssh/sshd_config.d/90-tgbot-port.conf

# 1. Запрос порта из текущей конфигурации sshd
DETECTED_PORT=$(sshd -T 2>/dev/null | awk '/^port / {print $2; exit}' || true)

# 2. Если sshd -T недоступен, определяем слушающий сокет sshd
if [ -z "$DETECTED_PORT" ]; then
    DETECTED_PORT=$(ss -tlHnp 2>/dev/null | grep -E 'users:.*sshd' | awk '{print $4}' | awk -F: '{print $NF}' | sort -u | head -n 1 || true)
fi

# 3. Фоллбек на порт текущей активной SSH-сессии
if [ -z "$DETECTED_PORT" ] && [ -n "${SSH_CONNECTION:-}" ]; then
    DETECTED_PORT=$(echo "$SSH_CONNECTION" | awk '{print $4}')
fi

# Если определить не удалось — стандартный 22
CURRENT_PORT="${DETECTED_PORT:-22}"

# Проверяем и разрешаем текущий порт в UFW (если фаервол активен)
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow "${CURRENT_PORT}/tcp" comment "Current SSH Port" >/dev/null
fi

echo "Текущий SSH-порт сервера: ${CURRENT_PORT} (без изменений)"

echo "=== [6/6] Отпечатки хоста для сверки (TOFU в боте) ==="
echo "--------------------------------------------------------"
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null || ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub
echo "--------------------------------------------------------"
echo "✅ Сервер успешно настроен!"
echo "• Пользователь: ${BOT_USER}"
echo "• SSH-порт:     ${CURRENT_PORT}"
echo "• IP-адрес:     $(hostname -I | awk '{print $1}')"
echo ""
echo "В боте при добавлении сервера укажите этот порт: ${CURRENT_PORT}."
