#!/usr/bin/env bash
set -euo pipefail

TARGET_USER="botadmin"
TARGET_HOME="/home/${TARGET_USER}"
SUDOERS_FILE="/etc/sudoers.d/${TARGET_USER}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[+]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_err()  { echo -e "${RED}[x]${NC} $1"; }

# 1. Проверка прав root
if [ "$(id -u)" -ne 0 ]; then
    log_err "Этот скрипт должен запускаться с правами root (sudo)."
    exit 1
fi

log_info "Подготовка сервера для управления через TG Server Admin Bot..."

# 2. Установка базовых утилит диагностики, используемых ботом
log_info "Проверка и установка базовых пакетов..."
if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq curl iproute2 vnstat sudo openssh-server >/dev/null 2>&1 || true
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q curl iproute vnstat sudo openssh-server >/dev/null 2>&1 || true
fi

# 3. Создание пользователя botadmin
if id "${TARGET_USER}" >/dev/null 2>&1; then
    log_info "Пользователь ${TARGET_USER} уже существует."
else
    log_info "Создание системного пользователя ${TARGET_USER}..."
    useradd -m -s /bin/bash "${TARGET_USER}"
fi

# 4. Добавление в группу docker (если Docker установлен)
if command -v docker >/dev/null 2>&1; then
    log_info "Docker обнаружен на сервере. Добавление ${TARGET_USER} в группу docker..."
    usermod -aG docker "${TARGET_USER}"
else
    log_warn "Docker не найден на сервере (мониторинг контейнеров будет отключен)."
fi

# 5. Запрос и настройка SSH-ключа
SSH_DIR="${TARGET_HOME}/.ssh"
AUTH_KEYS="${SSH_DIR}/authorized_keys"

mkdir -p "${SSH_DIR}"
chmod 700 "${SSH_DIR}"

echo ""
echo -e "${YELLOW}================================================================${NC}"
echo -e "Введите персональный открытый SSH-ключ (из Telegram-бота по команде ${GREEN}/key${NC}):"
echo -e "${YELLOW}================================================================${NC}"
read -rp "SSH Public Key: " INPUT_SSH_KEY

if [[ -z "${INPUT_SSH_KEY// }" ]]; then
    log_err "Ключ не может быть пустым. Прерывание установки."
    exit 1
fi

# Проверяем, чтобы ключ начинался с валидного префикса SSH
if [[ ! "${INPUT_SSH_KEY}" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521) ]]; then
    log_warn "Введенная строка не похожа на валидный публичный ключ OpenSSH."
fi

# Записываем ключ (не дублируя существующие)
touch "${AUTH_KEYS}"
if ! grep -qF "${INPUT_SSH_KEY}" "${AUTH_KEYS}"; then
    echo "${INPUT_SSH_KEY}" >> "${AUTH_KEYS}"
    log_info "Ключ успешно добавлен в ${AUTH_KEYS}"
else
    log_info "Ключ уже присутствует в ${AUTH_KEYS}"
fi

chmod 600 "${AUTH_KEYS}"
chown -R "${TARGET_USER}:${TARGET_USER}" "${SSH_DIR}"

# 6. Создание системных скриптов управления в /usr/local/sbin
log_info "Создание служебных скриптов в /usr/local/sbin/..."
mkdir -p /usr/local/sbin

# Скрипт полного обновления ОС
cat << 'EOF' > /usr/local/sbin/update.sh
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

# Скрипты временного включения/отключения root-доступа
cat << 'EOF' > /usr/local/sbin/root.sh
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

cat << 'EOF' > /usr/local/sbin/unroot.sh
#!/usr/bin/env bash
set -e
SSHD_DROPIN="/etc/ssh/sshd_config.d/99-tgbot-temp-root.conf"
rm -f "$SSHD_DROPIN"
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
echo "Root-доступ принудительно отключен."
EOF

chmod 750 /usr/local/sbin/update.sh /usr/local/sbin/root.sh /usr/local/sbin/unroot.sh
chown root:root /usr/local/sbin/update.sh /usr/local/sbin/root.sh /usr/local/sbin/unroot.sh

# 7. Динамическое определение бинарных путей и настройка sudoers
log_info "Формирование правил sudoers..."

find_bin() {
    local cmd="$1"
    command -v "$cmd" 2>/dev/null || echo "/usr/bin/$cmd"
}

BIN_SYSTEMD_RUN=$(find_bin systemd-run)
BIN_SYSTEMCTL=$(find_bin systemctl)
BIN_JOURNALCTL=$(find_bin journalctl)
BIN_UFW=$(find_bin ufw)
BIN_FAIL2BAN=$(find_bin fail2ban-client)
BIN_SS=$(find_bin ss)
BIN_CERTBOT=$(find_bin certbot)

cat << EOF > "${SUDOERS_FILE}"
# Разрешенные команды для бота мониторинга TG Server Admin Bot
${TARGET_USER} ALL=(ALL) NOPASSWD: \\
    /usr/local/sbin/update.sh, \\
    /usr/local/sbin/root.sh, \\
    /usr/local/sbin/unroot.sh, \\
    ${BIN_SYSTEMD_RUN} --unit=tgbot-upgrade --remain-after-exit /usr/local/sbin/update.sh, \\
    ${BIN_SYSTEMCTL} stop tgbot-upgrade, \\
    ${BIN_SYSTEMCTL} reset-failed tgbot-upgrade, \\
    ${BIN_JOURNALCTL} -u tgbot-upgrade *, \\
    ${BIN_SYSTEMCTL} reboot, \\
    ${BIN_UFW} status numbered, \\
    ${BIN_FAIL2BAN} *, \\
    ${BIN_SS} *, \\
    ${BIN_CERTBOT} certificates
EOF

# Проверка корректности синтаксиса sudoers
if visudo -cf "${SUDOERS_FILE}" >/dev/null 2>&1; then
    chmod 440 "${SUDOERS_FILE}"
    log_info "Правила sudoers валидны и сохранены в ${SUDOERS_FILE}"
else
    log_err "Ошибка синтаксиса в правилах sudoers! Файл удален во избежание сбоев."
    rm -f "${SUDOERS_FILE}"
    exit 1
fi

# 8. Диагностический вывод для ввода параметров в боте
SSH_PORT=$(ss -tlnp | grep -E 'sshd|ssh' | awk '{print $4}' | awk -F':' '{print $NF}' | head -n 1)
SSH_PORT=${SSH_PORT:-22}
SERVER_IP=$(curl -s -m 4 https://api.ipify.org || ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || echo "IP_НЕ_ОПРЕДЕЛЕН")

echo ""
echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN}        СЕРВЕР ГОТОВ К ДОБАВЛЕНИЮ В TELEGRAM-БОТА!              ${NC}"
echo -e "${GREEN}================================================================${NC}"
echo -e "Имя пользователя: ${YELLOW}${TARGET_USER}${NC}"
echo -e "Внешний IP:       ${YELLOW}${SERVER_IP}${NC}"
echo -e "SSH-порт:         ${YELLOW}${SSH_PORT}${NC}"
echo ""
echo -e "Дальнейшие шаги:"
echo -e "1. В Telegram-боте нажмите ${GREEN}➕ Добавить сервер${NC}."
echo -e "2. Укажите понятное имя (например: ${YELLOW}web-node-01${NC})."
echo -e "3. Отправьте адрес хоста: ${YELLOW}${SERVER_IP}${NC}."
echo -e "4. Выберите порт ${YELLOW}${SSH_PORT}${NC} и пользователя ${YELLOW}${TARGET_USER}${NC}."
echo -e "5. Сверьте выведенный ботом отпечаток ключа хоста и подтвердите добавление."
echo -e "${GREEN}================================================================${NC}"