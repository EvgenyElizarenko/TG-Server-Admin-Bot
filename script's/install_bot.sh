#!/usr/bin/env bash
set -euo pipefail

# ================= КОНФИГУРАЦИЯ УСТАНОВКИ =================
BOT_USER="tgbot"
BOT_HOME="/home/${BOT_USER}"
BOT_DIR="${BOT_HOME}/tg-bot-env"
SERVICE_NAME="tg-server-bot"
BOT_REPO_URL="https://raw.githubusercontent.com/EvgenyElizarenko/TG-Server-Admin-Bot/refs/heads/main/bot_souce_code/bot.py"

# Цвета терминала
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[+]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_err()  { echo -e "${RED}[x]${NC} $1"; }

# 1. Проверка прав root
if [ "$(id -u)" -ne 0 ]; then
    log_err "Этот скрипт должен быть запущен с правами root (через sudo)."
    exit 1
fi

log_info "Запуск установки TG Server Admin Bot для пользователя ${BOT_USER}..."

# 2. Установка системных зависимостей
log_info "Установка системных пакетов (Python, venv, OpenSSH, curl)..."
if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq python3 python3-venv python3-pip openssh-client curl git
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q python3 python3-pip openssh-clients curl git
else
    log_warn "Пакетный менеджер не определен автоматически. Убедитесь в наличии python3, venv, curl и openssh-client."
fi

# 3. Создание системного пользователя
if id "${BOT_USER}" >/dev/null 2>&1; then
    log_info "Пользователь ${BOT_USER} уже существует."
else
    log_info "Создание сервисного пользователя ${BOT_USER}..."
    useradd -m -s /bin/bash "${BOT_USER}"
fi

# 4. Создание изолированной структуры каталогов (права 0700)
log_info "Подготовка рабочей директории ${BOT_DIR}..."
mkdir -p "${BOT_DIR}/keys"
chmod 700 "${BOT_HOME}"
chmod 700 "${BOT_DIR}"
chmod 700 "${BOT_DIR}/keys"

# 5. Загрузка bot.py напрямую из GitHub-репозитория
log_info "Скачивание bot.py из репозитория GitHub..."
if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "${BOT_DIR}/bot.py" "${BOT_REPO_URL}"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "${BOT_DIR}/bot.py" "${BOT_REPO_URL}"
else
    log_err "Не найден ни curl, ни wget для загрузки bot.py."
    exit 1
fi

if [ ! -s "${BOT_DIR}/bot.py" ]; then
    log_err "Файл bot.py не был загружен или оказался пуст. Проверьте доступность URL: ${BOT_REPO_URL}"
    exit 1
fi

chmod 700 "${BOT_DIR}/bot.py"
log_info "Файл bot.py успешно загружен."

# 6. Развертывание виртуального окружения Python
log_info "Создание виртуального окружения Python..."
if [ ! -d "${BOT_DIR}/venv" ]; then
    sudo -u "${BOT_USER}" python3 -m venv "${BOT_DIR}/venv"
fi

log_info "Установка зависимостей (aiogram, asyncssh, python-dotenv)..."
sudo -u "${BOT_USER}" "${BOT_DIR}/venv/bin/pip" install --upgrade --quiet pip
sudo -u "${BOT_USER}" "${BOT_DIR}/venv/bin/pip" install --quiet \
    "aiogram>=3.4.0" \
    "asyncssh>=2.14.0" \
    "python-dotenv>=1.0.0"

# 7. Конфигурация .env
ENV_FILE="${BOT_DIR}/.env"
if [ ! -f "${ENV_FILE}" ]; then
    log_info "Настройка конфигурации бота (.env):"
    
    read -rp "Введите Telegram BOT_TOKEN: " input_token
    read -rp "Введите числовые ADMIN_IDS (через запятую): " input_admins

    cat <<EOF > "${ENV_FILE}"
BOT_TOKEN=${input_token}
ADMIN_IDS=${input_admins}
EOF
    chmod 600 "${ENV_FILE}"
    log_info "Файл .env успешно создан."
else
    log_warn "Файл ${ENV_FILE} уже существует, пропускаем генерацию."
fi

# 8. Создание служебных файлов с правами 0600
for f in "servers.json" "users.json" "known_hosts" "audit.log"; do
    target_file="${BOT_DIR}/${f}"
    if [ ! -f "${target_file}" ]; then
        touch "${target_file}"
        if [[ "${f}" == *".json" ]]; then
            echo "{}" > "${target_file}"
        fi
    fi
    chmod 600 "${target_file}"
done

# Корректировка владельца всех файлов
chown -R "${BOT_USER}:${BOT_USER}" "${BOT_DIR}"

# 9. Настройка и запуск systemd-сервиса
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
log_info "Создание службы systemd: ${SERVICE_FILE}..."

cat <<EOF > "${SERVICE_FILE}"
[Unit]
Description=Telegram Server Admin & Monitoring Bot
After=network.target

[Service]
Type=simple
User=${BOT_USER}
Group=${BOT_USER}
WorkingDirectory=${BOT_DIR}
ExecStart=${BOT_DIR}/venv/bin/python ${BOT_DIR}/bot.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Ограничения безопасности процесса
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${BOT_DIR}

[Install]
WantedBy=multi-user.target
EOF

log_info "Активация и запуск службы..."
systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}"

# 10. Проверка статуса
sleep 2
if systemctl is-active --quiet "${SERVICE_NAME}"; then
    log_info "Бот успешно установлен и запущен под пользователем ${BOT_USER}!"
    echo "------------------------------------------------------"
    echo "Пользователь:    ${BOT_USER}"
    echo "Директория бота: ${BOT_DIR}"
    echo "Статус сервиса:  systemctl status ${SERVICE_NAME}"
    echo "Журнал логов:    journalctl -u ${SERVICE_NAME} -f"
    echo "------------------------------------------------------"
else
    log_err "Служба не смогла запуститься. Проверьте логи: journalctl -u ${SERVICE_NAME} -n 30"
    exit 1
fi