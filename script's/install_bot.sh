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
CYAN='\033[0;36m'
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

# 4. Создание изолированной структуры каталогов и выставление владельца
log_info "Подготовка рабочей директории ${BOT_DIR}..."
mkdir -p "${BOT_DIR}/keys"
chmod 700 "${BOT_HOME}"
chmod 700 "${BOT_DIR}"
chmod 700 "${BOT_DIR}/keys"

# Сразу передаем права пользователю бота, чтобы venv и pip не падали с Errno 13
chown -R "${BOT_USER}:${BOT_USER}" "${BOT_HOME}"

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
chown "${BOT_USER}:${BOT_USER}" "${BOT_DIR}/bot.py"
log_info "Файл bot.py успешно загружен."

# 6. Сканирование и выбор сервисов для мониторинга (MONITORED_SERVICES)
log_info "Сканирование системы на наличие установленных сервисов..."

CANDIDATE_SERVICES=(
    "xray"
    "nginx"
    "telemt"
    "sing-box"
    "v2ray"
    "caddy"
    "apache2"
    "docker"
    "fail2ban"
    "ufw"
    "haproxy"
    "marzban"
    "tg-server-bot"
)

DETECTED_SERVICES=()
for svc in "${CANDIDATE_SERVICES[@]}"; do
    if systemctl list-unit-files "${svc}.service" >/dev/null 2>&1 || systemctl is-active --quiet "${svc}" 2>/dev/null; then
        DETECTED_SERVICES+=("${svc}")
    fi
done

SELECTED_SERVICES=()

if [ ${#DETECTED_SERVICES[@]} -gt 0 ]; then
    echo -e "\n${CYAN}=== Обнаруженные службы на сервере ===${NC}"
    for i in "${!DETECTED_SERVICES[@]}"; do
        status="inactive"
        if systemctl is-active --quiet "${DETECTED_SERVICES[$i]}" 2>/dev/null; then
            status="active"
        fi
        echo -e " [${GREEN}$((i+1))${NC}] ${DETECTED_SERVICES[$i]} (${status})"
    done
    echo ""
    read -rp "Выберите номера сервисов через запятую (например, 1,2) или Enter для добавления всех: " user_choice

    if [ -z "${user_choice// }" ]; then
        SELECTED_SERVICES=("${DETECTED_SERVICES[@]}")
    else
        IFS=',' read -ra CHOICES <<< "${user_choice}"
        for c in "${CHOICES[@]}"; do
            idx=$(( ${c// /} - 1 ))
            if [ "$idx" -ge 0 ] && [ "$idx" -lt "${#DETECTED_SERVICES[@]}" ]; then
                SELECTED_SERVICES+=("${DETECTED_SERVICES[$idx]}")
            fi
        done
    fi
else
    log_warn "Автоматически не обнаружено предустановленных сервисов из базы."
fi

# Запрос на добавление произвольных сервисов вручную
read -rp "Хотите добавить другие службы вручную? (имена через пробел или Enter для пропуска): " manual_services
if [ -n "${manual_services// }" ]; then
    for ms in ${manual_services}; do
        SELECTED_SERVICES+=("${ms}")
    done
fi

# Дефолтный список, если ничего не выбрано
if [ ${#SELECTED_SERVICES[@]} -eq 0 ]; then
    SELECTED_SERVICES=("xray" "nginx" "telemt" "tg-server-bot")
fi

# Устранение дубликатов
UNIQUE_SERVICES=($(printf "%s\n" "${SELECTED_SERVICES[@]}" | sort -u))
SERVICES_JSON=$(python3 -c "import sys, json; print(json.dumps(sys.argv[1:]))" "${UNIQUE_SERVICES[@]}")

log_info "Применение выбранных сервисов в bot.py: ${SERVICES_JSON}"

# Обновление переменной MONITORED_SERVICES в bot.py
python3 - <<EOF
import re
import json

services = json.loads('''${SERVICES_JSON}''')
bot_file = "${BOT_DIR}/bot.py"

with open(bot_file, "r", encoding="utf-8") as f:
    code = f.read()

new_code = re.sub(
    r'MONITORED_SERVICES\s*=\s*\[[^\]]*\]',
    f'MONITORED_SERVICES = {json.dumps(services)}',
    code,
    count=1
)

with open(bot_file, "w", encoding="utf-8") as f:
    f.write(new_code)
EOF

chown "${BOT_USER}:${BOT_USER}" "${BOT_DIR}/bot.py"
log_info "Конфигурация MONITORED_SERVICES успешно обновлена."

# 7. Развертывание виртуального окружения Python
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

# 8. Конфигурация .env
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
    chown "${BOT_USER}:${BOT_USER}" "${ENV_FILE}"
    log_info "Файл .env успешно создан."
else
    log_warn "Файл ${ENV_FILE} уже существует, пропускаем генерацию."
fi

# 9. Создание служебных файлов с правами 0600
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

# Финальное подтверждение прав на всю директорию
chown -R "${BOT_USER}:${BOT_USER}" "${BOT_DIR}"

# 10. Настройка и запуск systemd-сервиса
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

# 11. Проверка статуса
sleep 2
if systemctl is-active --quiet "${SERVICE_NAME}"; then
    log_info "Бот успешно установлен и запущен под пользователем ${BOT_USER}!"
    echo "------------------------------------------------------"
    echo "Пользователь:       ${BOT_USER}"
    echo "Директория бота:    ${BOT_DIR}"
    echo "Мониторинг служб:   ${SERVICES_JSON}"
    echo "Статус сервиса:     systemctl status ${SERVICE_NAME}"
    echo "Журнал логов:       journalctl -u ${SERVICE_NAME} -f"
    echo "------------------------------------------------------"
else
    log_err "Служба не смогла запуститься. Проверьте логи: journalctl -u ${SERVICE_NAME} -n 30"
    exit 1
fi
