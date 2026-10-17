#!/usr/bin/env python3
import asyncio
import html
import ipaddress
import json
import logging
import os
import re
import secrets
import shlex
import stat
import time
from dataclasses import dataclass
from typing import Optional

from aiogram import Bot, Dispatcher, F, types
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramBadRequest
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import BotCommand, InlineKeyboardButton, InlineKeyboardMarkup
from aiogram.utils.keyboard import InlineKeyboardBuilder
import asyncssh

# ================= КОНФИГУРАЦИЯ =================
BASE_DIR = "/home/tgbot/tg-bot-env"
ENV_FILE = os.path.join(BASE_DIR, ".env")

if not os.getenv("BOT_TOKEN") and os.path.exists(ENV_FILE):
    try:
        from dotenv import load_dotenv
        load_dotenv(ENV_FILE)
    except ImportError:
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip("'\""))

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
if not BOT_TOKEN:
    raise RuntimeError("Критическая ошибка: переменная BOT_TOKEN не найдена в окружении или файле .env!")

raw_admins = os.getenv("ADMIN_IDS", "").strip()
ADMIN_IDS = [int(x.strip()) for x in raw_admins.split(",") if x.strip().isdigit()]
if not ADMIN_IDS:
    raise RuntimeError("Критическая ошибка: переменная ADMIN_IDS пуста или содержит некорректные ID!")

KEYS_DIR = os.path.join(BASE_DIR, "keys")
SERVERS_FILE = os.path.join(BASE_DIR, "servers.json")
USERS_FILE = os.path.join(BASE_DIR, "users.json")
KNOWN_HOSTS_FILE = os.path.join(BASE_DIR, "known_hosts")
AUDIT_LOG_FILE = os.path.join(BASE_DIR, "audit.log")

MONITORED_SERVICES = ["xray", "nginx", "telemt", "tg-server-bot"]
DISK_THRESHOLD_PERCENT = 85
WATCHER_INTERVAL = 180
OFFLINE_STRIKES_LIMIT = 2
MAX_SERVERS_PER_USER = 5
REKEY_TTL_SECONDS = 300
UNPINNED_NOTICE_INTERVAL = 86400  # повторять уведомление о неподтверждённых отпечатках не чаще раза в сутки

# Валидаторы безопасности
RE_SERVER_NAME = re.compile(r"^[a-zA-Z0-9_-]{2,24}$")
RE_CONTAINER_ID = re.compile(r"^[a-f0-9]{12}$")
RE_IPV4 = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
VALID_DOCKER_STATUSES = {"running", "exited", "paused", "restarting", "created", "dead"}
# =================================================

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
dp = Dispatcher(storage=MemoryStorage())

upgrade_locks = set()
maintenance_until = {}
watcher_task: Optional[asyncio.Task] = None
background_tasks: set[asyncio.Task] = set()

# Хранилище временных токенов подтверждения ключей
pending_rekeys: dict[str, dict] = {}

# Блокировки генерации ключей (по пользователю) и журнал попыток зондирования хостов
_key_locks: dict[int, asyncio.Lock] = {}
probe_attempts: dict[int, list] = {}
PROBE_WINDOW_SECONDS = 600
PROBE_MAX_ATTEMPTS = 6


def _log_task_result(task: asyncio.Task):
    if task.cancelled():
        return
    exc = task.exception()
    if exc:
        logging.error(f"Фоновая задача завершилась с ошибкой: {exc!r}", exc_info=exc)


def spawn_task(coro) -> asyncio.Task:
    """Создает фоновую задачу и защищает её от сборщика мусора (GC)."""
    task = asyncio.create_task(coro)
    background_tasks.add(task)
    task.add_done_callback(background_tasks.discard)
    task.add_done_callback(_log_task_result)
    return task


@dataclass
class SSHResult:
    success: bool
    stdout: str
    stderr: str
    exit_status: int
    error: str = ""
    host_key_mismatch: bool = False

    def text(self) -> str:
        """Возвращает читаемый вывод или ошибку."""
        out = (self.stdout or "").strip()
        if out:
            return out
        err = (self.stderr or "").strip()
        if err:
            return err
        if self.error:
            return self.error
        return "Пустой ответ от сервера."


# --- БЕЗОПАСНАЯ РАБОТА С ФАЙЛАМИ И КАТАЛОГАМИ (0700/0600) ---


def ensure_secure_dir(dirpath: str):
    """Гарантирует права 0700 на каталоги."""
    if not dirpath:
        return
    os.makedirs(dirpath, mode=0o700, exist_ok=True)
    try:
        st = os.stat(dirpath)
        current_mode = stat.S_IMODE(st.st_mode)
        if current_mode != 0o700 and (st.st_uid == os.getuid() or os.getuid() == 0):
            os.chmod(dirpath, 0o700)
    except OSError as e:
        logging.error(f"Не удалось выставить права 0700 на {dirpath}: {e}")


def ensure_secure_file(filepath: str):
    """Гарантирует права 0700 на родительский каталог и 0600 на файл."""
    ensure_secure_dir(os.path.dirname(filepath))
    if not os.path.exists(filepath):
        fd = os.open(filepath, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
    try:
        st = os.stat(filepath)
        if stat.S_IMODE(st.st_mode) != 0o600 and (st.st_uid == os.getuid() or os.getuid() == 0):
            os.chmod(filepath, 0o600)
    except OSError as e:
        logging.error(f"Не удалось выставить права 0600 на {filepath}: {e}")


def atomic_json_dump(filepath: str, data: dict):
    """Атомарно сохраняет JSON с обязательными правами 0600."""
    ensure_secure_dir(os.path.dirname(filepath))
    tmp_path = f"{filepath}.tmp.{os.getpid()}"
    fd = os.open(tmp_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, filepath)
    os.chmod(filepath, 0o600)


# --- АУДИТ-ЛОГИРОВАНИЕ ---


def log_audit(user_id: int, srv_name: str, action: str, details: str = ""):
    """Запись действий в локальный файл аудита с правами 0600."""
    u_name = get_user_display_name(user_id)
    entry = (
        f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
        f"UID:{user_id} ({u_name}) | "
        f"SRV:{srv_name} | "
        f"ACTION:{action} | "
        f"DETAILS:{details}\n"
    )
    try:
        ensure_secure_file(AUDIT_LOG_FILE)
        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(entry)
    except Exception as e:
        logging.error(f"Ошибка записи аудит-лога: {e}")
    logging.info(f"AUDIT: {entry.strip()}")


# --- ПЕРСОНАЛЬНЫЕ SSH-КЛЮЧИ ПОЛЬЗОВАТЕЛЕЙ ---


async def ensure_user_ssh_keys(user_id: int) -> tuple[str, str]:
    """Возвращает (private_key_path, public_key_str), создавая ed25519 пару при необходимости."""
    if user_id in ADMIN_IDS and os.path.exists("/home/tgbot/.ssh/id_tgbot"):
        ensure_secure_dir("/home/tgbot/.ssh")
        priv_path = "/home/tgbot/.ssh/id_tgbot"
        pub_path = "/home/tgbot/.ssh/id_tgbot.pub"
        ensure_secure_file(priv_path)
        pub_str = ""
        if os.path.exists(pub_path):
            with open(pub_path, "r", encoding="utf-8") as f:
                pub_str = f.read().strip()
        return priv_path, pub_str

    ensure_secure_dir(BASE_DIR)
    ensure_secure_dir(KEYS_DIR)
    user_dir = os.path.join(KEYS_DIR, str(user_id))
    ensure_secure_dir(user_dir)

    priv_path = os.path.join(user_dir, "id_ed25519")
    pub_path = os.path.join(user_dir, "id_ed25519.pub")

    lock = _key_locks.setdefault(user_id, asyncio.Lock())
    async with lock:
        if not os.path.exists(priv_path):
            proc = await asyncio.create_subprocess_exec(
                "ssh-keygen", "-t", "ed25519", "-N", "", "-C", f"tgbot-user-{user_id}", "-f", priv_path,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.wait()

    if os.path.exists(priv_path):
        ensure_secure_file(priv_path)
    if os.path.exists(pub_path):
        ensure_secure_file(pub_path)

    pub_str = ""
    if os.path.exists(pub_path):
        with open(pub_path, "r", encoding="utf-8") as f:
            pub_str = f.read().strip()

    return priv_path, pub_str


async def get_server_key_path(srv_conf: dict) -> str:
    """Возвращает путь к SSH-ключу владельца сервера."""
    creator_id = srv_conf.get("creator_id", ADMIN_IDS[0] if ADMIN_IDS else 0)
    priv_path, _ = await ensure_user_ssh_keys(creator_id)
    return priv_path


# --- РАБОТА С KNOWN_HOSTS И TOFU ---


def format_known_hosts_pattern(host: str, port: int) -> str:
    return f"[{host}]:{port}" if port != 22 else host


def format_known_hosts_entry(host: str, port: int, key_str: str) -> str:
    pattern = format_known_hosts_pattern(host, port)
    parts = key_str.strip().split()
    clean_key = f"{parts[0]} {parts[1]}" if len(parts) >= 2 else key_str.strip()
    return f"{pattern} {clean_key}\n"


def record_host_key(host: str, port: int, key_str: str):
    ensure_secure_file(KNOWN_HOSTS_FILE)
    line = format_known_hosts_entry(host, port, key_str)
    remove_host_key(host, port)
    with open(KNOWN_HOSTS_FILE, "a", encoding="utf-8") as f:
        f.write(line)
    os.chmod(KNOWN_HOSTS_FILE, 0o600)


def remove_host_key(host: str, port: int):
    if not os.path.exists(KNOWN_HOSTS_FILE):
        return
    pattern = format_known_hosts_pattern(host, port)
    try:
        with open(KNOWN_HOSTS_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        filtered = [l for l in lines if not l.startswith(pattern + " ")]
        tmp_path = f"{KNOWN_HOSTS_FILE}.tmp.{os.getpid()}"
        fd = os.open(tmp_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.writelines(filtered)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, KNOWN_HOSTS_FILE)
        os.chmod(KNOWN_HOSTS_FILE, 0o600)
    except Exception as e:
        logging.error(f"Ошибка обновления {KNOWN_HOSTS_FILE}: {e}")


def has_host_key(host: str, port: int) -> bool:
    """Есть ли в known_hosts запись для host:port."""
    if not os.path.exists(KNOWN_HOSTS_FILE):
        return False
    pattern = format_known_hosts_pattern(host, port) + " "
    try:
        with open(KNOWN_HOSTS_FILE, "r", encoding="utf-8") as f:
            return any(line.startswith(pattern) for line in f)
    except OSError:
        return False


def allow_probe(user_id: int) -> bool:
    """Ограничение числа попыток зондирования чужих хостов (защита от сканирования)."""
    now = time.time()
    attempts = [t for t in probe_attempts.get(user_id, []) if now - t < PROBE_WINDOW_SECONDS]
    if len(attempts) >= PROBE_MAX_ATTEMPTS:
        probe_attempts[user_id] = attempts
        return False
    attempts.append(now)
    probe_attempts[user_id] = attempts
    return True


async def fetch_unverified_host_key(host: str, port: int) -> tuple[bool, dict, str]:
    """Получает публичный ключ хоста без аутентификации и без запуска команд."""
    try:
        server_host_key = await asyncio.wait_for(
            asyncssh.get_server_host_key(host, port=port),
            timeout=10,
        )
        if not server_host_key:
            return False, {}, "Сервер не предоставил открытый ключ хоста."
        key_export = server_host_key.export_public_key("openssh")
        key_str = key_export.decode("utf-8").strip() if isinstance(key_export, bytes) else str(key_export).strip()
        fp = server_host_key.get_fingerprint("sha256")
        alg = server_host_key.get_algorithm()
        return True, {"key_str": key_str, "fp": fp, "alg": alg, "host": host, "port": port}, ""
    except Exception as e:
        return False, {}, str(e)


def cleanup_expired_rekeys():
    """Очищает просроченные запросы обновления ключей."""
    now = time.time()
    expired = [k for k, v in pending_rekeys.items() if now - v.get("ts", 0) > REKEY_TTL_SECONDS]
    for k in expired:
        pending_rekeys.pop(k, None)


# --- ЗАЩИТА ОТ ИСПОЛЬЗОВАНИЯ В КАЧЕСТВЕ СКАНЕРА СЕТИ (SSRF) ---


async def validate_target_host(host: str, is_admin_user: bool) -> tuple[bool, str]:
    """Запрещает добавление приватных/локальных сетей обычными пользователями."""
    if not re.match(r"^[a-zA-Z0-9.-]+$", host) or ".." in host or host.startswith("-"):
        return False, "Некорректный формат адреса или домена."

    if is_admin_user:
        return True, ""

    if host.lower() in ("localhost", "localhost.localdomain"):
        return False, "Локальные адреса запрещены."

    loop = asyncio.get_running_loop()
    try:
        addr_info = await loop.getaddrinfo(host, None)
    except Exception:
        return False, "Не удалось разрешить IP-адрес или домен."

    for item in addr_info:
        ip_str = item[4][0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
                or ip_obj.is_unspecified
            ):
                return False, f"Адрес {ip_str} принадлежит приватной или системной сети."
        except ValueError:
            return False, "Некорректный IP-адрес при валидации."

    return True, ""


# --- ХРАНИЛИЩА ПОЛЬЗОВАТЕЛЕЙ И СЕРВЕРОВ ---


def load_users() -> dict:
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        ensure_secure_file(USERS_FILE)
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Ошибка чтения {USERS_FILE}: {e}")
        return {}


def save_users(users_dict: dict):
    atomic_json_dump(USERS_FILE, users_dict)


def is_admin(user_id: int) -> bool:
    if user_id in ADMIN_IDS:
        return True
    return load_users().get(str(user_id), {}).get("role") == "admin"


def is_allowed_user(user_id: int) -> bool:
    if user_id in ADMIN_IDS:
        return True
    return str(user_id) in load_users()


def get_user_display_name(user_id: int) -> str:
    if user_id in ADMIN_IDS:
        return "Администратор"
    u_data = load_users().get(str(user_id))
    if u_data and u_data.get("name"):
        return str(u_data["name"])
    return f"User_{user_id}"


def load_servers() -> dict:
    if not os.path.exists(SERVERS_FILE):
        return {}
    try:
        ensure_secure_file(SERVERS_FILE)
        with open(SERVERS_FILE, "r", encoding="utf-8") as f:
            servers = json.load(f)

        changed = False
        default_creator = ADMIN_IDS[0] if ADMIN_IDS else 0
        for data in servers.values():
            try:
                port_int = int(data.get("port", 22))
            except (TypeError, ValueError):
                port_int = 22
            if data.get("port") != port_int:
                data["port"] = port_int
                changed = True
            if "creator_id" not in data:
                data["creator_id"] = default_creator
                changed = True
            if "owners" not in data or not isinstance(data["owners"], list):
                data["owners"] = list(set(ADMIN_IDS + [data["creator_id"]]))
                changed = True

        if changed:
            save_servers(servers)
        return servers
    except Exception as e:
        logging.error(f"Ошибка чтения {SERVERS_FILE}: {e}")
        return {}


def save_servers(servers_dict: dict):
    atomic_json_dump(SERVERS_FILE, servers_dict)


SERVERS = load_servers()
server_states = {}


def is_valid_existing_server(srv_name: str) -> bool:
    return srv_name in SERVERS


def init_server_state(srv_name: str):
    if srv_name not in server_states:
        server_states[srv_name] = {
            "online": True,
            "strikes": 0,
            "disk_critical": False,
            "failed_services": set(),
            "failed_containers": set(),
            "known_containers": set(),
        }


for s in SERVERS:
    init_server_state(s)


def has_server_access(user_id: int, srv_name: str) -> bool:
    if is_admin(user_id):
        return True
    srv = SERVERS.get(srv_name)
    if not srv:
        return False
    return user_id in srv.get("owners", [])


def can_delete_server(user_id: int, srv_name: str) -> bool:
    if is_admin(user_id):
        return True
    srv = SERVERS.get(srv_name)
    return bool(srv and srv.get("creator_id") == user_id)


# --- ХЕЛПЕРЫ ДЛЯ TELEGRAM ---


def truncate_html(text: str, max_chars: int = 3500) -> str:
    """Берёт хвост текста и экранирует его. Длина результата (уже с &quot;, &amp; и т.п.) не превышает max_chars."""
    raw = (text or "").strip()
    if len(raw) > max_chars:
        raw = raw[-max_chars:]
    escaped = html.escape(raw)
    while len(escaped) > max_chars and raw:
        raw = raw[max(1, len(raw) // 10):]
        escaped = html.escape(raw)
    return escaped


async def safe_edit_text(message: types.Message, text: str, reply_markup=None) -> bool:
    try:
        await message.edit_text(text, reply_markup=reply_markup)
        return True
    except TelegramBadRequest as e:
        if "message is not modified" in str(e).lower():
            return False
        raise


# --- FSM СОСТОЯНИЯ ---


class AddServerWizard(StatesGroup):
    waiting_for_name = State()
    waiting_for_host = State()
    waiting_for_custom_port = State()
    waiting_for_custom_user = State()
    waiting_for_tofu_confirm = State()


class AddUserWizard(StatesGroup):
    waiting_for_id = State()
    waiting_for_name = State()


# --- ДИАГНОСТИЧЕСКИЕ КОМАНДЫ (ТОЧНЫЙ СЧЁТ CPU И ФИЛЬТР КОНТЕЙНЕРОВ) ---

STATS_COMMAND = r"""
export LC_ALL=C
echo "=== UPTIME & CPU ==="
uptime
read -r _ u1 n1 s1 i1 w1 x1 y1 z1 _ < /proc/stat
t1=$((u1 + n1 + s1 + i1 + w1 + x1 + y1 + z1))
id1=$((i1 + w1))

IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
if [ -n "$IFACE" ]; then
    R1=$(cat /sys/class/net/$IFACE/statistics/rx_bytes 2>/dev/null || echo 0)
    T1=$(cat /sys/class/net/$IFACE/statistics/tx_bytes 2>/dev/null || echo 0)
fi

sleep 1

read -r _ u2 n2 s2 i2 w2 x2 y2 z2 _ < /proc/stat
t2=$((u2 + n2 + s2 + i2 + w2 + x2 + y2 + z2))
id2=$((i2 + w2))
dt=$((t2 - t1))
did=$((id2 - id1))
if [ "$dt" -gt 0 ]; then
    CPU_USAGE=$(awk -v dt="$dt" -v did="$did" 'BEGIN {printf "%.1f%%", (dt - did) * 100 / dt}')
else
    CPU_USAGE="0.0%"
fi
echo "CPU Load: $CPU_USAGE"
echo ""
echo "=== MEMORY ==="
free -h | awk '/^Mem:/ {print "Использовано: "$3" / "$2" (доступно "$7")"}'
echo ""
echo "=== DISK (/) ==="
df -h / | awk 'NR==2 {print "Занято: "$3" / "$2" ("$5")"}'
echo ""
echo "=== NETWORK (1s delta) ==="
if [ -n "$IFACE" ]; then
    R2=$(cat /sys/class/net/$IFACE/statistics/rx_bytes 2>/dev/null || echo 0)
    T2=$(cat /sys/class/net/$IFACE/statistics/tx_bytes 2>/dev/null || echo 0)
    echo "Интерфейс: $IFACE"
    echo "RX: $(( (R2 - R1) / 1024 )) KB/s | TX: $(( (T2 - T1) / 1024 )) KB/s"
else
    echo "Интерфейс не определен"
fi
"""

CHECK_ALL_COMMAND = r"""
export LC_ALL=C
df / --output=pcent 2>/dev/null | tail -n 1 | tr -dc '0-9'
echo ""
echo "===SERVICES==="
for s in %s; do
    LOAD=$(systemctl show "$s" -p LoadState 2>/dev/null | cut -d= -f2)
    if [ "$LOAD" = "loaded" ]; then
        if systemctl is-active --quiet "$s" 2>/dev/null; then
            echo "sys|$s|active"
        else
            echo "sys|$s|inactive"
        fi
    fi
done
echo "===DOCKER==="
if command -v docker >/dev/null 2>&1; then
    if systemctl is-active --quiet docker 2>/dev/null; then
        echo "dk_daemon|active"
        CIDS=$(docker ps -aq 2>/dev/null)
        if [ -n "$CIDS" ]; then
            docker inspect --format 'dk|{{.Id}}|{{.Name}}|{{.State.Status}}|{{.State.ExitCode}}' $CIDS 2>/dev/null || true
        fi
    else
        echo "dk_daemon|inactive"
    fi
fi
exit 0
""" % " ".join(MONITORED_SERVICES)


# --- SSH ТРАНСПОРТ С ПРОВЕРКОЙ HOST KEY И ПРАВ ---


async def run_ssh(server_key: str, command: str, timeout: int = 40) -> SSHResult:
    if server_key not in SERVERS:
        return SSHResult(False, "", "", -1, "Сервер не найден в конфигурации")
    return await run_ssh_direct(SERVERS[server_key], command, timeout)


async def run_ssh_direct(conf: dict, command: str, timeout: int = 40) -> SSHResult:
    ensure_secure_file(KNOWN_HOSTS_FILE)
    key_path = await get_server_key_path(conf)
    try:
        async with asyncssh.connect(
            conf["host"],
            port=int(conf.get("port", 22)),
            username=conf["user"],
            client_keys=[key_path],
            known_hosts=KNOWN_HOSTS_FILE,
            connect_timeout=8,
        ) as conn:
            res = await asyncio.wait_for(conn.run(command, check=False), timeout=timeout)
            return SSHResult(
                success=(res.exit_status == 0),
                stdout=res.stdout or "",
                stderr=res.stderr or "",
                exit_status=res.exit_status if res.exit_status is not None else 0,
            )
    except asyncssh.HostKeyNotVerifiable as e:
        err_msg = str(e)
        logging.error(f"Ошибка проверки ключа хоста {conf.get('host')}: {err_msg}")
        return SSHResult(
            success=False,
            stdout="",
            stderr="",
            exit_status=-1,
            error=(
                f"КРИТИЧЕСКАЯ ОШИБКА: Отпечаток хоста отсутствует в known_hosts или изменился "
                f"(возможен MITM или переустановка ОС): {err_msg}\n"
                f"Администратор может проверить и подтвердить новый отпечаток."
            ),
            host_key_mismatch=True,
        )
    except asyncssh.PermissionDenied as e:
        return SSHResult(
            success=False,
            stdout="",
            stderr="",
            exit_status=-1,
            error=f"Ошибка авторизации SSH (проверьте открытый ключ /key на сервере): {e}",
        )
    except asyncio.TimeoutError:
        return SSHResult(False, "", "", -1, "Превышен таймаут ответа сервера")
    except Exception as e:
        return SSHResult(False, "", "", -1, f"Ошибка подключения SSH: {e}")


async def send_server_alert(server_key: str, text: str, reply_markup=None):
    srv = SERVERS.get(server_key)
    recipients = set(ADMIN_IDS)

    for uid_str, udata in load_users().items():
        if udata.get("role") == "admin":
            recipients.add(int(uid_str))

    if srv:
        for owner in srv.get("owners", []):
            if is_allowed_user(owner):
                recipients.add(owner)

    for uid in recipients:
        try:
            await bot.send_message(uid, text, reply_markup=reply_markup)
        except Exception as e:
            logging.error(f"Не удалось доставить алерт {uid}: {e}")


# --- МОНИТОРИНГ ОБНОВЛЕНИЯ ОС ЧЕРЕЗ SYSTEMD-RUN ---


async def monitor_upgrade(srv_name: str, user_id: int):
    final_status = "unknown"
    exit_code = "-1"
    result_str = "unknown"

    try:
        await asyncio.sleep(5)
        for _ in range(180):  # До 30 минут опроса
            res = await run_ssh(
                srv_name,
                "systemctl show tgbot-upgrade -p ActiveState,SubState,ExecMainStatus,Result,LoadState",
                timeout=12,
            )
            if not res.success:
                await asyncio.sleep(10)
                continue

            props = {}
            for line in res.stdout.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    props[k.strip()] = v.strip()

            active_state = props.get("ActiveState", "")
            sub_state = props.get("SubState", "")
            exit_code = props.get("ExecMainStatus", "-1")
            result_str = props.get("Result", "")

            # Юнита нет (сервер перезагружался / запуск не состоялся) — это не «успех»
            if props.get("LoadState", "") == "not-found":
                final_status = "not-found"
                break

            if active_state == "activating" or (active_state == "active" and sub_state == "running"):
                await asyncio.sleep(10)
                continue

            if active_state in ("active", "failed", "inactive", "deactivating"):
                final_status = active_state
                break

            await asyncio.sleep(10)

        log_res = await run_ssh(
            srv_name,
            "sudo journalctl -u tgbot-upgrade -n 25 --no-pager 2>&1",
            timeout=15,
        )
        await run_ssh(
            srv_name,
            "sudo systemctl stop tgbot-upgrade 2>/dev/null; sudo systemctl reset-failed tgbot-upgrade 2>/dev/null",
            timeout=10,
        )

        is_ok = (exit_code == "0" and result_str == "success" and final_status not in ("failed", "not-found", "unknown"))
        if final_status == "not-found":
            header = (
                f"⚠️ <b>Статус обновления на {html.escape(srv_name)} неизвестен:</b> "
                f"юнит <code>tgbot-upgrade</code> не найден (сервер мог перезагрузиться). "
                f"Проверьте результат вручную."
            )
        elif is_ok:
            header = f"✅ <b>Обновление на сервере {html.escape(srv_name)} успешно завершено!</b>"
        else:
            header = (
                f"❌ <b>Обновление на сервере {html.escape(srv_name)} завершилось с ошибкой!</b>\n"
                f"Статус: <code>{html.escape(final_status)} / {html.escape(result_str)} (код {html.escape(exit_code)})</code>"
            )

        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🖥 В меню сервера", callback_data=f"srv:{srv_name}")]
        ])
        await bot.send_message(
            user_id,
            f"{header}\n\n<pre>{truncate_html(log_res.text(), 1800)}</pre>",
            reply_markup=kb,
        )
    except Exception as e:
        logging.error(f"Ошибка в monitor_upgrade для {srv_name}: {e}")
    finally:
        upgrade_locks.discard(srv_name)
        # Небольшой «хвост» тишины: сервер может ещё перезагружаться
        maintenance_until[srv_name] = time.time() + 120


# --- ФОНОВЫЙ МОНИТОРИНГ (WATCHER) ---


async def poll_single_server(srv_name: str, warm_up: bool, sem: asyncio.Semaphore):
    async with sem:
        if srv_name not in SERVERS:
            return

        srv_conf = SERVERS[srv_name]
        init_server_state(srv_name)
        state = server_states[srv_name]

        if time.time() < maintenance_until.get(srv_name, 0):
            return

        res = await run_ssh(srv_name, CHECK_ALL_COMMAND, timeout=12)

        if not res.success and (res.exit_status == -1 or not res.stdout.strip()):
            state["strikes"] += 1
            if state["strikes"] >= OFFLINE_STRIKES_LIMIT and state["online"]:
                state["online"] = False
                if not warm_up:
                    buttons = [[InlineKeyboardButton(text="🔄 Проверить", callback_data=f"srv:{srv_name}")]]
                    if res.host_key_mismatch:
                        buttons.append([InlineKeyboardButton(text="🔑 Проверить ключ хоста (Admin)", callback_data=f"sec:rekey:{srv_name}")])
                    btn = InlineKeyboardMarkup(inline_keyboard=buttons)
                    await send_server_alert(
                        srv_name,
                        f"🚨 <b>СБОЙ ХОСТА:</b>\n"
                        f"Сервер <b>{html.escape(srv_name)}</b> (<code>{html.escape(srv_conf['host'])}:{srv_conf['port']}</code>) "
                        f"не отвечает на запросы!\n<pre>{truncate_html(res.text())}</pre>",
                        reply_markup=btn,
                    )
            return

        state["strikes"] = 0
        if not state["online"]:
            state["online"] = True
            if not warm_up:
                btn = InlineKeyboardMarkup(inline_keyboard=[
                    [InlineKeyboardButton(text="🖥 В меню сервера", callback_data=f"srv:{srv_name}")]
                ])
                await send_server_alert(
                    srv_name,
                    f"✅ <b>СВЯЗЬ ВОССТАНОВЛЕНА:</b>\nСервер <b>{html.escape(srv_name)}</b> снова в сети.",
                    reply_markup=btn,
                )

        raw_out = res.stdout
        try:
            parts = raw_out.split("===SERVICES===")
            disk_str = parts[0].strip()
            rest = parts[1].split("===DOCKER===")
            services_str = rest[0].strip()
            docker_str = rest[1].strip() if len(rest) > 1 else ""

            if disk_str.isdigit():
                disk_val = int(disk_str)
                if disk_val >= DISK_THRESHOLD_PERCENT and not state["disk_critical"]:
                    state["disk_critical"] = True
                    if not warm_up:
                        await send_server_alert(
                            srv_name,
                            f"⚠️ <b>ДЕФИЦИТ МЕСТА:</b>\nНа сервере <b>{html.escape(srv_name)}</b> диск заполнен на <b>{disk_val}%</b>!",
                        )
                elif disk_val < (DISK_THRESHOLD_PERCENT - 5) and state["disk_critical"]:
                    state["disk_critical"] = False
                    if not warm_up:
                        await send_server_alert(
                            srv_name,
                            f"🟢 <b>МЕСТО ОСВОБОЖДЕНО:</b>\nНа сервере <b>{html.escape(srv_name)}</b> занятость диска: <b>{disk_val}%</b>.",
                        )

            current_failed_services = set()
            for line in services_str.split("\n"):
                line = line.strip()
                if line.startswith("sys|"):
                    _, name, status = line.split("|")
                    if status != "active":
                        current_failed_services.add(name)

            if not warm_up:
                for svc in (current_failed_services - state["failed_services"]):
                    btn = InlineKeyboardMarkup(inline_keyboard=[
                        [InlineKeyboardButton(text=f"📋 Статус {svc}", callback_data=f"st:{srv_name}:{svc}")]
                    ])
                    await send_server_alert(
                        srv_name,
                        f"⚠️ <b>ПАДЕНИЕ СЛУЖБЫ:</b>\nНа сервере <b>{html.escape(srv_name)}</b> служба <b>{html.escape(svc)}</b> перешла в inactive/failed!",
                        reply_markup=btn,
                    )
                for svc in (state["failed_services"] - current_failed_services):
                    await send_server_alert(
                        srv_name,
                        f"🟢 <b>СЛУЖБА ВОССТАНОВЛЕНА:</b>\nНа сервере <b>{html.escape(srv_name)}</b> служба <b>{html.escape(svc)}</b> снова active.",
                    )
            state["failed_services"] = current_failed_services

            if "dk_daemon|inactive" in docker_str:
                if not state.get("docker_down_alerted", False):
                    state["docker_down_alerted"] = True
                    if not warm_up:
                        await send_server_alert(srv_name, f"🚨 <b>DOCKER ДЕМОН УПАЛ</b> на сервере <b>{html.escape(srv_name)}</b>!")
            else:
                if state.get("docker_down_alerted", False):
                    state["docker_down_alerted"] = False
                    if not warm_up:
                        await send_server_alert(srv_name, f"🟢 <b>Docker демон восстановлен</b> на <b>{html.escape(srv_name)}</b>.")

                current_failed_dk = set()
                current_present_dk = set()
                dk_ids = {}
                for line in docker_str.split("\n"):
                    line = line.strip()
                    if line.startswith("dk|"):
                        p = line.split("|")
                        if len(p) >= 5:
                            _, c_full_id, c_name, c_state, c_exit = p[:5]
                            c_name = c_name.lstrip("/")
                            dk_ids[c_name] = c_full_id[:12]
                            c_state_low = c_state.lower()
                            current_present_dk.add(c_name)
                            # Игнорируем created и штатно остановленные с кодом 0
                            if c_state_low in ("running", "created"):
                                continue
                            if c_state_low == "exited" and c_exit.strip() == "0":
                                continue
                            current_failed_dk.add(c_name)

                if not warm_up:
                    for c_name in (current_failed_dk - state["failed_containers"]):
                        c_id = dk_ids.get(c_name)
                        restart_btn = None
                        if c_id:
                            restart_btn = InlineKeyboardMarkup(inline_keyboard=[
                                [InlineKeyboardButton(text="🔄 Перезапустить", callback_data=f"dk:quick_restart:{srv_name}:{c_id}")]
                            ])
                        await send_server_alert(
                            srv_name,
                            f"🛑 <b>КОНТЕЙНЕР АВАРИЙНО ОСТАНОВИЛСЯ:</b>\n"
                            f"На сервере <b>{html.escape(srv_name)}</b> контейнер <b>{html.escape(c_name)}</b> упал (exit != 0)!",
                            reply_markup=restart_btn,
                        )
                    for c_name in (state["failed_containers"] - current_failed_dk):
                        if c_name in current_present_dk:
                            await send_server_alert(
                                srv_name,
                                f"🟢 <b>КОНТЕЙНЕР ВОССТАНОВЛЕН:</b>\nНа сервере <b>{html.escape(srv_name)}</b> контейнер <b>{html.escape(c_name)}</b> снова в норме.",
                            )
                state["failed_containers"] = current_failed_dk
                state["known_containers"] = current_present_dk

        except Exception as parse_err:
            logging.error(f"Ошибка парсинга метрик {srv_name}: {parse_err}")


async def background_watcher():
    sem = asyncio.Semaphore(5)
    warm_up = True
    await asyncio.sleep(5)

    while True:
        try:
            server_keys = list(SERVERS.keys())
            if server_keys:
                tasks = [poll_single_server(srv, warm_up, sem) for srv in server_keys]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for srv, res in zip(server_keys, results):
                    if isinstance(res, Exception):
                        logging.error(f"Ошибка в таске мониторинга сервера {srv}: {res}", exc_info=res)
            warm_up = False
        except Exception as e:
            logging.exception(f"Критическая ошибка цикла watcher: {e}")
        await asyncio.sleep(WATCHER_INTERVAL)


# --- КЛАВИАТУРЫ ---


def get_folders_keyboard(user_id: int):
    builder = InlineKeyboardBuilder()
    admin_mode = is_admin(user_id)

    creators_with_servers = {srv.get("creator_id") for srv in SERVERS.values() if srv.get("creator_id")}

    if admin_mode:
        all_users = load_users()
        all_ids = set(int(uid) for uid in all_users.keys()).union(ADMIN_IDS).union(creators_with_servers)
        for uid in sorted(list(all_ids)):
            u_name = get_user_display_name(uid)
            count = sum(1 for s in SERVERS.values() if s.get("creator_id") == uid)
            builder.button(text=f"📁 {uid} ({u_name}) [{count}]", callback_data=f"fld:{uid}")
    else:
        count = sum(1 for s in SERVERS.values() if s.get("creator_id") == user_id)
        builder.button(text=f"📁 Мои серверы [{count}]", callback_data=f"fld:{user_id}")

    builder.adjust(1)
    action_buttons = [
        InlineKeyboardButton(text="➕ Добавить сервер", callback_data="wizard:start"),
        InlineKeyboardButton(text="🔑 Мой SSH-ключ", callback_data="show_my_key"),
    ]
    if admin_mode:
        action_buttons.append(InlineKeyboardButton(text="👥 Пользователи", callback_data="u_man:list"))
        action_buttons.append(InlineKeyboardButton(text="⚙️ Рестарт бота", callback_data="bot:restart_confirm"))

    builder.row(*action_buttons)
    return builder.as_markup()


def get_servers_in_folder_keyboard(folder_uid: int, user_id: int):
    builder = InlineKeyboardBuilder()
    folder_servers = []

    for srv_name, srv_conf in SERVERS.items():
        if srv_conf.get("creator_id") == folder_uid:
            folder_servers.append(srv_name)
            builder.button(text=f"🖥 {srv_name}", callback_data=f"srv:{srv_name}")

    builder.adjust(2)

    builder.row(
        InlineKeyboardButton(text="➕ Добавить сервер", callback_data="wizard:start")
    )

    if (is_admin(user_id) or user_id == folder_uid) and folder_servers:
        builder.row(
            InlineKeyboardButton(text="🗑 Удалить сервер", callback_data=f"fld_del_menu:{folder_uid}")
        )

    builder.row(
        InlineKeyboardButton(text="⬅️ Назад к папкам", callback_data="folders_root")
    )
    return builder.as_markup()


def build_server_dashboard(server_key: str, sys_services: list, containers: list, user_id: int):
    srv_data = SERVERS.get(server_key, {})
    creator = srv_data.get("creator_id", 0)
    admin_mode = is_admin(user_id)

    lines = [
        f"🖥 Сервер: <b>{html.escape(server_key)}</b>",
        f"📁 Владелец: <code>{creator}</code> ({html.escape(get_user_display_name(creator))})\n",
        "┌ <b>Состояние сервисов:</b>",
    ]
    for name, state in sys_services:
        icon = "🟢" if state == "active" else "🔴"
        lines.append(f"│ {icon} <b>{html.escape(name)}:</b> {state}")

    if containers:
        lines.append("│\n│ 🐳 <b>Docker контейнеры:</b>")
        for _, c_name, c_state in containers:
            icon = "🟢" if c_state == "running" else "🔴"
            lines.append(f"│ {icon} <code>{html.escape(c_name)}</code> ({c_state})")
    lines.append("└──────────────────────────")
    lines.append("\n<i>Нажмите на плашку для вывода логов и статуса:</i>")

    text = "\n".join(lines)
    builder = InlineKeyboardBuilder()

    for name, state in sys_services:
        icon = "🟢" if state == "active" else "🔴"
        builder.button(text=f"{icon} {name}", callback_data=f"st:{server_key}:{name}")
    builder.adjust(2)

    if containers:
        dk_builder = InlineKeyboardBuilder()
        for cid_short, c_name, c_state in containers:
            icon = "🟢" if c_state == "running" else "🔴"
            dk_builder.button(text=f"{icon} {c_name}", callback_data=f"st:{server_key}:{cid_short}")
        dk_builder.adjust(2)
        builder.attach(dk_builder)

    builder.row(
        InlineKeyboardButton(text="📊 Ресурсы (CPU/RAM)", callback_data=f"act:stats:{server_key}"),
        InlineKeyboardButton(text="🌐 Сеть и Трафик", callback_data=f"net:menu:{server_key}"),
    )
    builder.row(
        InlineKeyboardButton(text="🛡 Безопасность и Сеть", callback_data=f"sec:menu:{server_key}"),
        InlineKeyboardButton(text="🐳 Управление Docker", callback_data=f"dk:list:{server_key}"),
    )

    if admin_mode:
        builder.row(
            InlineKeyboardButton(text="🚀 Обновление ОС", callback_data=f"act:upgrade_ask:{server_key}"),
            InlineKeyboardButton(text="🔄 Перезагрузить", callback_data=f"act:reboot_confirm:{server_key}"),
        )

    bottom_row = []
    if can_delete_server(user_id, server_key):
        bottom_row.append(InlineKeyboardButton(text="🗑 Удалить сервер", callback_data=f"srv_del_ask:{server_key}"))
    bottom_row.append(InlineKeyboardButton(text="⬅️ К папке", callback_data=f"fld:{creator}"))
    builder.row(*bottom_row)

    return text, builder.as_markup()


def get_security_menu_keyboard(server_key: str, user_id: int):
    buttons = []
    if is_admin(user_id):
        buttons.append([
            InlineKeyboardButton(text="🔑 Вкл Root (2 мин)", callback_data=f"sec:root:{server_key}"),
            InlineKeyboardButton(text="🔒 Выкл Root", callback_data=f"sec:unroot:{server_key}"),
        ])
        buttons.append([
            InlineKeyboardButton(text="🔄 Проверить/обновить ключ SSH", callback_data=f"sec:rekey:{server_key}"),
        ])

    buttons.extend([
        [
            InlineKeyboardButton(text="🧱 Правила UFW", callback_data=f"sec:ufw:{server_key}"),
            InlineKeyboardButton(text="🔌 Порты (TCP/UDP)", callback_data=f"sec:ports:{server_key}"),
        ],
        [
            InlineKeyboardButton(text="🚫 Fail2ban", callback_data=f"sec:f2b:{server_key}"),
            InlineKeyboardButton(text="📜 SSL-сертификаты", callback_data=f"sec:ssl:{server_key}"),
        ],
        [InlineKeyboardButton(text="⬅️ Меню сервера", callback_data=f"srv:{server_key}")],
    ])
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def get_docker_containers_keyboard(server_key: str, raw_output: str):
    builder = InlineKeyboardBuilder()
    for line in raw_output.strip().split("\n"):
        if not line or "|" not in line:
            continue
        try:
            cid_short, name, state = line.split("|")[:3]
            status_icon = "🟢" if state.strip() == "running" else "🔴"
            builder.button(
                text=f"{status_icon} {name}",
                callback_data=f"dk:v:{server_key}:{cid_short[:12]}",
            )
        except ValueError:
            continue
    builder.adjust(2)
    builder.row(
        InlineKeyboardButton(text="🔄 Обновить", callback_data=f"dk:list:{server_key}"),
        InlineKeyboardButton(text="⬅️ Меню сервера", callback_data=f"srv:{server_key}"),
    )
    return builder.as_markup()


def get_container_action_keyboard(server_key: str, cid_short: str, status: str = "running"):
    buttons = []
    if status in VALID_DOCKER_STATUSES:
        if status != "running":
            buttons.append([
                InlineKeyboardButton(text="▶️ Запустить", callback_data=f"dk:str:{server_key}:{cid_short}"),
                InlineKeyboardButton(text="🔄 Перезапустить", callback_data=f"dk:rst:{server_key}:{cid_short}"),
            ])
        else:
            buttons.append([
                InlineKeyboardButton(text="🔄 Перезапустить", callback_data=f"dk:rst:{server_key}:{cid_short}"),
                InlineKeyboardButton(text="⏹️ Остановить", callback_data=f"dk:stp:{server_key}:{cid_short}"),
            ])
        buttons.append([
            InlineKeyboardButton(text="📜 Логи (30 строк)", callback_data=f"dk:log:{server_key}:{cid_short}"),
        ])
    buttons.append([
        InlineKeyboardButton(text="⬅️ К списку контейнеров", callback_data=f"dk:list:{server_key}"),
    ])
    return InlineKeyboardMarkup(inline_keyboard=buttons)


# --- ГЛОБАЛЬНЫЙ ОБРАБОТЧИК ОШИБОК ДИСПЕТЧЕРА ---


@dp.errors()
async def global_error_handler(event: types.ErrorEvent):
    logging.exception(f"Необработанное исключение: {event.exception}")
    if event.update.callback_query:
        try:
            await event.update.callback_query.answer("⚠️ Внутренняя ошибка", show_alert=True)
        except Exception:
            pass


# --- ХЭНДЛЕРЫ КОМАНД ---


@dp.message(Command("start", "servers"))
async def cmd_start(message: types.Message, state: FSMContext):
    await state.clear()
    if not is_allowed_user(message.from_user.id):
        await message.answer(
            f"⛔ <b>Доступ ограничен</b>\n\n"
            f"Ваш Telegram ID: <code>{message.from_user.id}</code>\n"
            f"Передайте этот ID администратору для получения доступа."
        )
        return
    await message.answer(
        "📂 <b>Серверы по папкам владельцев:</b>\nВыберите нужную папку:",
        reply_markup=get_folders_keyboard(message.from_user.id),
    )


@dp.message(Command("key", "my_key"))
async def cmd_my_key(message: types.Message, state: FSMContext):
    await state.clear()
    if not is_allowed_user(message.from_user.id):
        return
    _, pub_key = await ensure_user_ssh_keys(message.from_user.id)
    await message.answer(
        f"🔑 <b>Ваш персональный SSH-ключ:</b>\n\n"
        f"<code>{html.escape(pub_key)}</code>\n\n"
        f"<i>Добавьте эту строку на ваш сервер в файл <code>~/.ssh/authorized_keys</code> пользователя <code>botadmin</code>.</i>"
    )


@dp.message(Command("cancel"))
async def cmd_cancel(message: types.Message, state: FSMContext):
    await state.clear()
    if not is_allowed_user(message.from_user.id):
        return
    await message.answer("❌ Текущее действие отменено.", reply_markup=get_folders_keyboard(message.from_user.id))


@dp.message(Command("restart_bot"), lambda msg: is_admin(msg.from_user.id))
async def cmd_restart_bot(message: types.Message, state: FSMContext):
    await state.clear()
    confirm_kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="⚠️ ДА, перезагрузить бота", callback_data="bot:do_restart")],
        [InlineKeyboardButton(text="❌ Отмена", callback_data="folders_root")],
    ])
    await message.answer("Перезагрузить процесс Telegram-бота?", reply_markup=confirm_kb)


@dp.message(Command("cmd"))
async def cmd_exec(message: types.Message, state: FSMContext):
    await state.clear()
    if not is_admin(message.from_user.id):
        await message.answer("⛔ Команда /cmd доступна исключительно администраторам бота.")
        return

    parts = message.text.split(maxsplit=2)
    if len(parts) < 3:
        await message.answer("<b>Использование:</b> <code>/cmd &lt;сервер&gt; &lt;команда&gt;</code>")
        return

    srv_name, command = parts[1], parts[2]
    if not is_valid_existing_server(srv_name):
        await message.answer(f"❌ Сервер <code>{html.escape(srv_name)}</code> не найден!")
        return

    log_audit(message.from_user.id, srv_name, "CMD_EXEC", command)
    status_msg = await message.answer(f"⏳ Выполняю на <b>{html.escape(srv_name)}</b>...")
    res = await run_ssh(srv_name, command, timeout=60)
    await status_msg.edit_text(f"🖥 <b>{html.escape(srv_name)}</b>:\n<pre>{truncate_html(res.text())}</pre>")


# --- FSM МАСТЕР: ДОБАВЛЕНИЕ СЕРВЕРА С ДВУХЭТАПНЫМ TOFU ---


@dp.callback_query(F.data == "show_my_key")
async def callback_show_my_key(call: types.CallbackQuery, state: FSMContext):
    await state.clear()
    if not is_allowed_user(call.from_user.id):
        await call.answer("⛔ Доступ запрещен.", show_alert=True)
        return
    _, pub_key = await ensure_user_ssh_keys(call.from_user.id)
    await bot.send_message(
        call.from_user.id,
        f"🔑 <b>Ваш персональный SSH-ключ:</b>\n\n"
        f"<code>{html.escape(pub_key)}</code>\n\n"
        f"<i>Добавьте эту строку на ваш сервер в <code>~/.ssh/authorized_keys</code> пользователя <code>botadmin</code>.</i>"
    )
    await call.answer()


@dp.callback_query(F.data == "wizard:cancel")
async def wizard_cancel(call: types.CallbackQuery, state: FSMContext):
    await state.clear()
    if not is_allowed_user(call.from_user.id):
        await call.answer("⛔ Доступ запрещен.", show_alert=True)
        return
    if isinstance(call.message, types.Message):
        await safe_edit_text(call.message, "❌ Действие отменено.", reply_markup=get_folders_keyboard(call.from_user.id))
    await call.answer()


@dp.callback_query(F.data == "wizard:start")
async def wizard_step_name(call: types.CallbackQuery, state: FSMContext):
    user_id = call.from_user.id
    if not is_allowed_user(user_id):
        await call.answer("Доступ запрещен.", show_alert=True)
        return

    if not is_admin(user_id):
        user_srv_count = sum(1 for s in SERVERS.values() if s.get("creator_id") == user_id)
        if user_srv_count >= MAX_SERVERS_PER_USER:
            await call.answer(f"⚠️ Достигнут лимит серверов ({MAX_SERVERS_PER_USER} шт.).", show_alert=True)
            return

    await state.set_state(AddServerWizard.waiting_for_name)
    cancel_kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="❌ Отмена", callback_data="wizard:cancel")]
    ])
    if isinstance(call.message, types.Message):
        await safe_edit_text(
            call.message,
            "<b>Шаг 1/3:</b> Введите имя сервера (латиница, цифры, дефис, 2-24 символа):",
            reply_markup=cancel_kb,
        )
    await call.answer()


@dp.message(AddServerWizard.waiting_for_name, F.text, ~F.text.startswith("/"))
async def wizard_step_host(message: types.Message, state: FSMContext):
    if not is_allowed_user(message.from_user.id):
        await state.clear()
        return

    name = message.text.strip().replace(" ", "-")
    if not RE_SERVER_NAME.match(name):
        await message.answer("⚠️ Недопустимое имя! Используйте только латиницу, цифры, дефис или подчеркивание (2-24 символа):")
        return

    if name in SERVERS:
        await message.answer(f"⚠️ Сервер с именем <code>{html.escape(name)}</code> уже существует! Введите другое:")
        return

    await state.update_data(srv_name=name)
    await state.set_state(AddServerWizard.waiting_for_host)
    cancel_kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="❌ Отмена", callback_data="wizard:cancel")]
    ])
    await message.answer(
        f"Имя принято: <b>{html.escape(name)}</b>\n\n<b>Шаг 2/3:</b> Отправьте публичный IP-адрес или домен сервера:",
        reply_markup=cancel_kb,
    )


@dp.message(AddServerWizard.waiting_for_host, F.text, ~F.text.startswith("/"))
async def wizard_step_options(message: types.Message, state: FSMContext):
    user_id = message.from_user.id
    if not is_allowed_user(user_id):
        await state.clear()
        return

    host = message.text.strip()
    ok, err_reason = await validate_target_host(host, is_admin(user_id))
    if not ok:
        await message.answer(f"⚠️ <b>Адрес отклонен:</b> {html.escape(err_reason)}\nВведите корректный публичный адрес:")
        return

    await state.update_data(srv_host=host)
    options_kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🚀 Порт 59856 (botadmin)", callback_data="wz_set:59856:botadmin")],
        [InlineKeyboardButton(text="🚀 Порт 22 (botadmin)", callback_data="wz_set:22:botadmin")],
        [InlineKeyboardButton(text="✏️ Задать порт / user вручную", callback_data="wz_set:custom")],
        [InlineKeyboardButton(text="❌ Отмена", callback_data="wizard:cancel")],
    ])
    data = await state.get_data()
    await message.answer(
        f"Сервер: <b>{html.escape(data.get('srv_name', ''))}</b> (<code>{html.escape(host)}</code>)\n\n"
        f"<b>Шаг 3/3:</b> Выберите параметры подключения:",
        reply_markup=options_kb,
    )


async def probe_server_for_tofu(
    target_msg: types.Message,
    state: FSMContext,
    port: int,
    user: str,
    creator_id: int,
):
    """Шаг 1 TOFU: транспортный опрос открытого ключа хоста без выполнения команд."""
    data = await state.get_data()
    srv_name = data.get("srv_name")
    srv_host = data.get("srv_host")
    if not srv_name or not srv_host:
        await state.clear()
        await safe_edit_text(target_msg, "⚠️ Сессия добавления устарела. Начните заново.", reply_markup=get_folders_keyboard(creator_id))
        return

    if not is_admin(creator_id) and not allow_probe(creator_id):
        await state.clear()
        await safe_edit_text(
            target_msg,
            "⚠️ Слишком много попыток подключения. Повторите через несколько минут.",
            reply_markup=get_folders_keyboard(creator_id),
        )
        return

    await safe_edit_text(target_msg, "⏳ Запрашиваю открытый ключ хоста (без авторизации)...")

    ok, key_info, err = await fetch_unverified_host_key(srv_host, port)
    if not ok:
        retry_kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🔄 Попробовать снова", callback_data="wizard:start")],
            [InlineKeyboardButton(text="❌ Отмена", callback_data="wizard:cancel")],
        ])
        err_display = err if is_admin(creator_id) else "Не удалось получить ключ хоста (проверьте IP и SSH-порт)."
        await safe_edit_text(
            target_msg,
            f"❌ <b>Не удалось связаться с SSH-сервером!</b>\n\n<pre>{truncate_html(err_display)}</pre>",
            reply_markup=retry_kb,
        )
        return

    await state.update_data(
        srv_port=port,
        srv_user=user,
        tofu_key_str=key_info["key_str"],
        tofu_fp=key_info["fp"],
    )
    await state.set_state(AddServerWizard.waiting_for_tofu_confirm)

    confirm_kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✅ Доверять и проверить вход", callback_data="wz_tofu:accept")],
        [InlineKeyboardButton(text="❌ Отмена", callback_data="wizard:cancel")],
    ])
    await safe_edit_text(
        target_msg,
        "🔐 <b>Подтверждение ключа хоста (TOFU):</b>\n\n"
        f"• Сервер: <b>{html.escape(srv_name)}</b> (<code>{html.escape(srv_host)}:{port}</code>)\n"
        f"• Алгоритм: <code>{html.escape(key_info['alg'])}</code>\n"
        f"• Отпечаток: <code>{html.escape(key_info['fp'])}</code>\n\n"
        "<i>Сверьте отпечаток с выводом <code>ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub</code> на сервере.\n"
        "Вход по ключу будет выполнен только после подтверждения.</i>",
        reply_markup=confirm_kb,
    )


@dp.callback_query(AddServerWizard.waiting_for_tofu_confirm, F.data == "wz_tofu:accept")
async def wizard_tofu_accept(call: types.CallbackQuery, state: FSMContext):
    """Шаг 2 TOFU: проверка входа по подтвержденному ключу и фиксация сервера."""
    creator_id = call.from_user.id
    data = await state.get_data()
    srv_name = data.get("srv_name")
    srv_host = data.get("srv_host")
    port = int(data.get("srv_port", 22))
    user = data.get("srv_user", "botadmin")
    key_str = data.get("tofu_key_str", "")
    fp = data.get("tofu_fp", "")

    if not srv_name or not srv_host or not key_str:
        await state.clear()
        await call.answer("Данные сессии устарели.", show_alert=True)
        return

    if not is_allowed_user(creator_id):
        await state.clear()
        await call.answer("⛔ Доступ запрещен.", show_alert=True)
        return
    if srv_name in SERVERS:
        await state.clear()
        await call.answer("Сервер с таким именем уже существует. Начните заново.", show_alert=True)
        return
    if not is_admin(creator_id):
        if sum(1 for s in SERVERS.values() if s.get("creator_id") == creator_id) >= MAX_SERVERS_PER_USER:
            await state.clear()
            await call.answer(f"⚠️ Достигнут лимит серверов ({MAX_SERVERS_PER_USER} шт.).", show_alert=True)
            return
    # Повторная проверка адреса перед входом (смягчает подмену DNS-ответа между шагами)
    host_ok, host_err = await validate_target_host(srv_host, is_admin(creator_id))
    if not host_ok:
        await state.clear()
        await call.answer(f"Адрес отклонен: {host_err}", show_alert=True)
        return

    try:
        parsed_key = asyncssh.import_public_key(key_str)
        if parsed_key.get_fingerprint("sha256") != fp:
            await state.clear()
            await call.answer("Ошибка целостности отпечатка!", show_alert=True)
            return
    except Exception:
        await state.clear()
        await call.answer("Некорректный формат ключа!", show_alert=True)
        return

    await call.answer()
    if isinstance(call.message, types.Message):
        await safe_edit_text(call.message, "⏳ Отпечаток принят. Проверяю авторизацию по вашему SSH-ключу...")

    user_key_path, _ = await ensure_user_ssh_keys(creator_id)
    kh_entry = format_known_hosts_entry(srv_host, port, key_str)
    pinned_kh = asyncssh.import_known_hosts(kh_entry)

    try:
        async with asyncssh.connect(
            srv_host,
            port=port,
            username=user,
            client_keys=[user_key_path],
            known_hosts=pinned_kh,
            connect_timeout=8,
        ) as conn:
            res = await asyncio.wait_for(conn.run("whoami", check=False), timeout=10)
            output = (res.stdout or "").strip()
    except Exception as e:
        await state.clear()
        retry_kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🔄 Попробовать снова", callback_data="wizard:start")],
            [InlineKeyboardButton(text="❌ Отмена", callback_data="wizard:cancel")],
        ])
        err_display = str(e) if is_admin(creator_id) else "Авторизация не удалась (проверьте ключ /key в authorized_keys)."
        if isinstance(call.message, types.Message):
            await safe_edit_text(
                call.message,
                "❌ <b>Ошибка SSH-авторизации!</b> Сервер не добавлен.\n\n"
                f"<pre>{truncate_html(err_display)}</pre>\n"
                f"<i>Убедитесь, что ваш персональный ключ (/key) добавлен в <code>~/.ssh/authorized_keys</code> пользователя <code>{html.escape(user)}</code>.</i>",
                reply_markup=retry_kb,
            )
        return

    if output != user:
        await state.clear()
        retry_kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🔄 Попробовать снова", callback_data="wizard:start")],
            [InlineKeyboardButton(text="❌ Отмена", callback_data="wizard:cancel")],
        ])
        if isinstance(call.message, types.Message):
            await safe_edit_text(
                call.message,
                "❌ <b>Ошибка валидации пользователя!</b>\n"
                f"Ожидался: <code>{html.escape(user)}</code>, получен: <code>{html.escape(output)}</code>",
                reply_markup=retry_kb,
            )
        return

    if srv_name in SERVERS:  # имя могли занять, пока шла проверка входа
        await state.clear()
        if isinstance(call.message, types.Message):
            await safe_edit_text(call.message, "⚠️ Сервер с таким именем уже добавлен. Начните заново.", reply_markup=get_folders_keyboard(creator_id))
        return

    record_host_key(srv_host, port, key_str)

    owners_list = list(set(ADMIN_IDS + [creator_id]))
    SERVERS[srv_name] = {
        "host": srv_host,
        "port": port,
        "user": user,
        "creator_id": creator_id,
        "owners": owners_list,
    }
    save_servers(SERVERS)
    init_server_state(srv_name)
    log_audit(creator_id, srv_name, "SERVER_ADDED", f"{srv_host}:{port} ({user}) FP:{fp}")
    await state.clear()

    if isinstance(call.message, types.Message):
        await safe_edit_text(
            call.message,
            "✅ <b>Сервер успешно проверен и добавлен!</b>\n\n"
            f"• Имя: <b>{html.escape(srv_name)}</b>\n"
            f"• Хост: <code>{html.escape(srv_host)}:{port}</code>\n"
            f"• Отпечаток: <code>{html.escape(fp)}</code>\n"
            f"• Папка владельца: <code>{creator_id}</code>",
            reply_markup=get_folders_keyboard(creator_id),
        )


@dp.callback_query(F.data.startswith("wz_set:"))
async def wizard_preset_choice(call: types.CallbackQuery, state: FSMContext):
    if not is_allowed_user(call.from_user.id):
        await call.answer("Доступ запрещен.", show_alert=True)
        return

    choice = call.data.split(":", 1)[1]
    if choice == "custom":
        await state.set_state(AddServerWizard.waiting_for_custom_port)
        cancel_kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="❌ Отмена", callback_data="wizard:cancel")]
        ])
        if isinstance(call.message, types.Message):
            await safe_edit_text(call.message, "Введите номер SSH-порта (1–65535):", reply_markup=cancel_kb)
        await call.answer()
        return

    port_str, user = choice.split(":")
    await call.answer()
    if isinstance(call.message, types.Message):
        await probe_server_for_tofu(call.message, state, int(port_str), user, call.from_user.id)


@dp.message(AddServerWizard.waiting_for_custom_port, F.text, ~F.text.startswith("/"))
async def wizard_custom_port(message: types.Message, state: FSMContext):
    port_text = message.text.strip()
    if not port_text.isdigit() or not (1 <= int(port_text) <= 65535):
        await message.answer("⚠️ Введите корректный порт от 1 до 65535:")
        return

    await state.update_data(srv_port=int(port_text))
    await state.set_state(AddServerWizard.waiting_for_custom_user)
    await message.answer("Введите имя SSH-пользователя (например, <code>botadmin</code>):")


@dp.message(AddServerWizard.waiting_for_custom_user, F.text, ~F.text.startswith("/"))
async def wizard_custom_user(message: types.Message, state: FSMContext):
    user = message.text.strip()
    if not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", user):
        await message.answer("⚠️ Недопустимое имя пользователя Linux. Введите снова:")
        return

    data = await state.get_data()
    port = data.get("srv_port")
    if not port:
        await state.clear()
        await message.answer("⚠️ Сессия добавления устарела. Начните заново с команды /servers.")
        return
    status_msg = await message.answer("⏳ Запрашиваю ключ хоста...")
    await probe_server_for_tofu(status_msg, state, port, user, message.from_user.id)


# --- FSM МАСТЕР: УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ ---


async def show_users_list(target_msg: types.Message) -> bool:
    users = load_users()
    builder = InlineKeyboardBuilder()

    text_lines = ["👥 <b>Управление пользователями:</b>\n\n<i>Главные администраторы:</i>"]
    for aid in ADMIN_IDS:
        text_lines.append(f"• <code>{aid}</code> (SuperAdmin)")

    text_lines.append("\n<i>Добавленные пользователи:</i>")
    if not users:
        text_lines.append("Нет добавленных пользователей.")
    else:
        for uid_str, u_data in users.items():
            name = u_data.get("name", "Без имени")
            role = u_data.get("role", "user")
            text_lines.append(f"• <code>{uid_str}</code> — <b>{html.escape(name)}</b> ({role})")
            builder.button(text=f"❌ Удалить {name}", callback_data=f"u_del:{uid_str}")

    builder.adjust(1)
    builder.row(
        InlineKeyboardButton(text="➕ Добавить пользователя", callback_data="u_add:start"),
        InlineKeyboardButton(text="⬅️ Назад к папкам", callback_data="folders_root"),
    )
    return await safe_edit_text(target_msg, "\n".join(text_lines), reply_markup=builder.as_markup())


@dp.callback_query(F.data == "u_man:list")
async def user_management_list(call: types.CallbackQuery, state: FSMContext):
    await state.clear()
    if not is_admin(call.from_user.id):
        await call.answer("Доступ разрешен только администраторам.", show_alert=True)
        return
    if isinstance(call.message, types.Message):
        await show_users_list(call.message)
    await call.answer()


@dp.callback_query(F.data == "u_add:start")
async def user_add_start(call: types.CallbackQuery, state: FSMContext):
    if not is_admin(call.from_user.id):
        await call.answer("Доступ запрещен.", show_alert=True)
        return
    await state.set_state(AddUserWizard.waiting_for_id)
    cancel_kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="❌ Отмена", callback_data="u_man:list")]
    ])
    if isinstance(call.message, types.Message):
        await safe_edit_text(call.message, "<b>Шаг 1/2:</b> Введите числовой Telegram ID пользователя:", reply_markup=cancel_kb)
    await call.answer()


@dp.message(AddUserWizard.waiting_for_id, F.text, ~F.text.startswith("/"))
async def user_add_id(message: types.Message, state: FSMContext):
    if not is_admin(message.from_user.id):
        return
    uid_text = message.text.strip()
    if not uid_text.isdigit():
        await message.answer("Telegram ID должен состоять только из цифр:")
        return

    await state.update_data(target_uid=uid_text)
    await state.set_state(AddUserWizard.waiting_for_name)
    cancel_kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="❌ Отмена", callback_data="u_man:list")]
    ])
    await message.answer(
        f"ID: <code>{uid_text}</code> принят.\n\n<b>Шаг 2/2:</b> Введите имя или заметку для пользователя:",
        reply_markup=cancel_kb,
    )


@dp.message(AddUserWizard.waiting_for_name, F.text, ~F.text.startswith("/"))
async def user_add_name(message: types.Message, state: FSMContext):
    if not is_admin(message.from_user.id):
        return
    name_text = message.text.strip()
    data = await state.get_data()
    uid_str = data.get("target_uid")
    if not uid_str:
        await state.clear()
        await message.answer("⚠️ Сессия устарела. Начните добавление пользователя заново.")
        return

    users = load_users()
    users[uid_str] = {"role": "user", "name": name_text}
    save_users(users)

    await ensure_user_ssh_keys(int(uid_str))
    log_audit(message.from_user.id, "GLOBAL", "USER_ADDED", f"UID:{uid_str} ({name_text})")
    await state.clear()

    await message.answer(
        f"✅ Пользователь <b>{html.escape(name_text)}</b> (ID: <code>{uid_str}</code>) успешно добавлен!\nПерсональный SSH-ключ сгенерирован.",
        reply_markup=get_folders_keyboard(message.from_user.id),
    )


@dp.callback_query(F.data.startswith("u_del:"))
async def user_delete(call: types.CallbackQuery, state: FSMContext):
    await state.clear()
    if not is_admin(call.from_user.id):
        await call.answer("Доступ запрещен.", show_alert=True)
        return
    uid_str = call.data.split(":")[1]
    users = load_users()
    if uid_str in users:
        del users[uid_str]
        save_users(users)
        log_audit(call.from_user.id, "GLOBAL", "USER_DELETED", f"UID:{uid_str}")
        msg_ans = "Пользователь удален."
    else:
        msg_ans = "Пользователь уже удален."

    if isinstance(call.message, types.Message):
        await show_users_list(call.message)
    await call.answer(msg_ans)


# --- ОБРАБОТЧИКИ ДИАГНОСТИКИ И УПРАВЛЕНИЯ ---


async def show_f2b_menu(message: types.Message, srv_name: str) -> bool:
    cmd = r"""
if ! command -v fail2ban-client >/dev/null 2>&1; then echo "NO_F2B"; exit 0; fi
JAILS=$(sudo fail2ban-client status 2>/dev/null | grep "Jail list:" | sed "s/.*Jail list://;s/,//g")
echo "===STATUS==="
for j in $JAILS; do
    echo "--- $j ---"
    sudo fail2ban-client status "$j" | grep -E "(Currently banned|Banned IP list)"
done
"""
    res = await run_ssh(srv_name, cmd, timeout=15)
    out = res.text()

    if "NO_F2B" in out:
        kb = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="⬅️ Назад", callback_data=f"sec:menu:{srv_name}")]])
        return await safe_edit_text(message, f"Утилита <code>fail2ban</code> не установлена на <b>{html.escape(srv_name)}</b>.", reply_markup=kb)

    banned_ips = set(re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", res.stdout))
    builder = InlineKeyboardBuilder()
    for ip in sorted(list(banned_ips))[:6]:
        builder.button(text=f"🔓 Разбанить {ip}", callback_data=f"f2b:u:{srv_name}:{ip}")
    builder.adjust(1)
    builder.row(
        InlineKeyboardButton(text="🔄 Обновить", callback_data=f"sec:f2b:{srv_name}"),
        InlineKeyboardButton(text="⬅️ Назад", callback_data=f"sec:menu:{srv_name}"),
    )
    safe_out = truncate_html(out.replace("===STATUS===", ""))
    return await safe_edit_text(message, f"🚫 <b>Fail2ban</b> (<code>{html.escape(srv_name)}</code>):\n\n<pre>{safe_out}</pre>", reply_markup=builder.as_markup())


@dp.callback_query()
async def handle_callbacks(call: types.CallbackQuery, state: FSMContext):
    # Сбрасываем незавершенные шаги FSM при клике на меню
    await state.clear()

    data = call.data or ""
    user_id = call.from_user.id

    if not is_allowed_user(user_id):
        await call.answer("Доступ заблокирован администратором.", show_alert=True)
        return

    msg = call.message
    if not isinstance(msg, types.Message):
        await call.answer()
        return

    if data == "folders_root":
        changed = await safe_edit_text(msg, "📂 <b>Серверы по папкам владельцев:</b>\nВыберите нужную папку:", reply_markup=get_folders_keyboard(user_id))
        await call.answer(None if changed else "Состояние не изменилось")
        return

    if data.startswith("fld:"):
        folder_uid = int(data.split(":", 1)[1])
        if not is_admin(user_id) and folder_uid != user_id:
            await call.answer("⛔ Доступ к чужой папке запрещен!", show_alert=True)
            return

        u_name = get_user_display_name(folder_uid)
        kb = get_servers_in_folder_keyboard(folder_uid, user_id)
        changed = await safe_edit_text(
            msg,
            f"📁 <b>Папка:</b> <code>{folder_uid}</code> ({html.escape(u_name)})\n\nВыберите сервер:",
            reply_markup=kb,
        )
        await call.answer(None if changed else "Состояние не изменилось")
        return

    if data == "bot:restart_confirm":
        if not is_admin(user_id):
            await call.answer("Только для SuperAdmin.", show_alert=True)
            return
        confirm_kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="⚠️ ДА, перезагрузить бота", callback_data="bot:do_restart")],
            [InlineKeyboardButton(text="❌ Отмена", callback_data="folders_root")],
        ])
        await safe_edit_text(msg, "Перезапустить процесс Telegram-бота?", reply_markup=confirm_kb)
        await call.answer()
        return

    elif data == "bot:do_restart":
        if not is_admin(user_id):
            await call.answer("Доступ запрещен.", show_alert=True)
            return
        log_audit(user_id, "LOCAL", "BOT_RESTART")
        await safe_edit_text(msg, "⏳ Бот перезапускается...")
        await call.answer()
        await asyncio.sleep(1)
        os._exit(1)

    # Меню дашборда сервера
    if data.startswith("srv:"):
        srv_name = data.split(":", 1)[1]
        if not is_valid_existing_server(srv_name) or not has_server_access(user_id, srv_name):
            await call.answer("⛔ Сервер не найден или доступ запрещен!", show_alert=True)
            return

        await safe_edit_text(msg, f"⏳ Опрос <b>{html.escape(srv_name)}</b>...")
        res = await run_ssh(srv_name, CHECK_ALL_COMMAND, timeout=12)

        if not res.success and "===SERVICES===" not in res.stdout:
            creator = SERVERS.get(srv_name, {}).get("creator_id", user_id)
            buttons = [
                [InlineKeyboardButton(text="🔄 Повторить", callback_data=f"srv:{srv_name}")],
                [InlineKeyboardButton(text="⬅️ К папке", callback_data=f"fld:{creator}")],
            ]
            if res.host_key_mismatch and is_admin(user_id):
                buttons.insert(1, [InlineKeyboardButton(text="🔑 Проверить ключ хоста", callback_data=f"sec:rekey:{srv_name}")])
            await safe_edit_text(
                msg,
                f"⚠️ <b>Ошибка связи с сервером {html.escape(srv_name)}:</b>\n\n<pre>{truncate_html(res.text())}</pre>",
                reply_markup=InlineKeyboardMarkup(inline_keyboard=buttons),
            )
            await call.answer()
            return

        sys_services = []
        containers = []
        if "===SERVICES===" in res.stdout:
            parts = res.stdout.split("===SERVICES===")[1].split("===DOCKER===")
            s_lines = parts[0].strip().split("\n")
            d_lines = parts[1].strip().split("\n") if len(parts) > 1 else []

            for line in s_lines:
                if line.startswith("sys|"):
                    p = line.split("|")
                    if len(p) == 3:
                        sys_services.append((p[1], p[2]))
            for line in d_lines:
                if line.startswith("dk|"):
                    p = line.split("|")
                    if len(p) >= 4:
                        containers.append((p[1][:12], p[2].lstrip("/"), p[3]))

        text, kb = build_server_dashboard(srv_name, sys_services, containers, user_id)
        await safe_edit_text(msg, text, reply_markup=kb)
        await call.answer()
        return

    # Удаление сервера
    if data.startswith("fld_del_menu:"):
        folder_uid = int(data.split(":", 1)[1])
        if not is_admin(user_id) and user_id != folder_uid:
            await call.answer("⛔ Удаление чужих серверов запрещено!", show_alert=True)
            return

        builder = InlineKeyboardBuilder()
        folder_servers = [s for s, c in SERVERS.items() if c.get("creator_id") == folder_uid]

        if not folder_servers:
            await call.answer("В этой папке нет серверов.", show_alert=True)
            return

        for srv_name in folder_servers:
            builder.button(text=f"🗑 {srv_name}", callback_data=f"srv_del_ask:{srv_name}")

        builder.adjust(1)
        builder.row(InlineKeyboardButton(text="⬅️ Отмена", callback_data=f"fld:{folder_uid}"))

        u_name = get_user_display_name(folder_uid)
        await safe_edit_text(
            msg,
            f"🗑 <b>Удаление сервера</b> из папки <code>{folder_uid}</code> ({html.escape(u_name)}):\n\n"
            f"Выберите сервер для удаления из бота:",
            reply_markup=builder.as_markup(),
        )
        await call.answer()
        return

    elif data.startswith("srv_del_ask:"):
        srv_name = data.split(":", 1)[1]
        if not is_valid_existing_server(srv_name):
            await call.answer("Сервер не найден!", show_alert=True)
            return
        if not can_delete_server(user_id, srv_name):
            await call.answer("⛔ У вас нет прав на удаление этого сервера!", show_alert=True)
            return

        creator = SERVERS[srv_name].get("creator_id", user_id)
        confirm_kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="⚠️ ДА, удалить из бота", callback_data=f"srv_del_do:{srv_name}")],
            [InlineKeyboardButton(text="❌ Отмена", callback_data=f"fld:{creator}")],
        ])
        await safe_edit_text(
            msg,
            f"Вы действительно хотите удалить сервер <b>{html.escape(srv_name)}</b> из бота?\n\n"
            f"<i>Запись будет стёрта из базы, а отпечаток узла удалён из known_hosts.</i>",
            reply_markup=confirm_kb,
        )
        await call.answer()
        return

    elif data.startswith("srv_del_do:"):
        srv_name = data.split(":", 1)[1]
        if not is_valid_existing_server(srv_name):
            await safe_edit_text(msg, "Сервер уже не числится в списке.", reply_markup=get_folders_keyboard(user_id))
            await call.answer()
            return
        if not can_delete_server(user_id, srv_name):
            await call.answer("⛔ Доступ запрещен!", show_alert=True)
            return

        srv_conf = SERVERS[srv_name]
        creator = srv_conf.get("creator_id", user_id)

        remove_host_key(srv_conf["host"], srv_conf["port"])
        for rk in [k for k, v in pending_rekeys.items() if v.get("srv_name") == srv_name]:
            pending_rekeys.pop(rk, None)
        del SERVERS[srv_name]
        save_servers(SERVERS)
        server_states.pop(srv_name, None)
        log_audit(user_id, srv_name, "SERVER_DELETED")

        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="⬅️ Вернуться в папку", callback_data=f"fld:{creator}")],
            [InlineKeyboardButton(text="📂 Все папки", callback_data="folders_root")],
        ])
        await safe_edit_text(msg, f"🗑 Сервер <b>{html.escape(srv_name)}</b> успешно удален из бота.", reply_markup=kb)
        await call.answer("Сервер удален.")
        return

    # Статус службы или отдельного контейнера
    if data.startswith("st:"):
        parts = data.rsplit(":", 1)
        if len(parts) != 2 or not parts[0].startswith("st:"):
            await call.answer()
            return
        srv_name = parts[0][3:]
        target = parts[1]

        if not is_valid_existing_server(srv_name) or not has_server_access(user_id, srv_name):
            await call.answer("⛔ Доступ запрещен!", show_alert=True)
            return

        if target in MONITORED_SERVICES:
            cmd = f"systemctl status {shlex.quote(target)} --no-pager -l -n 25 2>&1"
        elif RE_CONTAINER_ID.match(target):
            q_target = shlex.quote(target)
            cmd = (
                "if command -v docker >/dev/null 2>&1 && docker inspect __CID__ >/dev/null 2>&1; then\n"
                "    echo '=== Docker Container: __CID__ ==='\n"
                "    docker ps -a --filter id=^__CID__ --format 'ID: {{.ID}}\\nСтатус: {{.Status}}\\nПорты: {{.Ports}}'\n"
                "    echo ''\n"
                "    echo '=== Последние логи (25 строк) ==='\n"
                "    DRIVER=$(docker inspect --format '{{.HostConfig.LogConfig.Type}}' __CID__ 2>/dev/null)\n"
                "    if [ \"$DRIVER\" = \"none\" ]; then\n"
                "        echo 'Логирование отключено для этого контейнера (driver: none).'\n"
                "    else\n"
                "        docker logs --tail 25 __CID__ 2>&1 || echo 'Не удалось прочитать логи.'\n"
                "    fi\n"
                "else\n"
                "    echo 'Объект не найден.'\n"
                "fi"
            ).replace("__CID__", q_target)
        else:
            await call.answer("Недопустимое имя службы или контейнера!", show_alert=True)
            return

        res = await run_ssh(srv_name, cmd, timeout=15)
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(text="🔄 Обновить", callback_data=f"st:{srv_name}:{target}"),
                InlineKeyboardButton(text="⬅️ Меню сервера", callback_data=f"srv:{srv_name}"),
            ]
        ])
        changed = await safe_edit_text(msg, f"📋 Статус <b>{html.escape(target)}</b>:\n\n<pre>{truncate_html(res.text())}</pre>", reply_markup=kb)
        await call.answer(None if changed else "Состояние не изменилось")
        return

    # Меню сети
    if data.startswith("net:menu:"):
        srv_name = data.split(":", 2)[2]
        if not is_valid_existing_server(srv_name) or not has_server_access(user_id, srv_name):
            await call.answer("⛔ Доступ запрещен!", show_alert=True)
            return
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(text="📈 Расход трафика (vnstat)", callback_data=f"net:vnstat:{srv_name}"),
                InlineKeyboardButton(text="⚡ Задержка (TCP Ping)", callback_data=f"net:latency:{srv_name}"),
            ],
            [InlineKeyboardButton(text="🔗 Сессии и сокеты (ss)", callback_data=f"net:conn:{srv_name}")],
            [InlineKeyboardButton(text="⬅️ Меню сервера", callback_data=f"srv:{srv_name}")],
        ])
        changed = await safe_edit_text(msg, f"🌐 <b>Сеть и Трафик</b> (<code>{html.escape(srv_name)}</code>):", reply_markup=kb)
        await call.answer(None if changed else "Состояние не изменилось")
        return

    elif data.startswith("net:vnstat:"):
        srv_name = data.split(":", 2)[2]
        if not is_valid_existing_server(srv_name) or not has_server_access(user_id, srv_name):
            await call.answer("⛔ Доступ запрещен!", show_alert=True)
            return
        cmd = r"""
if command -v vnstat >/dev/null 2>&1; then
    echo "=== РАСХОД ЗА МЕСЯЦ ==="; vnstat -m | head -n 12
    echo ""; echo "=== РАСХОД ПО ДНЯМ ==="; vnstat -d | head -n 10
else
    echo "vnstat не установлен."
fi
"""
        res = await run_ssh(srv_name, cmd, timeout=15)
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🔄 Обновить", callback_data=f"net:vnstat:{srv_name}"), InlineKeyboardButton(text="⬅️ Назад", callback_data=f"net:menu:{srv_name}")]
        ])
        changed = await safe_edit_text(msg, f"📈 <b>Расход трафика</b>:\n\n<pre>{truncate_html(res.text())}</pre>", reply_markup=kb)
        await call.answer(None if changed else "Состояние не изменилось")
        return

    elif data.startswith("net:latency:"):
        srv_name = data.split(":", 2)[2]
        if not is_valid_existing_server(srv_name) or not has_server_access(user_id, srv_name):
            await call.answer("⛔ Доступ запрещен!", show_alert=True)
            return
        cmd = r"""
targets=("Cloudflare (1.1.1.1)|https://1.1.1.1" "Google (8.8.8.8)|https://8.8.8.8" "Telegram|https://api.telegram.org")
for t in "${targets[@]}"; do
    n="${t%%|*}"; u="${t##*|}"
    lat=$(curl -o /dev/null -s -m 3 -w "%{time_connect}" "$u" 2>/dev/null)
    rc=$?
    if [ $rc -eq 0 ] && [ -n "$lat" ]; then
        ms=$(awk -v t="$lat" 'BEGIN {printf "%.1f ms", t * 1000}')
        printf "%-20s: %s\n" "$n" "$ms"
    else
        printf "%-20s: Таймаут / Ошибка\n" "$n"
    fi
done
"""
        res = await run_ssh(srv_name, cmd, timeout=20)
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🔄 Замерить снова", callback_data=f"net:latency:{srv_name}"), InlineKeyboardButton(text="⬅️ Назад", callback_data=f"net:menu:{srv_name}")]
        ])
        changed = await safe_edit_text(msg, f"⚡ <b>Задержка сети (TCP Handshake)</b>:\n\n<pre>{truncate_html(res.text())}</pre>", reply_markup=kb)
        await call.answer(None if changed else "Состояние не изменилось")
        return

    elif data.startswith("net:conn:"):
        srv_name = data.split(":", 2)[2]
        if not is_valid_existing_server(srv_name) or not has_server_access(user_id, srv_name):
            await call.answer("⛔ Доступ запрещен!", show_alert=True)
            return
        cmd = r"""
echo "=== СВОДКА СОКЕТОВ ==="
ss -s
echo ""
echo "=== ТОП ПРОЦЕССОВ ПО TCP (ESTABLISHED) ==="
TOP=$(sudo ss -tanp state established 2>/dev/null | sed -n 's/.*users:(("\([^",]*\).*/\1/p' | sort | uniq -c | sort -nr | head -n 10)
if [ -n "$TOP" ]; then
    printf "%-8s %s\n" "СЕССИЙ" "ПРОЦЕСС"
    echo "$TOP" | awk '{printf "%-8s %s\n", $1, $2}'
else
    echo "Нет активных соединений"
fi
"""
        res = await run_ssh(srv_name, cmd, timeout=12)
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🔄 Обновить", callback_data=f"net:conn:{srv_name}"), InlineKeyboardButton(text="⬅️ Назад", callback_data=f"net:menu:{srv_name}")]
        ])
        changed = await safe_edit_text(msg, f"🔗 <b>Сетевые сессии</b>:\n\n<pre>{truncate_html(res.text())}</pre>", reply_markup=kb)
        await call.answer(None if changed else "Состояние не изменилось")
        return

    # Меню безопасности
    if data.startswith("sec:menu:"):
        srv_name = data.split(":", 2)[2]
        if not is_valid_existing_server(srv_name) or not has_server_access(user_id, srv_name):
            await call.answer("⛔ Доступ запрещен!", show_alert=True)
            return
        changed = await safe_edit_text(msg, f"🛡 <b>Безопасность и Сеть</b> (<code>{html.escape(srv_name)}</code>):", reply_markup=get_security_menu_keyboard(srv_name, user_id))
        await call.answer(None if changed else "Состояние не изменилось")
        return

    # Интерактивное обновление отпечатка SSH
    elif data.startswith("sec:rekey:"):
        srv_name = data.split(":", 2)[2]
        if not is_admin(user_id) or not is_valid_existing_server(srv_name):
            await call.answer("⛔ Проверка и обновление ключа хоста доступны только администраторам!", show_alert=True)
            return

        cleanup_expired_rekeys()
        await safe_edit_text(msg, f"⏳ Запрашиваю открытый ключ хоста <b>{html.escape(srv_name)}</b> (без авторизации)...")
        conf = SERVERS[srv_name]
        ok, key_info, err = await fetch_unverified_host_key(conf["host"], int(conf.get("port", 22)))
        if not ok:
            kb = InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="🔄 Повторить", callback_data=f"sec:rekey:{srv_name}")],
                [InlineKeyboardButton(text="⬅️ Меню сервера", callback_data=f"srv:{srv_name}")],
            ])
            await safe_edit_text(
                msg,
                f"❌ <b>Не удалось получить ключ от {html.escape(srv_name)}:</b>\n<pre>{truncate_html(err)}</pre>",
                reply_markup=kb,
            )
            await call.answer()
            return

        req_id = secrets.token_hex(6)
        pending_rekeys[req_id] = {
            **key_info,
            "srv_name": srv_name,
            "admin_id": user_id,
            "ts": time.time(),
        }
        confirm_kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="✅ Подтвердить этот отпечаток", callback_data=f"sec:rekey_do:{req_id}")],
            [InlineKeyboardButton(text="❌ Отмена", callback_data=f"srv:{srv_name}")],
        ])
        await safe_edit_text(
            msg,
            f"🔐 <b>Проверка нового отпечатка SSH (Запрос <code>#{req_id}</code>):</b>\n\n"
            f"• Сервер: <b>{html.escape(srv_name)}</b> (<code>{html.escape(key_info['host'])}:{key_info['port']}</code>)\n"
            f"• Алгоритм: <code>{html.escape(key_info['alg'])}</code>\n"
            f"• Новый отпечаток: <code>{html.escape(key_info['fp'])}</code>\n\n"
            f"⚠️ <i>Убедитесь, что этот SHA256-отпечаток совпадает с реальным ключом сервера перед сохранением!</i>",
            reply_markup=confirm_kb,
        )
        await call.answer()
        return

    elif data.startswith("sec:rekey_do:"):
        req_id = data.split(":", 2)[2]
        if not is_admin(user_id):
            await call.answer("⛔ Доступ запрещен!", show_alert=True)
            return

        cleanup_expired_rekeys()
        key_info = pending_rekeys.get(req_id)
        if not key_info:
            await call.answer("⚠️ Запрос устарел или уже был использован. Запросите проверку заново.", show_alert=True)
            return

        if key_info.get("admin_id") != user_id:
            await call.answer("⛔ Этот запрос подтверждения был создан другим администратором!", show_alert=True)
            return

        srv_name = key_info["srv_name"]
        if not is_valid_existing_server(srv_name):
            pending_rekeys.pop(req_id, None)
            await call.answer("⚠️ Сервер больше не существует.", show_alert=True)
            return

        try:
            parsed_key = asyncssh.import_public_key(key_info["key_str"])
            actual_fp = parsed_key.get_fingerprint("sha256")
        except Exception:
            pending_rekeys.pop(req_id, None)
            await call.answer("❌ Ошибка чтения публичного ключа!", show_alert=True)
            return

        if actual_fp != key_info["fp"]:
            pending_rekeys.pop(req_id, None)
            await call.answer("❌ Несовпадение контрольного отпечатка! Операция отклонена.", show_alert=True)
            return

        pending_rekeys.pop(req_id, None)
        record_host_key(key_info["host"], key_info["port"], key_info["key_str"])
        log_audit(user_id, srv_name, "HOST_KEY_UPDATED", f"REQ:{req_id} FP:{actual_fp}")

        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🖥 В меню сервера", callback_data=f"srv:{srv_name}")]
        ])
        await safe_edit_text(
            msg,
            f"✅ <b>Отпечаток хоста {html.escape(srv_name)} успешно обновлен!</b>\n"
            f"Запрос: <code>#{html.escape(req_id)}</code>\n"
            f"Сохранен отпечаток: <code>{html.escape(actual_fp)}</code>",
            reply_markup=kb,
        )
        await call.answer("Ключ сохранен!")
        return

    elif data.startswith("sec:root:"):
        srv_name = data.split(":", 2)[2]
        if not is_admin(user_id) or not is_valid_existing_server(srv_name) or not has_server_access(user_id, srv_name):
            await call.answer("⛔ Включение root-доступа разрешено только администраторам бота!", show_alert=True)
            return

        log_audit(user_id, srv_name, "ROOT_ENABLED_2MIN")
        res = await run_ssh(srv_name, "sudo /usr/local/sbin/root.sh", timeout=25)
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🔒 Выключить Root сейчас", callback_data=f"sec:unroot:{srv_name}"), InlineKeyboardButton(text="⬅️ Назад", callback_data=f"sec:menu:{srv_name}")]
        ])
        changed = await safe_edit_text(msg, f"🔑 <b>Root-доступ</b> (таймер 2 мин):\n\n<pre>{truncate_html(res.text())}</pre>", reply_markup=kb)
        await call.answer(None if changed else "Выполнено")
        return

    elif data.startswith("sec:unroot:"):
        srv_name = data.split(":", 2)[2]
        if not is_admin(user_id) or not is_valid_existing_server(srv_name) or not has_server_access(user_id, srv_name):
            await call.answer("⛔ Действие разрешено только администраторам бота!", show_alert=True)
            return

        log_audit(user_id, srv_name, "ROOT_DISABLED")
        res = await run_ssh(srv_name, "sudo /usr/local/sbin/unroot.sh", timeout=25)
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🔑 Включить снова (2 мин)", callback_data=f"sec:root:{srv_name}"), InlineKeyboardButton(text="⬅️ Назад", callback_data=f"sec:menu:{srv_name}")]
        ])
        changed = await safe_edit_text(msg, f"🔒 <b>Root-доступ</b>:\n\n<pre>{truncate_html(res.text())}</pre>", reply_markup=kb)
        await call.answer(None if changed else "Выполнено")
        return

    elif data.startswith("sec:ufw:"):
        srv_name = data.split(":", 2)[2]
        if not is_valid_existing_server(srv_name) or not has_server_access(user_id, srv_name):
            await call.answer("⛔ Доступ запрещен!", show_alert=True)
            return
        res = await run_ssh(srv_name, "sudo ufw status numbered 2>&1", timeout=12)
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🔄 Обновить", callback_data=f"sec:ufw:{srv_name}"), InlineKeyboardButton(text="⬅️ Назад", callback_data=f"sec:menu:{srv_name}")]
        ])
        changed = await safe_edit_text(msg, f"🧱 <b>Правила UFW</b>:\n\n<pre>{truncate_html(res.text())}</pre>", reply_markup=kb)
        await call.answer(None if changed else "Состояние не изменилось")
        return

    elif data.startswith("sec:ports:"):
        srv_name = data.split(":", 2)[2]
        if not is_valid_existing_server(srv_name) or not has_server_access(user_id, srv_name):
            await call.answer("⛔ Доступ запрещен!", show_alert=True)
            return
        cmd = r"""sudo ss -tulpn | awk 'NR==1 || /LISTEN/ || /UNCONN/ {printf "%-6s %-24s %s\n", $1, $5, $7}'"""
        res = await run_ssh(srv_name, cmd, timeout=12)
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🔄 Обновить", callback_data=f"sec:ports:{srv_name}"), InlineKeyboardButton(text="⬅️ Назад", callback_data=f"sec:menu:{srv_name}")]
        ])
        changed = await safe_edit_text(msg, f"🔌 <b>Слушающие порты (TCP/UDP)</b>:\n\n<pre>{truncate_html(res.text())}</pre>", reply_markup=kb)
        await call.answer(None if changed else "Состояние не изменилось")
        return

    elif data.startswith("sec:f2b:"):
        srv_name = data.split(":", 2)[2]
        if not is_valid_existing_server(srv_name) or not has_server_access(user_id, srv_name):
            await call.answer("⛔ Доступ запрещен!", show_alert=True)
            return
        changed = await show_f2b_menu(msg, srv_name)
        await call.answer(None if changed else "Состояние не изменилось")
        return

    elif data.startswith("f2b:u:"):
        parts = data.rsplit(":", 1)
        if len(parts) != 2 or not parts[0].startswith("f2b:u:"):
            await call.answer()
            return
        srv_name = parts[0][6:]
        ip = parts[1]

        if not is_valid_existing_server(srv_name) or not has_server_access(user_id, srv_name):
            await call.answer("⛔ Доступ запрещен!", show_alert=True)
            return
        if not RE_IPV4.match(ip):
            await call.answer("Некорректный IP-адрес!", show_alert=True)
            return

        cmd = f"sudo fail2ban-client unban {shlex.quote(ip)} 2>&1"
        res = await run_ssh(srv_name, cmd, timeout=12)
        log_audit(user_id, srv_name, "FAIL2BAN_UNBAN", ip)
        await call.answer(f"Результат: {res.text()[:180]}", show_alert=True)
        await show_f2b_menu(msg, srv_name)
        return

    elif data.startswith("sec:ssl:"):
        srv_name = data.split(":", 2)[2]
        if not is_valid_existing_server(srv_name) or not has_server_access(user_id, srv_name):
            await call.answer("⛔ Доступ запрещен!", show_alert=True)
            return
        cmd = r"""
if sudo test -f /root/.acme.sh/acme.sh; then
    sudo /root/.acme.sh/acme.sh --list 2>&1
elif command -v certbot >/dev/null 2>&1; then
    sudo certbot certificates 2>&1 | grep -E "(Certificate Name|Domains|Expiry Date)"
else
    echo "acme.sh / certbot не обнаружены."
fi
"""
        res = await run_ssh(srv_name, cmd, timeout=15)
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🔄 Обновить", callback_data=f"sec:ssl:{srv_name}"), InlineKeyboardButton(text="⬅️ Назад", callback_data=f"sec:menu:{srv_name}")]
        ])
        changed = await safe_edit_text(msg, f"📜 <b>SSL-сертификаты</b>:\n\n<pre>{truncate_html(res.text())}</pre>", reply_markup=kb)
        await call.answer(None if changed else "Состояние не изменилось")
        return

    elif data.startswith("act:stats:"):
        srv_name = data.split(":", 2)[2]
        if not is_valid_existing_server(srv_name) or not has_server_access(user_id, srv_name):
            await call.answer("⛔ Доступ запрещен!", show_alert=True)
            return
        res = await run_ssh(srv_name, STATS_COMMAND, timeout=15)
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(text="🔄 Обновить", callback_data=f"act:stats:{srv_name}"),
                InlineKeyboardButton(text="⬅️ Меню сервера", callback_data=f"srv:{srv_name}"),
            ]
        ])
        changed = await safe_edit_text(msg, f"Сервер: <b>{html.escape(srv_name)}</b>\n<pre>{truncate_html(res.text())}</pre>", reply_markup=kb)
        await call.answer(None if changed else "Состояние не изменилось")
        return

    # Обновление ОС через systemd-run
    elif data.startswith("act:upgrade_ask:"):
        srv_name = data.split(":", 2)[2]
        if not is_admin(user_id) or not is_valid_existing_server(srv_name) or not has_server_access(user_id, srv_name):
            await call.answer("⛔ Обновление ОС доступно только администраторам бота!", show_alert=True)
            return
        if srv_name in upgrade_locks:
            await call.answer("⚠️ Обновление этого сервера уже выполняется!", show_alert=True)
            return

        confirm_kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🚀 ДА, обновить!", callback_data=f"act:do_upgrade:{srv_name}")],
            [InlineKeyboardButton(text="❌ Отмена", callback_data=f"srv:{srv_name}")],
        ])
        await safe_edit_text(
            msg,
            f"Запустить полное обновление ОС на <b>{html.escape(srv_name)}</b>?\n\n"
            f"<i>Запуск будет выполнен в изолированном юните systemd с проверкой кода возврата.</i>",
            reply_markup=confirm_kb,
        )
        await call.answer()
        return

    elif data.startswith("act:do_upgrade:"):
        srv_name = data.split(":", 2)[2]
        if not is_admin(user_id) or not is_valid_existing_server(srv_name) or not has_server_access(user_id, srv_name):
            await call.answer("⛔ Доступ запрещен!", show_alert=True)
            return
        if srv_name in upgrade_locks:
            await call.answer("Обновление уже запущено.", show_alert=True)
            return

        upgrade_locks.add(srv_name)
        maintenance_until[srv_name] = time.time() + 1800
        log_audit(user_id, srv_name, "SYSTEM_UPGRADE_INIT")

        cmd = (
            "sudo systemctl stop tgbot-upgrade 2>/dev/null || true; "
            "sudo systemctl reset-failed tgbot-upgrade 2>/dev/null || true; "
            "sudo systemd-run --unit=tgbot-upgrade --remain-after-exit /usr/local/sbin/update.sh 2>&1"
        )
        res = await run_ssh(srv_name, cmd, timeout=15)
        if not res.success:
            upgrade_locks.discard(srv_name)
            maintenance_until.pop(srv_name, None)
            kb = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="⬅️ Меню сервера", callback_data=f"srv:{srv_name}")]])
            await safe_edit_text(
                msg,
                f"❌ <b>Не удалось запустить systemd-юнит обновления на {html.escape(srv_name)}:</b>\n"
                f"<pre>{truncate_html(res.text())}</pre>",
                reply_markup=kb,
            )
            await call.answer()
            return

        kb = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="⬅️ Меню сервера", callback_data=f"srv:{srv_name}")]])
        await safe_edit_text(
            msg,
            f"🚀 <b>Обновление запущено на {html.escape(srv_name)}!</b>\n\n"
            f"Watcher заглушен на время работ. По окончании работы юнита <code>tgbot-upgrade</code> вам придет отчет с кодом завершения.",
            reply_markup=kb,
        )
        await call.answer()
        spawn_task(monitor_upgrade(srv_name, user_id))
        return

    elif data.startswith("act:reboot_confirm:"):
        srv_name = data.split(":", 2)[2]
        if not is_admin(user_id) or not is_valid_existing_server(srv_name) or not has_server_access(user_id, srv_name):
            await call.answer("⛔ Перезагрузка сервера доступна только администраторам!", show_alert=True)
            return
        confirm_kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="⚠️ ДА, перезагрузить!", callback_data=f"act:do_reboot:{srv_name}")],
            [InlineKeyboardButton(text="❌ Отмена", callback_data=f"srv:{srv_name}")],
        ])
        await safe_edit_text(msg, f"Перезагрузить <b>{html.escape(srv_name)}</b>?", reply_markup=confirm_kb)
        await call.answer()
        return

    elif data.startswith("act:do_reboot:"):
        srv_name = data.split(":", 2)[2]
        if not is_admin(user_id) or not is_valid_existing_server(srv_name) or not has_server_access(user_id, srv_name):
            await call.answer("⛔ Доступ запрещен!", show_alert=True)
            return
        maintenance_until[srv_name] = time.time() + 240
        log_audit(user_id, srv_name, "SYSTEM_REBOOT")
        spawn_task(run_ssh(srv_name, "sudo systemctl reboot", timeout=5))
        await asyncio.sleep(1)
        creator = SERVERS.get(srv_name, {}).get("creator_id", user_id)
        await safe_edit_text(
            msg,
            f"✅ Сигнал на перезагрузку <b>{html.escape(srv_name)}</b> отправлен.\nWatcher временно заглушен.",
            reply_markup=get_servers_in_folder_keyboard(creator, user_id),
        )
        await call.answer()
        return

    # Управление Docker
    elif data.startswith("dk:list:"):
        srv_name = data.split(":", 2)[2]
        if not is_valid_existing_server(srv_name) or not has_server_access(user_id, srv_name):
            await call.answer("⛔ Доступ запрещен!", show_alert=True)
            return
        res = await run_ssh(srv_name, "docker ps -a --format '{{.ID}}|{{.Names}}|{{.State}}'", timeout=10)
        out = res.stdout
        if not res.success or not out.strip():
            kb = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="⬅️ Меню сервера", callback_data=f"srv:{srv_name}")]])
            changed = await safe_edit_text(msg, f"Статус Docker на <b>{html.escape(srv_name)}</b>:\n<pre>{truncate_html(res.text())}</pre>", reply_markup=kb)
        else:
            kb = get_docker_containers_keyboard(srv_name, out)
            changed = await safe_edit_text(msg, f"🐳 Контейнеры на <b>{html.escape(srv_name)}</b>:", reply_markup=kb)
        await call.answer(None if changed else "Состояние не изменилось")
        return

    elif data.startswith("dk:v:"):
        parts = data.rsplit(":", 1)
        if len(parts) != 2 or not parts[0].startswith("dk:v:"):
            await call.answer()
            return
        srv_name = parts[0][5:]
        cid_short = parts[1]

        if not is_valid_existing_server(srv_name) or not has_server_access(user_id, srv_name) or not RE_CONTAINER_ID.match(cid_short):
            await call.answer("⛔ Доступ запрещен!", show_alert=True)
            return
        q_cid = shlex.quote(cid_short)
        cmd = (
            "docker inspect __CID__ "
            "--format 'Status: {{.State.Status}}\nImage: {{.Config.Image}}\nStarted: {{.State.StartedAt}}'"
        ).replace("__CID__", q_cid)
        res = await run_ssh(srv_name, cmd, timeout=10)
        out = res.text()

        status_match = re.search(r"^Status:\s*(\w+)", res.stdout.strip()) if res.success else None
        c_status = status_match.group(1).lower() if status_match else "unknown"

        if not res.success or c_status not in VALID_DOCKER_STATUSES:
            back_kb = InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="⬅️ К списку контейнеров", callback_data=f"dk:list:{srv_name}")]
            ])
            changed = await safe_edit_text(
                msg,
                f"⚠️ <b>Контейнер <code>{html.escape(cid_short)}</code> недоступен или не найден:</b>\n"
                f"<pre>{truncate_html(out)}</pre>",
                reply_markup=back_kb,
            )
            await call.answer(None if changed else "Состояние не изменилось")
            return

        changed = await safe_edit_text(
            msg,
            f"📦 Контейнер: <code>{html.escape(cid_short)}</code>\n<pre>{truncate_html(out)}</pre>",
            reply_markup=get_container_action_keyboard(srv_name, cid_short, status=c_status),
        )
        await call.answer(None if changed else "Состояние не изменилось")
        return

    # Быстрый перезапуск контейнера из алерта (по 12-символьному ID)
    elif data.startswith("dk:quick_restart:"):
        parts = data.rsplit(":", 1)
        if len(parts) != 2 or not parts[0].startswith("dk:quick_restart:"):
            await call.answer()
            return
        srv_name = parts[0][len("dk:quick_restart:"):]
        cid_short = parts[1]

        if not is_valid_existing_server(srv_name) or not has_server_access(user_id, srv_name) or not RE_CONTAINER_ID.match(cid_short):
            await call.answer("⛔ Доступ запрещен!", show_alert=True)
            return

        q_cid = shlex.quote(cid_short)
        await safe_edit_text(msg, f"⏳ Перезапуск контейнера <code>{html.escape(cid_short)}</code> на <code>{html.escape(srv_name)}</code>...")
        await call.answer()

        restart_res = await run_ssh(srv_name, f"docker restart {q_cid} 2>&1", timeout=30)
        log_audit(user_id, srv_name, "CONTAINER_QUICK_RESTART", cid_short)

        if restart_res.success:
            kb = InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="🖥 В меню сервера", callback_data=f"srv:{srv_name}")]
            ])
            await safe_edit_text(
                msg,
                f"✅ Контейнер <code>{html.escape(cid_short)}</code> на сервере <b>{html.escape(srv_name)}</b> перезапущен!",
                reply_markup=kb,
            )
        else:
            logs_res = await run_ssh(srv_name, f"docker logs --tail 40 {q_cid} 2>&1", timeout=15)
            error_details = restart_res.text()
            container_logs = logs_res.text() if logs_res.success else "Не удалось получить логи контейнера."

            retry_kb = InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="🔄 Повторить запуск", callback_data=f"dk:quick_restart:{srv_name}:{cid_short}")],
                [InlineKeyboardButton(text="⬅️ Меню сервера", callback_data=f"srv:{srv_name}")],
            ])
            # Два блока <pre> суммарно должны уложиться в лимит Telegram (4096)
            await safe_edit_text(
                msg,
                f"❌ <b>Не удалось перезапустить контейнер <code>{html.escape(cid_short)}</code> на {html.escape(srv_name)}:</b>\n"
                f"<pre>{truncate_html(error_details, 1200)}</pre>\n\n"
                f"📜 <b>Последние логи контейнера:</b>\n"
                f"<pre>{truncate_html(container_logs, 1800)}</pre>",
                reply_markup=retry_kb,
            )
        return

    elif data.startswith(("dk:str:", "dk:stp:", "dk:rst:")):
        action_code = data[3:6]
        rest = data[7:]
        parts = rest.rsplit(":", 1)
        if len(parts) != 2:
            await call.answer()
            return
        srv_name, cid_short = parts

        if not is_valid_existing_server(srv_name) or not has_server_access(user_id, srv_name) or not RE_CONTAINER_ID.match(cid_short):
            await call.answer("⛔ Доступ запрещен!", show_alert=True)
            return

        action_map = {
            "str": ("start", "CONTAINER_START", "запуска", "running"),
            "stp": ("stop", "CONTAINER_STOP", "остановки", "exited"),
            "rst": ("restart", "CONTAINER_RESTART", "перезапуска", "running"),
        }
        dk_verb, audit_act, label_ru, ok_state = action_map[action_code]
        cmd = f"docker {dk_verb} {shlex.quote(cid_short)}"
        res = await run_ssh(srv_name, cmd, timeout=30)
        new_status = ok_state if res.success else "unknown"
        log_audit(user_id, srv_name, audit_act, cid_short)
        await safe_edit_text(
            msg,
            f"Результат {label_ru}:\n<pre>{truncate_html(res.text())}</pre>",
            reply_markup=get_container_action_keyboard(srv_name, cid_short, status=new_status),
        )
        await call.answer()
        return

    elif data.startswith("dk:log:"):
        parts = data.rsplit(":", 1)
        if len(parts) != 2 or not parts[0].startswith("dk:log:"):
            await call.answer()
            return
        srv_name = parts[0][7:]
        cid_short = parts[1]

        if not is_valid_existing_server(srv_name) or not has_server_access(user_id, srv_name) or not RE_CONTAINER_ID.match(cid_short):
            await call.answer("⛔ Доступ запрещен!", show_alert=True)
            return
        q_cid = shlex.quote(cid_short)
        cmd = (
            "STATUS=$(docker inspect --format '{{.State.Status}}' __CID__ 2>/dev/null || echo 'unknown')\n"
            "echo \"__STATUS__:$STATUS\"\n"
            "docker logs --tail 30 __CID__ 2>&1"
        ).replace("__CID__", q_cid)
        res = await run_ssh(srv_name, cmd, timeout=15)
        raw_out = res.text()
        c_status = "unknown"
        if res.success and raw_out.startswith("__STATUS__:"):
            first_line, _, rest_logs = raw_out.partition("\n")
            c_status = first_line.split(":", 1)[1].strip().lower()
            out = rest_logs.strip() or "Логи пусты."
        else:
            out = raw_out or "Не удалось получить логи."

        changed = await safe_edit_text(
            msg,
            f"📜 Логи <code>{html.escape(cid_short)}</code>:\n<pre>{truncate_html(out)}</pre>",
            reply_markup=get_container_action_keyboard(srv_name, cid_short, status=c_status),
        )
        await call.answer(None if changed else "Логи не изменились")
        return

    await call.answer()


# --- ТОЧКА ВХОДА ---


async def notify_unpinned_servers():
    """После обновления: серверы без записи в known_hosts не подключатся, пока админ не подтвердит отпечаток."""
    ensure_secure_file(KNOWN_HOSTS_FILE)
    missing = [
        name for name, conf in SERVERS.items()
        if not has_server_key_pinned(conf)
    ]
    notice_file = os.path.join(BASE_DIR, "unpinned_notice.json")
    if not missing:
        try:
            os.remove(notice_file)
        except FileNotFoundError:
            pass
        return

    logging.warning("Серверы без отпечатка хоста в known_hosts: %s", ", ".join(missing))

    # Не шлём одно и то же при каждом рестарте: только если набор изменился или прошли сутки
    signature = ",".join(sorted(missing))
    try:
        with open(notice_file, "r", encoding="utf-8") as f:
            prev = json.load(f)
    except (OSError, ValueError):
        prev = {}
    if prev.get("signature") == signature and time.time() - prev.get("ts", 0) < UNPINNED_NOTICE_INTERVAL:
        return

    builder = InlineKeyboardBuilder()
    for name in missing[:20]:
        builder.button(text=f"🔑 {name}", callback_data=f"sec:rekey:{name}")
    builder.adjust(2)

    text = (
        f"⚠️ <b>Для {len(missing)} сервер(ов) нет отпечатка SSH-ключа хоста в known_hosts.</b>\n\n"
        "Пока отпечаток не подтверждён, бот не сможет подключиться к ним (защита от MITM).\n"
        "Нажмите на сервер ниже, сверьте SHA256-отпечаток с выводом "
        "<code>ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub</code> на самом сервере и подтвердите.\n\n"
        + "\n".join(f"• <code>{html.escape(n)}</code>" for n in missing[:20])
    )
    for uid in ADMIN_IDS:
        try:
            await bot.send_message(uid, text, reply_markup=builder.as_markup())
        except Exception as e:
            logging.error(f"Не удалось отправить уведомление о known_hosts админу {uid}: {e}")

    try:
        atomic_json_dump(notice_file, {"signature": signature, "ts": time.time()})
    except OSError as e:
        logging.error(f"Не удалось сохранить состояние уведомления: {e}")


def has_server_key_pinned(conf: dict) -> bool:
    try:
        return has_host_key(conf["host"], int(conf.get("port", 22)))
    except (KeyError, ValueError, TypeError):
        return False


async def main():
    global watcher_task
    ensure_secure_dir(BASE_DIR)
    ensure_secure_dir(KEYS_DIR)
    if os.path.exists(KEYS_DIR):
        for entry in os.scandir(KEYS_DIR):
            if entry.is_dir():
                ensure_secure_dir(entry.path)
                for sub in os.scandir(entry.path):
                    if sub.is_file():
                        ensure_secure_file(sub.path)

    ensure_secure_file(KNOWN_HOSTS_FILE)
    ensure_secure_file(AUDIT_LOG_FILE)
    if os.path.exists(SERVERS_FILE):
        ensure_secure_file(SERVERS_FILE)
    if os.path.exists(USERS_FILE):
        ensure_secure_file(USERS_FILE)

    await bot.delete_webhook(drop_pending_updates=True)
    await bot.set_my_commands([
        BotCommand(command="start", description="🚀 Главное меню"),
        BotCommand(command="servers", description="📂 Папки серверов"),
        BotCommand(command="key", description="🔑 Мой SSH-ключ"),
        BotCommand(command="cmd", description="⚡ Выполнить команду (Admin)"),
        BotCommand(command="cancel", description="❌ Отмена действия"),
        BotCommand(command="restart_bot", description="⚙️ Перезагрузить бота (Admin)"),
    ])

    await notify_unpinned_servers()
    watcher_task = spawn_task(background_watcher())
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
