# TG Server Admin Bot

Руководство по установке и первичной настройке управляющего
Telegram-бота на Linux-сервере: Ubuntu, Debian, CentOS, Rocky Linux и
AlmaLinux.

## Быстрая установка в один шаг

Запустите команду от имени `root` или пользователя с правами `sudo`.
Скрипт загрузит установщик из официального репозитория и выполнит
установку:

``` bash
wget -O install_bot.sh https://raw.githubusercontent.com/EvgenyElizarenko/TG-Server-Admin-Bot/refs/heads/main/script's/install_bot.sh \
  && chmod +x install_bot.sh \
  && sudo ./install_bot.sh
```

Установщик автоматически:

-   установит системные зависимости: Python 3, `python3-venv`,
    OpenSSH-клиент, `curl` и `git`;
-   создаст непривилегированного системного пользователя `tgbot` с
    домашним каталогом `/home/tgbot`;
-   подготовит рабочие каталоги с ограниченными правами доступа;
-   разместит исполняемый код `bot.py`;
-   создаст виртуальное окружение Python и установит `aiogram`,
    `asyncssh` и `python-dotenv`;
-   запросит токен Telegram-бота и Telegram ID администраторов и
    сохранит их в закрытом файле `.env`;
-   создаст и запустит службу `systemd` с именем
    `tg-server-bot.service`.

> Перед запуском убедитесь, что доверяете исходному коду установщика и
> скачиваете его из официального репозитория проекта.

## Пошаговая ручная установка

### 1. Установка системных пакетов

**Ubuntu / Debian:**

``` bash
sudo apt-get update -qq
sudo apt-get install -y python3 python3-venv python3-pip openssh-client curl git
```

**CentOS / Rocky Linux / AlmaLinux:**

``` bash
sudo dnf install -y python3 python3-pip openssh-clients curl git
```

### 2. Создание пользователя и каталогов

Создайте непривилегированного пользователя `tgbot` и рабочие каталоги:

``` bash
sudo useradd -m -s /bin/bash tgbot
sudo mkdir -p /home/tgbot/tg-bot-env/keys

sudo chmod 700 /home/tgbot
sudo chmod 700 /home/tgbot/tg-bot-env
sudo chmod 700 /home/tgbot/tg-bot-env/keys
sudo chown -R tgbot:tgbot /home/tgbot
```

Если пользователь `tgbot` уже существует, повторно выполнять `useradd`
не нужно. Проверьте владельца и права каталогов перед продолжением.

### 3. Размещение кода бота

``` bash
sudo -u tgbot wget -O /home/tgbot/tg-bot-env/bot.py \
  https://raw.githubusercontent.com/EvgenyElizarenko/TG-Server-Admin-Bot/refs/heads/main/bot.py

sudo chmod 700 /home/tgbot/tg-bot-env/bot.py
```

### 4. Создание виртуального окружения Python

``` bash
sudo -u tgbot python3 -m venv /home/tgbot/tg-bot-env/venv
sudo -u tgbot /home/tgbot/tg-bot-env/venv/bin/pip install --upgrade pip
sudo -u tgbot /home/tgbot/tg-bot-env/venv/bin/pip install \
  "aiogram>=3.4.0" \
  "asyncssh>=2.14.0" \
  "python-dotenv>=1.0.0"
```

### 5. Настройка файла окружения `.env`

Создайте файл `/home/tgbot/tg-bot-env/.env`:

``` bash
sudo tee /home/tgbot/tg-bot-env/.env > /dev/null <<'EOF'
BOT_TOKEN=ВСТАВЬТЕ_ТОКЕН_ОТ_BOTFATHER
ADMIN_IDS=123456789,987654321
EOF
```

Замените примерные значения на настоящий токен бота и Telegram ID
администраторов. Укажите ID числами через запятую, без пробелов --- если
это соответствует формату, ожидаемому используемой версией бота.

Ограничьте доступ к файлу:

``` bash
sudo chown tgbot:tgbot /home/tgbot/tg-bot-env/.env
sudo chmod 600 /home/tgbot/tg-bot-env/.env
```

**Не публикуйте токен и не передавайте файл `.env` посторонним.** Если
токен раскрыт, перевыпустите его через BotFather.

### 6. Инициализация служебных файлов

``` bash
cd /home/tgbot/tg-bot-env

sudo -u tgbot sh -c 'echo "{}" > servers.json'
sudo -u tgbot sh -c 'echo "{}" > users.json'
sudo -u tgbot touch known_hosts audit.log

sudo chown tgbot:tgbot servers.json users.json known_hosts audit.log
sudo chmod 600 servers.json users.json known_hosts audit.log
```

### 7. Создание службы systemd

Создайте файл `/etc/systemd/system/tg-server-bot.service`:

``` bash
sudo tee /etc/systemd/system/tg-server-bot.service > /dev/null <<'EOF'
[Unit]
Description=Telegram Server Admin & Monitoring Bot
After=network.target

[Service]
Type=simple
User=tgbot
Group=tgbot
WorkingDirectory=/home/tgbot/tg-bot-env
ExecStart=/home/tgbot/tg-bot-env/venv/bin/python /home/tgbot/tg-bot-env/bot.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Ограничения безопасности процесса
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/home/tgbot/tg-bot-env

[Install]
WantedBy=multi-user.target
EOF
```

Служба запускается от имени `tgbot`, а не `root`. Параметры
`ProtectSystem`, `ProtectHome` и `ReadWritePaths` ограничивают доступ
процесса к файловой системе. Если бот использует дополнительные каталоги
для записи, их потребуется явно учесть в настройках службы.

### 8. Запуск и проверка службы

``` bash
sudo systemctl daemon-reload
sudo systemctl enable --now tg-server-bot.service
```

Проверить состояние:

``` bash
sudo systemctl status tg-server-bot.service --no-pager
```

Посмотреть журнал в реальном времени:

``` bash
sudo journalctl -u tg-server-bot.service -f
```

Последние 100 строк журнала:

``` bash
sudo journalctl -u tg-server-bot.service -n 100 --no-pager
```

Перезапустить службу после изменения конфигурации или кода:

``` bash
sudo systemctl restart tg-server-bot.service
```

Остановить службу:

``` bash
sudo systemctl stop tg-server-bot.service
```

## Первые действия после запуска

1.  Откройте диалог с ботом в Telegram и отправьте `/start`.

2.  Отправьте `/key`, чтобы получить персональный публичный SSH-ключ
    Ed25519.

3.  На каждом целевом сервере добавьте полученный публичный ключ в файл
    `authorized_keys` пользователя, от имени которого бот должен
    подключаться. Например, для пользователя `botadmin`:

    ``` bash
    sudo install -d -m 700 -o botadmin -g botadmin /home/botadmin/.ssh
    sudo -u botadmin touch /home/botadmin/.ssh/authorized_keys
    sudo chmod 600 /home/botadmin/.ssh/authorized_keys
    ```

    Затем добавьте содержимое публичного ключа отдельной строкой в
    `/home/botadmin/.ssh/authorized_keys` и проверьте владельца файла:

    ``` bash
    sudo chown botadmin:botadmin /home/botadmin/.ssh/authorized_keys
    ```

4.  Настройте `sudoers` на целевых серверах, предоставив пользователю
    `botadmin` только те команды, которые действительно нужны функциям
    бота. Для редактирования правил используйте `visudo` и избегайте
    безусловного предоставления `NOPASSWD: ALL`, если это не является
    осознанным требованием вашей модели безопасности.

## Диагностика

Если бот не запускается, сначала проверьте журнал:

``` bash
sudo journalctl -u tg-server-bot.service -n 100 --no-pager
```

Проверьте права и наличие основных файлов:

``` bash
sudo ls -ld /home/tgbot /home/tgbot/tg-bot-env
sudo ls -l /home/tgbot/tg-bot-env
sudo ls -l /home/tgbot/tg-bot-env/.env
```

Убедитесь, что токен и Telegram ID в `.env` указаны корректно, а
виртуальное окружение содержит необходимые пакеты.

## Структура каталогов

После установки рабочая директория должна содержать примерно следующие
файлы:

``` text
/home/tgbot/
└── tg-bot-env/
    ├── bot.py
    ├── .env
    ├── venv/
    ├── keys/
    ├── servers.json
    ├── users.json
    ├── known_hosts
    └── audit.log
```

Фактический состав файлов может зависеть от версии бота и установщика.
