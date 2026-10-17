# TG Server Admin Bot

Руководство по установке и первичной настройке управляющего
Telegram-бота на Linux-сервере: Ubuntu, Debian, CentOS, Rocky Linux и
AlmaLinux.

## Быстрая установка в один шаг

Запустите команду от имени `root` или пользователя с правами `sudo`.
Скрипт загрузит установщик из официального репозитория и выполнит
установку:

```bash
wget -O install_bot.sh \
  https://raw.githubusercontent.com/EvgenyElizarenko/TG-Server-Admin-Bot/refs/heads/main/script's/install_bot.sh && \
  chmod +x install_bot.sh && \
  sudo ./install_bot.sh
```

Установщик автоматически:

- установит системные зависимости: Python 3, `python3-venv`, OpenSSH-
  клиент, `curl` и `git`;
- создаст непривилегированного системного пользователя `tgbot` с
  домашним каталогом `/home/tgbot`;
- подготовит рабочие каталоги с ограниченными правами доступа;
- разместит исполняемый код `bot.py`;
- создаст виртуальное окружение Python и установит `aiogram`,
  `asyncssh` и `python-dotenv`;
- запросит токен Telegram-бота и Telegram ID администраторов и
  сохранит их в закрытом файле `.env`;
- создаст и запустит службу `systemd` с именем
  `tg-server-bot.service`.

> Перед запуском убедитесь, что доверяете исходному коду установщика и
> скачиваете его из официального репозитория проекта.
