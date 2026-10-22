# 🛡️ XSafety — сканер вирусов

Веб-сканер файлов на Firebase (Auth + Realtime Database). Работает сразу на **GitHub Pages** (без сборки): https://Koteycagames.github.io/XSafety/

## Модели и тарифы
| Тариф | XSafety 1 | XSafety 2 | XSafety 3 Lite | XSafety 3 Pro |
|---|---|---|---|---|
| **Default** (сразу при регистрации) | 5 запросов, до 10 МБ | 🔒 | 🔒 | 🔒 |
| **Pro** | 15 запр., до 30 МБ | 10 запр., до 30 МБ | 5 запр., до 30 МБ | 🔒 |
| **Premium** | 30 запр., до 50 МБ | 25 запр., до 50 МБ | 20 запр., до 50 МБ | 15 запр., до 100 МБ |

- **XSafety 1** — только `.bat`, `.py`, базовый детект.
- **XSafety 2** — `.bat .py .js .vbs .vbe .hta`, лучше видит обфускацию.
- **XSafety 3 Lite** — всё из v2 + `.docm/.dotm/.xlsm/.xltm/.pptm/.potm/.ppsm`, `.doc/.xls/.ppt`, архивы `.zip/.rar/.7z/.tar/.gz`, образы `.iso/.img/.vhd/.vhdx`, `.jar`, `.pyw`, `.dll`, `.jse`, PowerShell `.ps1/.ps1xml/.ps2/.ps2xml/.psc1/.psc2`. Глубокий анализ: строки из бинарников, распаковка ZIP, поиск скрытых сигнатур.
- **XSafety 3 Pro** — любые файлы, максимум: энтропия, Base64/XOR/hex-пейлоады, shellcode, анти-анализ, двойные расширения, зашифрованные вирусы.

Лимиты на запросы списываются в Realtime Database (`users/{uid}/usage`), админ может их сбрасывать и добавлять.

## Авторизация
- Вводится только имя почты — `@gmail.com` подставляется автоматически.
- Запрещена регистрация имён, похожих на **Koteyca** (включая варианты с цифрами-«литом»: k0teyca и т.п.). Единственное исключение — сам админ `Koteyca@gmail.com`.
- Админ-панель (только `Koteyca@gmail.com`): все пользователи, выдача/забор подписки (смена тарифа), +5 запросов по любой модели, сброс лимитов, бан/разбан.

## 🔐 Firebase-конфиг НЕ на GitHub
Настоящий конфиг лежит в `js/firebase-config.js` — файл в `.gitignore` и в репозиторий не попадает.
Шаблон: `js/firebase-config.example.js` (скопировать → `js/firebase-config.js` → вставить свои ключи).

## Настройка Firebase (один раз)
1. Firebase Console → **Authentication** → включить **Email/Password**.
2. **Realtime Database** → создать базу → в **Rules** вставить правила из `firebase.rules.json` → Publish.
3. Зарегистрироваться как `Koteyca` (пароль свой) — этот аккаунт автоматически админ.

## Структура
```
index.html            — интерфейс (Live Server)
css/style.css
js/app.js             — авторизация, сканер, история, тарифы
js/admin.js           — админ-панель
js/firebase.js        — Firebase + защита имени Koteyca
js/plans.js           — тарифы, лимиты, форматы моделей
js/engines/scanner.js — движок: сигнатуры, энтропия, строки, ZIP
js/engines/signatures.js — база сигнатур по уровням моделей
js/firebase-config.example.js — шаблон конфига (без секретов)
firebase.rules.json   — правила Realtime Database
```
