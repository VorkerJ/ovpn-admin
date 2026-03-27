# ovpn-admin Frontend Redesign — Design Spec

**Date:** 2026-03-26
**Status:** Approved

## Цель

Редизайн фронтенда ovpn-admin — только визуальная часть, без изменения функциональности. Все API-вызовы и логика остаются прежними.

## Стек

| Было | Станет |
|------|--------|
| Vue 2 | Vue 3 (Composition API) |
| Bootstrap-Vue 2 | shadcn-vue + Tailwind CSS |
| vue-good-table | Нативная таблица (shadcn Table) |
| vue-notification | shadcn Toast |
| vue-clipboard2 | Clipboard API (нативный) |
| Монолитный `main.js` (504 строки) | Компонентная архитектура `.vue` файлы |
| Webpack | Vite |

## Дизайн

### Тема
- Тёмная и светлая тема с переключателем ☀️/🌙 в хедере
- По умолчанию — системная (`prefers-color-scheme`)
- Цветовой акцент: Indigo (`#6366f1`)

### Layout — App Shell
```
┌─────────────────────────────────────────┐
│  ⬡ OVPN Admin              ☀/🌙  + Добавить │  ← Topbar (sticky)
├─────────────────────────────────────────┤
│  [ Всего: 24 ] [ Активных: 18 ] [ Подключено: 5 ] [ Отозвано: 6 ]  │  ← Stat cards
├─────────────────────────────────────────┤
│  🔍 Поиск...         [ Скрыть отозванных ]   │  ← Toolbar
│  ┌─────────────────────────────────────┐ │
│  │ # │ Имя │ Статус │ ... │ Действия  │ │  ← Table
│  └─────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

### Таблица пользователей
- Колонки: #, Имя, Статус, Подключений, Дата истечения, Дата отзыва, Действия
- Цветовая подсветка строк: зелёная (подключён), серая (отозван), жёлтая (истёк)
- Бейджи статусов: Активен / Отозван / Истёк

### Кнопки действий (колонка «Действия»)
Паттерн: **главная кнопка + меню `···`**

| Статус | Главная кнопка | Меню ··· |
|--------|---------------|----------|
| Активен | ⬇ Конфиг | Отозвать, Маршруты, Сменить пароль |
| Отозван | ✓ Восстановить | Ротация, Удалить |
| Истёк | *(нет)* | Ротация, Удалить |

Видимость кнопок зависит от `serverRole` (master/slave) и `modulesEnabled`.

### Модальные окна (shadcn Dialog)
1. **Добавить пользователя** — поля username + password (если passwdAuth)
2. **Удалить пользователя** — подтверждение
3. **Ротация сертификатов** — поле password (если passwdAuth)
4. **Сменить пароль** — поле нового пароля
5. **Маршруты (CCD)** — статический адрес + таблица маршрутов с добавлением/удалением
6. **Конфиг** — показ текста конфига с кнопкой копирования (только slave / если нужен preview)

### Slave-режим
- В хедере показывать: «Последняя синхронизация: {lastSync}» (вместо кнопки Add user)
- Таблица маршрутов — только просмотр (без редактирования)

## Структура файлов

```
frontend/
├── index.html
├── package.json          ← обновить зависимости
├── vite.config.js        ← заменить webpack.config.js
├── tailwind.config.js
├── src/
│   ├── main.js           ← инициализация Vue 3
│   ├── App.vue           ← корневой компонент
│   ├── api.js            ← все axios-запросы (вынести из компонентов)
│   ├── components/
│   │   ├── AppHeader.vue
│   │   ├── StatCards.vue
│   │   ├── UsersTable.vue
│   │   ├── ActionsMenu.vue     ← кнопка + dropdown ···
│   │   └── modals/
│   │       ├── AddUserModal.vue
│   │       ├── DeleteUserModal.vue
│   │       ├── RotateUserModal.vue
│   │       ├── ChangePasswordModal.vue
│   │       └── CcdModal.vue
│   └── style.css
```

## API — без изменений

Все эндпоинты остаются прежними:
- `GET api/users/list`
- `GET api/server/settings`
- `GET api/sync/last/successful`
- `POST api/user/create`
- `POST api/user/revoke`
- `POST api/user/unrevoke`
- `POST api/user/rotate`
- `POST api/user/delete`
- `POST api/user/change-password`
- `POST api/user/config/show`
- `POST api/user/ccd`
- `POST api/user/ccd/apply`

## Вне скоупа

- Никаких новых функций
- Go-бэкенд не меняется
- Docker/CI конфиги не меняются (только `frontend/build.sh` может потребовать правки под Vite)
