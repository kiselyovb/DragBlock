# DragBlock

**DragBlock** — это защитная DLL-библиотека для Windows, блокирующая перенос выделенного текста между приложениями через механизм `DoDragDrop`. Предназначена для использования в системах предотвращения утечек данных (DLP).

## Назначение

При установке в автозагрузку или инъекции в процессы, DragBlock:

- перехватывает вызов `DoDragDrop` из `ole32.dll`
- проверяет, содержит ли переносимый объект текст (в форматах `CF_TEXT` или `CF_UNICODETEXT`)
- отменяет перетаскивание, если оно содержит текст
- записывает события в системный журнал Windows
- управляется через параметры в реестре

## Возможности

- Блокировка перетаскивания текстовых данных
- Логирование в `Event Log` (журнал Windows)
- Отладочный режим с измерением времени выполнения функций
- Управление логированием через реестр
- Отображение ошибок хуков в системном журнале

##  Сборка

### Требования

- Visual Studio 2022 с рабочей нагрузкой **Desktop development with C++**
- [MinHook](https://github.com/TsudaKageyu/minhook) — клонировать/скачать и собрать `.lib` для x64/x86

### Шаги

1. Склонируйте репозиторий MinHook и соберите `libMinHook.x64.lib` и `libMinHook.x86.lib` из `build/VC17`.
2. Скопируйте их в папку `external\minhook\lib`.
3. Добавьте в свойства проекта:
   - `Additional Include Directories` → `external\minhook\include`
   - `Additional Library Directories` → `external\minhook\lib`
4. Для **x64** сборки:
   - Установите `Target Name` → `DragBlock.64`
5. Для **x86** (Win32) сборки:
   - Установите `Target Name` → `DragBlock.32`

## Логирование

Журнал записей находится в:

```
Панель управления → Администрирование → Просмотр событий
→ Журналы Windows → Приложение → Источник: DragBlock
```

### Режимы логирования

Уровень задаётся через реестр:

```reg
[HKEY_LOCAL_MACHINE\SOFTWARE\DragBlock]
"LogLevel"=dword:00000002
```

- `0` — логирование отключено
- `1` — обычный режим (старт, стоп, ошибки)
- `2` — отладочный режим (вход в функции, тайминг, подробности)

> ⚠️ Требуются права администратора для доступа к HKLM

## Интеграция

### Вариант 1: `AppInit_DLLs` (для глобальной инъекции)

1. Убедитесь, что DLL подписана (или отключено `RequireSignedAppInit_DLLs`)
2. Создайте запись:

```reg
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows]
"LoadAppInit_DLLs"=dword:00000001
"AppInit_DLLs"="C:\\Path\\To\\DragBlock.64.dll"
"RequireSignedAppInit_DLLs"=dword:00000000
```

### Вариант 2: Инъекция вручную

- Через `SetWindowsHookEx`, `CreateRemoteThread`, или сторонние инструменты (например, `DLL Injector`)

## Сборка в двух вариантах

| Платформа | Имя DLL             | Путь             |
|-----------|---------------------|------------------|
| x64       | `DragBlock.64.dll` | `x64\Release\` |
| x86       | `DragBlock.32.dll` | `Release\`      |

## Ограничения

- Не защищает от нестандартных переносов (если приложение не использует `DoDragDrop`)
- Инъекция в процессы с правами администратора требует запуска с теми же правами
- `AppInit_DLLs` работает только с GUI-приложениями, загружающими `user32.dll`

## Лицензия

MIT License (если используется MinHook — он распространяется под лицензией BSD-2-Clause)

## Авторы и вдохновение

Разработка основана на изучении структуры Windows Drag & Drop (OLE), MinHook, и практик защиты данных на уровне API и ошибки при эксплуатации ПО Perimetrix.

## Генерауия самоподписанного (локального) сертификата
Генерация сертификата
New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=Test DragBlock" -CertStoreLocation "Cert:\\CurrentUser\\My"
  
После этого сертификат появится в: certmgr.msc → Личное → Сертификаты → "Test DragBlock"
Копируй его в: Доверенные корневые центры сертификации → Сертификаты

Подписываем DLL
.\signtool.exe sign /n "Test DragBlock" /fd SHA256 /td SHA256 /tr http://timestamp.digicert.com "C:\Users\kisel\source\DragBlock\x64\Release\DragBlock.x64.dll"

Проверка подписи
.\signtool.exe verify /pa /v "C:\Users\kisel\source\DragBlock\x64\Release\DragBlock.x64.dll"

## Проверка работоспособности решения
Запускаем notepad PowerShell
Start-Process "$env:windir\\System32\\notepad.exe"
вводим текст, выделяем и переносим в другой редактор -> перенос не должен происходить