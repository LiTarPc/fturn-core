# Передача тестового TURN/FTcore 4.2.4-test.3 — 2026-11-07

Кандидат заморожен по исходникам `91ee6cda0ef9175c5eb5c286068fb4197a7daaff`, ветка `codex/turn-browser-pow-4.2.4-test.3`.
Это клиентский тестовый комплект. Windows-сборка выполнена и запущена; Android CLI/AAR и native fixture ELF собраны и проверены по структуре. Запуск native fixtures на телефоне и настоящий WebView/VK E2E пока ожидают централизованной проверки. Приложение, его vendored cores, установленный APK, пользовательские данные, работающий VPN и серверы этой задачей не менялись.

## Исправление после test.2

Test.3 заменяет test.2 для дальнейшей интеграции. После получения success token API мог вернуть ошибку без нового challenge; этот путь теперь допускает только одну свежую ручную попытку в advanced, а после её отказа останавливает новую авторизацию. Старый IPC browser/manual при отказе, повторной капче и timeout также ждёт явного resume вместо перебора client_id. Добавлена регрессия на все шесть сценариев. Замороженные файлы test.2 сохранены неизменными.

## Состав и происхождение

Каталог: `C:/Users/LiTar/Desktop/fturn-core-4.1.3/vk-turn-fix/dist/test-client-4.2.4-test.3`.

| Файл | Назначение |
|---|---|
| client-windows-amd64.exe | Windows amd64, PE, версия v4.2.4-test.3 |
| client-android-arm64 | Android ARM64 CLI, ELF64 PIE AArch64, для последующей интеграции как native core |
| freeturn-4.2.4-test.3.aar | Android API 24+, arm64-v8a и armeabi-v7a |
| freeturn-4.2.4-test.3-sources.jar | Java-обёртки gomobile |
| manifest.json / SHA256SUMS.txt | Исходный commit, версия протокола, результаты проверок, SHA-256 |
| native-fixtures/ | Отдельные Android ARM64 PIE test ELF, необходимые testdata и run-on-device.ps1 |

Go 1.26.10. Базовые исправления стабильности сохранены commit `ca9934a`; исходная основа FTcore 4.2.3 — `fc2a5cd`. Браузерный PoW адаптирован из `hackdiaz-dev/free-turn-proxy`, tag `v4.1.0`, commit `465486ba96c4c2ff93443682ec900510b2e0ff9e`. Использована его HBL, уведомление находится в `third_party/licenses/free-turn-proxy-HBL.txt` и приложено к комплекту. Перенесён механизм браузерного результата, при этом сохранены местные ограничения запросов, cooldown и очищенная диагностика.

## Поведение и настройки

По умолчанию `advancedCaptcha=false`, автоматический режим включён. CLI `-advanced-captcha` или JSON `vk.advancedCaptcha=true` включает расширенный путь. `-manual-captcha`, JSON `vk.manualCaptcha=true`, `-auto-captcha=false` или `vk.autoCaptcha=false` имеют приоритет: получение браузерного PoW в этом случае не запускается.

Автоматическая последовательность: получить браузерный envelope за срок до 12 секунд → проверить соответствие текущему challenge, hash/nonce/difficulty и telemetry hash → продолжить существующий серверный solver → передать success token API → закончить цепочку выдачи TURN-реквизитов. Envelope не считается успехом капчи или готовым соединением.

Недоступный браузер и некорректный envelope допускают одну резервную legacy automatic попытку до отправки неверного proof. Отказ BOT отключает последующие автоматические проверки до перезапуска процесса. Rate limit и ошибка сервиса сохраняют Retry-After/cooldown и не создают немедленную ручную попытку. После обычной неудачи автоматической проверки запрашивается максимум один свежий manual challenge с прежними identity/client_id. Неудачная или повторная ручная капча переводит новую авторизацию в ожидание явного возобновления. Закэшированные реквизиты и действующие транспортные соединения не обязаны прерываться.

В CLI без IPC ожидание advanced-авторизации снимается явным перезапуском; с IPC используется `/v1/auth/resume`. Для AAR добавлен `Mobile.resumeCaptcha()`. Существующий `EventSink` сохранён; необязательный `BrowserPowSink` и `Mobile.setBrowserPowSink(...)` передают готовый приватный URL браузерному хосту и пустую строку для закрытия. AAR без BrowserPowSink не пытается сам открыть внешний браузер: выполняется ограниченный fallback. Это API для последующей UI-интеграции, готового Android WebView-хоста здесь нет.

## IPC v1/v2 и граница Android-интеграции

`internal/captchaipc/PROTOCOL.md` совпадает с RAW proposal из `E:/fturn-raw-advanced-20261107/source/internal/captchaipc/PROTOCOL.md` на момент freeze. SHA-256 документа:
`8d9c63c095eb8aa823f8b1df58bfb702bb82f0b91c3dcd20d7d8b137d37c921c`.

Поддерживаются canonical `FREETURN_CAPTCHA_TOKEN/GENERATION/PROTOCOL`, а также алиасы `FREETURN_TURN_...` и совместимые с RAW `FREETURN_RAW_...`. Разные значения одного параметра в алиасах приводят к явной ошибке запуска. TOKEN — 32 bytes hex, GENERATION — новый идентификатор процесса. Обычный запуск без IPC сохраняет CLI-режим. Для advanced+IPC требуется `CAPTCHA_PROTOCOL=2`; несовместимый v1 отклоняется до запуска сессии. Advanced environment flag поддерживается в вариантах `FREETURN_ADVANCED_CAPTCHA=1`, `FREETURN_TURN_ADVANCED_CAPTCHA=1`, `FREETURN_RAW_ADVANCED_CAPTCHA=1`.

`FREETURN_RAW_BROWSER_CAPTCHA=1` и соответствующие canonical/TURN алиасы сохраняют прежний browser-token-first режим. Advanced имеет приоритет над этим старым флагом; manual-only имеет приоритет над обоими.

В v1 поле purpose отсутствует и сохраняется старое поведение browser→manual. В v2 все события имеют `v:2`; captcha events/GET descriptor содержат `purpose`:

| purpose / phase | Значение |
|---|---|
| pow_capture / pending | Открыть отдельный фоновый браузерный хост, TTL не более 12 s |
| pow_capture / captured | Только получение envelope; закрыть эту страницу |
| pow_capture / unavailable, expired, cancelled | Закрыть capture; не превращать его в manual |
| solve / pending | Отдельная страница ручного решения либо прежний browser-token режим |
| solve / resolved | Получен success token; авторизация ещё не подтверждена |
| auth / authorized | Получены свежие TURN-реквизиты; это ещё не ready worker |

Routes остаются `/v1/captcha/<id>`, `/v1/captcha/<id>/host`, `/v1/auth/resume` и в v2. Метаданные не содержат приватный URL, PoW или токены; URL доступен только через authenticated GET. Host/Origin, bearer, generation, ID и TTL проверяются. Late replies получают 410. Захват отменяет локальный сервер при host unavailable/manual_requested/STOP/TTL; отдельный manual получает новый ID. Включены проверки, что capture/resolved/cache hit не дают ложного auth/authorized и не снимают новую паузу.

На момент передачи production Android-парсер v1-only. Нельзя включать v2 для этого парсера без его доработки и проверки жизненного цикла WebView. RAW android.6 и TURN test.2 — отдельные кандидаты; этот комплект не меняет их pins в Android-проекте.

## Проверки на компьютере

| Проверка | Результат |
|---|---|
| Основной модуль | 455 верхнеуровневых тестов PASS; 664 с subtests; 0 skip |
| third_party/turn | 135 PASS; 313 с subtests/seed cases, из test.2: исходники зависимости не менялись |
| third_party/smux | 2 PASS; 4 с subtests, из test.2: исходники зависимости не менялись |
| Пакет релея с integration tag | 26 PASS; 38 с subtests; 0 skip |
| golangci-lint 2.12.2, включая integration | 0 issues |
| go vet | PASS |
| JS observer в Node VM | PASS: final assignment, intermediate/error filtering, one-shot, token separation, legacy mode |
| Windows EXE | PASS: версия, help, incomplete IPC, v1/advanced incompatibility, unknown protocol, conflicting aliases |
| Android CLI + пять native test ELF | ELF64 PIE AArch64 |
| AAR | API 24 build; ARM64/ARMv7 ELF; Go 1.26.10; версия 4.2.4-test.3; namespace com.freeturn.core; старый EventSink и новые методы проверены |

Полная локальная fixture-цепочка проверяет browser PoW и отправку success token вплоть до TURN username/password/addresses, fallback при отсутствии хоста и неверном PoW, manual priority. Отдельно проверяются malformed/mismatched proof, error field, telemetry hash, negative nonce/duration, BOT, 429/Retry-After, 10/5, fresh manual без смены identity/client_id, repeated challenge, явная пауза, cache-hit и fresh-authorization events, приватный HTTP endpoint, late/stale replies и точный старый JSON envelope без добавления пустого error.

Стабильность: TCP half-close и доставка хвоста ответа, ограниченные UDP-очереди, отбрасывание oversized datagram, лимиты параллельных Allocate и общий quota cooldown, отмена/setup budget, delete ACK/timeout, DTLS readiness, восстановление TURN/TCP, 20 workers, typed TURN renewal callbacks и mobile shutdown fence. Серверный wire protocol smux v1 сохраняется.

Логи содержат стадии и исходы SOLVE/SUBMIT отдельно, коды сервиса и очищенный ответ, время и число попыток. Сырые PoW/telemetry, bearer/cookie, success/access/session tokens и значения URL query не выводятся. Для сетевых ошибок добавлено безопасное форматирование с сохранением errors.Is/errors.As. JSONL отчёты проверены на PRIVATE fixture markers и JWT shape — совпадений нет.

Проверки выполнялись на Windows; native Android пока только собран, JS VM не заменяет WebView. Race detector не запускался: gcc в этой Windows-среде отсутствует. Живой VK не вызывался. Ни один локальный тест не доказывает 100% принятие капчи VK.

## Запуск выбранных native fixture suites на телефоне

Устройство используется централизованно Android-координатором. Этот чат не запускает ADB и не перехватывает слот. Из каталога комплекта:

```powershell
./native-fixtures/run-on-device.ps1 -Serial '<serial>' -Adb '<path-to-adb.exe>'
```

Скрипт создаёт только `/data/local/tmp/fturn-turn-fixture-4.2.4-test.3`, копирует fixtures, запускает выбранные suites. APK не устанавливает, приложения/VPN не останавливает, данные не очищает. TMPDIR указывает на отдельную tmp-папку. Native fixture checks используют локальные/подставные ответы и loopback, без VK.

| ELF | -test.run | Рабочая папка |
|---|---|---|
| captchaipc.test | `^Test(V2\|V1Wire\|IPCEnvironment)` | корень набора |
| captcha.test | `^Test(BrowserPow\|TransportError)` | captcha/ |
| manual.test | `^Test(PowCapture\|CaptureInjection\|RunCaptchaServerPresents)` | корень набора |
| vkauth.test | `^TestAdvanced` | vkauth/ |
| vk.test | `^TestAuthGate` | корень набора |

Единственный внешний testdata-файл — `captcha/testdata/not_robot_captcha.html`. Для captcha.test он доступен как `testdata/not_robot_captcha.html`; для vkauth.test — как `../captcha/testdata/not_robot_captcha.html`. Не запускать vkauth.test из корня набора. Скрипт учитывает эти рабочие папки и проверяет каждый exit code. Все ELF PIE, API 24 arm64.

Результаты native suites нужно приложить отдельным acceptance-отчётом с device/API и хешами. Привязку к настоящему Android WebView, STOP/background/renderer restart/TTL и действующему VK проверять после доработки v2 host. До этого комплект имеет статус test candidate.

## Воспроизводимость

```powershell
./scripts/build-client-test.ps1 -Version '4.2.4-test.3' -GoExe '<Go-1.26.10-go.exe>'
node scripts/test-captcha-observer.cjs
go test -count=1 ./...
go -C third_party/turn test -count=1 ./...
go -C third_party/smux test -count=1 ./...
go test -count=1 -tags integration ./internal/proxy/tcprelay
go vet ./...
golangci-lint run --build-tags integration ./...
```

Для сборки AAR нужны JDK, Android SDK/NDK; в текущем комплекте использован NDK 28.2.13676358. gomobile/gobind собираются из закреплённых зависимостей проекта. Контрольные суммы окончательных файлов находятся в manifest.json / SHA256SUMS.txt; исходники после freeze не меняются, изменение кандидата потребует новых хешей и передачи.
