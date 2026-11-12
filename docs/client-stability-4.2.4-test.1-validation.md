# Проверка клиентских ядер 4.2.4-test.1

Версия проверена запуском Windows EXE: `v4.2.4-test.1`. `-h` также завершается успешно.

| Проверка | Результат |
|---|---|
| Основной модуль | 428 тестов PASS |
| TURN | 135 проверок PASS, включая штатный seed corpus Fuzz |
| smux | 2 теста PASS; half-close дополнительно проверен для v1 и v2 |
| Integration TCP/UDP | 26 верхнеуровневых тестов PASS |
| golangci-lint 2.12.2 с integration tag | 0 issues |
| go vet | PASS |
| gofmt изменённых/новых Go-файлов | PASS |
| Windows amd64 | Сборка, версия, help и build info проверены |
| Android arm64 CLI | ELF AArch64, версия и Go 1.26.10 проверены |
| Android AAR | ARM64/ARMv7 ELF, Go 1.26.10, версия и Java namespace проверены |

Integration включает восемь комбинаций TURN TCP/UDP и none/rtpopus/rtpopus2/rtpopus3, проверку целостности после oversized datagram, отсутствие ready при недоступном DTLS peer, восстановление TURN/TCP, 20 workers и два quota-кандидата, delete ACK и потерю delete. Совместимые INFO-сигналы для оболочек проверяются в UDP-матрице.

Проверки выполнялись локально на Windows. Race detector недоступен без gcc. GitHub Actions для локальной ветки не запускались; Linux race и Windows integration добавлены в CI. Запуск на Android-устройстве и живом VK не проверялся. Валидация ELF/версии не заменяет проверку устройства и реальной сети.

Полный Windows gofmt-list включает исходные нетронутые файлы с CRLF; для изменения проверены только затронутые и новые Go-файлы, без массового форматирования чужого кода.

Аудит `audit/2026-10-25/FTCORE-4.2.3-AUDIT.md` описывает исходную 4.2.3. Результаты исправлений находятся в `audit/2026-10-25/results/final-*`.
