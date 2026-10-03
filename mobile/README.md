# Ftcore mobile

Сборка AAR: `task build:android`. Результат: `dist/freeturn.aar`.

Java API: `com.freeturn.core.mobile.Mobile`.

Получите шаблон через `DefaultConfigJSON()`, заполните адрес сервера и ссылки мессенджера. Проверьте конфигурацию через `ValidateConfig()`.

Запуск: `Start()` или `StartTunnel()`. Остановка: `Stop()`. Состояние: `GetState()`.
