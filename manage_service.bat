@echo off
echo === Управление VirusDetect Service ===
echo.

if "%1"=="install" goto install
if "%1"=="uninstall" goto uninstall
if "%1"=="start" goto start
if "%1"=="stop" goto stop
if "%1"=="status" goto status
if "%1"=="console" goto console
if "%1"=="delete" goto delete

echo Использование: %0 [install^|uninstall^|start^|stop^|status^|console^|delete]
echo.
echo   install   - Установить сервис
echo   uninstall - Удалить сервис
echo   start     - Запустить сервис
echo   stop      - Остановить сервис
echo   status    - Показать статус сервиса
echo   console   - Запустить в консольном режиме
echo   delete    - Удалить подозрительные процессы
echo.
goto end

:install
echo Установка VirusDetect Service...
VirusDetect.exe install
if %errorlevel%==0 (
    echo Сервис успешно установлен!
    echo Для запуска используйте: %0 start
) else (
    echo Ошибка при установке сервиса!
)
goto end

:uninstall
echo Удаление VirusDetect Service...
sc stop VirusDetectService >nul 2>&1
VirusDetect.exe uninstall
if %errorlevel%==0 (
    echo Сервис успешно удален!
) else (
    echo Ошибка при удалении сервиса!
)
goto end

:start
echo Запуск VirusDetect Service...
sc start VirusDetectService
if %errorlevel%==0 (
    echo Сервис успешно запущен!
) else (
    echo Ошибка при запуске сервиса!
)
goto end

:stop
echo Остановка VirusDetect Service...
sc stop VirusDetectService
if %errorlevel%==0 (
    echo Сервис успешно остановлен!
) else (
    echo Ошибка при остановке сервиса!
)
goto end

:status
echo Статус VirusDetect Service:
sc query VirusDetectService
goto end

:console
echo Запуск в консольном режиме...
VirusDetect.exe console
goto end

:delete
echo Запуск удаления подозрительных процессов...
echo ВНИМАНИЕ: Эта операция завершит все процессы с паттернами .exe.exe и удалит их файлы!
echo.
VirusDetect.exe delete
goto end

:end
pause
