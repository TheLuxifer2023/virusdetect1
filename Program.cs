using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Management;
using System.Reflection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.EventLog;
using System.Runtime.InteropServices;

namespace VirusDetect
{
    class Program
    {
        static async Task Main(string[] args)
        {
            // Проверяем аргументы командной строки для установки/удаления сервиса
            if (args.Length > 0)
            {
                switch (args[0].ToLower())
                {
                    case "install":
                        InstallService();
                        return;
                    case "uninstall":
                        UninstallService();
                        return;
                    case "console":
                        // Запуск в консольном режиме для отладки
                        RunAsConsole();
                        return;
                    case "delete":
                        // Удаление подозрительных процессов
                        await DeleteSuspiciousProcesses();
                        return;
                }
            }

            // Создаем хост для Windows Service
            var host = CreateHostBuilder(args).Build();
            host.Run();
        }

        static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .UseWindowsService(options =>
                {
                    options.ServiceName = "VirusDetectService";
                })
                .ConfigureServices((context, services) =>
                {
                    services.AddHostedService<VirusDetectService>();
                    services.AddSingleton<ProcessMonitor>();
                    services.AddSingleton<ConfigurationService>();
                    services.AddSingleton<SecurityService>();
                })
                .ConfigureLogging((context, logging) =>
                {
                    logging.ClearProviders();
                    logging.AddConsole();
                    logging.AddEventLog(new EventLogSettings
                    {
                        SourceName = "VirusDetectService",
                        LogName = "Application"
                    });
                });

        static void RunAsConsole()
        {
            Console.WriteLine("=== Детектор подозрительных процессов (Консольный режим) ===");
            Console.WriteLine("Для установки как Windows Service используйте: VirusDetect.exe install");
            Console.WriteLine("Для удаления Windows Service используйте: VirusDetect.exe uninstall");
            Console.WriteLine();

            var host = CreateHostBuilder(new string[] { "console" }).Build();
            host.Run();
        }

        static void InstallService()
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "sc",
                        Arguments = $"create VirusDetectService binPath= \"{Environment.ProcessPath}\" start= auto DisplayName= \"Virus Detection Service\"",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                process.Start();
                process.WaitForExit();
                
                if (process.ExitCode == 0)
                {
                    Console.WriteLine("Сервис успешно установлен!");
                    Console.WriteLine("Для запуска используйте: sc start VirusDetectService");
                }
                else
                {
                    Console.WriteLine("Ошибка при установке сервиса. Убедитесь, что запущено от имени администратора.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка при установке сервиса: {ex.Message}");
            }
        }

        static void UninstallService()
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "sc",
                        Arguments = "delete VirusDetectService",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                process.Start();
                process.WaitForExit();
                
                if (process.ExitCode == 0)
                {
                    Console.WriteLine("Сервис успешно удален!");
                }
                else
                {
                    Console.WriteLine("Ошибка при удалении сервиса. Убедитесь, что запущено от имени администратора.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка при удалении сервиса: {ex.Message}");
            }
        }

        static async Task DeleteSuspiciousProcesses()
        {
            Console.WriteLine("=== Удаление подозрительных процессов ===");
            Console.WriteLine("ВНИМАНИЕ: Эта операция завершит все процессы с паттернами .exe.exe и удалит их файлы!");
            Console.WriteLine();
            
            Console.Write("Вы уверены? Введите 'YES' для подтверждения: ");
            var confirmation = Console.ReadLine();
            
            if (confirmation?.ToUpper() != "YES")
            {
                Console.WriteLine("Операция отменена.");
                return;
            }
            
            try
            {
                // Создаем хост для получения сервисов
                var host = CreateHostBuilder(new string[] { "delete" }).Build();
                
                using (var scope = host.Services.CreateScope())
                {
                    var securityService = scope.ServiceProvider.GetRequiredService<SecurityService>();
                    var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();
                    
                    logger.LogInformation("Запуск операции удаления подозрительных процессов...");
                    
                    var actions = await securityService.KillAndDeleteSuspiciousProcessesAsync();
                    
                    Console.WriteLine($"\nОперация завершена!");
                    Console.WriteLine($"Обработано процессов: {actions.Count}");
                    Console.WriteLine($"Завершено процессов: {actions.Count(a => a.ProcessKilled)}");
                    Console.WriteLine($"Удалено файлов: {actions.Count(a => a.FileDeleted)}");
                    
                    if (actions.Any(a => !string.IsNullOrEmpty(a.ErrorMessage)))
                    {
                        Console.WriteLine("\nОшибки:");
                        foreach (var action in actions.Where(a => !string.IsNullOrEmpty(a.ErrorMessage)))
                        {
                            Console.WriteLine($"- {action.ProcessName}: {action.ErrorMessage}");
                        }
                    }
                    
                    Console.WriteLine($"\nПодробные результаты записаны в лог файл.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка при выполнении операции: {ex.Message}");
            }
            
            Console.WriteLine("\nНажмите любую клавишу для выхода...");
            Console.ReadKey();
        }
    }

    // Основной сервис для мониторинга процессов
    public class VirusDetectService : BackgroundService
    {
        private readonly ILogger<VirusDetectService> _logger;
        private readonly ProcessMonitor _processMonitor;
        private readonly ConfigurationService _configService;

        public VirusDetectService(ILogger<VirusDetectService> logger, ProcessMonitor processMonitor, ConfigurationService configService)
        {
            _logger = logger;
            _processMonitor = processMonitor;
            _configService = configService;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("VirusDetectService запущен");

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await _processMonitor.ScanProcessesAsync();
                    await Task.Delay(TimeSpan.FromSeconds(_configService.GetScanInterval()), stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Ошибка при сканировании процессов");
                    await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken); // Ждем 30 секунд перед повтором
                }
            }

            _logger.LogInformation("VirusDetectService остановлен");
        }
    }

    // Сервис для мониторинга процессов
    public class ProcessMonitor
    {
        private readonly ILogger<ProcessMonitor> _logger;
        private readonly ConfigurationService _configService;
        private readonly string _logFilePath;
        private readonly HashSet<int> _knownProcesses = new();

        public ProcessMonitor(ILogger<ProcessMonitor> logger, ConfigurationService configService)
        {
            _logger = logger;
            _configService = configService;
            _logFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "suspicious_processes.log");
            
            // Логируем путь к файлу для отладки
            _logger.LogInformation("Лог файл будет сохранен в: {LogFilePath}", _logFilePath);
        }

        public async Task ScanProcessesAsync()
        {
            var suspiciousProcesses = new List<SuspiciousProcess>();
            var newSuspiciousProcesses = new List<SuspiciousProcess>();
            var processes = Process.GetProcesses();
            var totalProcessesScanned = processes.Length;
            
            _logger.LogDebug($"Сканирование {processes.Length} процессов");
            
            foreach (var process in processes)
            {
                try
                {
                    // Логируем только подозрительные процессы
                    // _logger.LogDebug("Проверяем процесс: {ProcessName} (PID: {ProcessId})", process.ProcessName, process.Id);
                    
                    // Специальная проверка для Registry процессов
                    if (process.ProcessName.ToLower().Contains("registry"))
                    {
                        _logger.LogInformation("НАЙДЕН ПРОЦЕСС REGISTRY: {ProcessName} (PID: {ProcessId})", process.ProcessName, process.Id);
                    }
                    
                    if (IsSuspiciousProcess(process, out string reason))
                    {
                        var processPath = GetProcessPath(process);
                        var suspiciousProcess = new SuspiciousProcess
                        {
                            ProcessName = process.ProcessName,
                            ProcessId = process.Id,
                            MainModulePath = processPath,
                            DetectionReason = reason,
                            DetectionTime = DateTime.Now,
                            FileProperties = GetFileProperties(processPath ?? "")
                        };
                        
                        suspiciousProcesses.Add(suspiciousProcess);
                        
                        _logger.LogWarning("ОБНАРУЖЕН ПОДОЗРИТЕЛЬНЫЙ ПРОЦЕСС: {ProcessName} (PID: {ProcessId}) Путь: {ProcessPath} - {Reason}", 
                            process.ProcessName, process.Id, suspiciousProcess.MainModulePath ?? "Неизвестно", reason);
                        
                        // Проверяем, является ли это новым подозрительным процессом
                        if (!_knownProcesses.Contains(process.Id))
                        {
                            _knownProcesses.Add(process.Id);
                            newSuspiciousProcesses.Add(suspiciousProcess);
                            
                            _logger.LogWarning("НОВЫЙ подозрительный процесс: {ProcessName} (PID: {ProcessId}) Путь: {ProcessPath} - {Reason}", 
                                process.ProcessName, process.Id, suspiciousProcess.MainModulePath ?? "Неизвестно", reason);
                        }
                        else
                        {
                            _logger.LogWarning("ИЗВЕСТНЫЙ подозрительный процесс: {ProcessName} (PID: {ProcessId}) Путь: {ProcessPath} - {Reason}", 
                                process.ProcessName, process.Id, suspiciousProcess.MainModulePath ?? "Неизвестно", reason);
                        }
                    }
                    else
                    {
                        // Отслеживаем обычные процессы (не подозрительные)
                        if (!_knownProcesses.Contains(process.Id))
                        {
                            _knownProcesses.Add(process.Id);
                            // Не логируем обычные процессы
                            // _logger.LogDebug("Новый процесс: {ProcessName} (PID: {ProcessId})", 
                            //     process.ProcessName, process.Id);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Не удалось проверить процесс {ProcessName}", process.ProcessName);
                }
            }

            // Очищаем список известных процессов от завершенных
            var currentProcessIds = processes.Select(p => p.Id).ToHashSet();
            _knownProcesses.RemoveWhere(id => !currentProcessIds.Contains(id));
            
            // Записываем результаты в лог только если найдены подозрительные процессы
            if (suspiciousProcesses.Count > 0 || newSuspiciousProcesses.Count > 0)
            {
            await WriteToLogAsync(suspiciousProcesses, newSuspiciousProcesses, totalProcessesScanned);
            }
                    
                    // Дополнительное логирование для отладки
                    if (suspiciousProcesses.Count > 0)
                    {
                        _logger.LogWarning("НАЙДЕНО ПОДОЗРИТЕЛЬНЫХ ПРОЦЕССОВ: {Count}", suspiciousProcesses.Count);
                        foreach (var proc in suspiciousProcesses)
                        {
                            _logger.LogWarning("ПОДОЗРИТЕЛЬНЫЙ ПРОЦЕСС: {ProcessName} - {Reason}", proc.ProcessName, proc.DetectionReason);
                        }
                    }
            
            // Логируем только если найдены подозрительные процессы
            if (suspiciousProcesses.Count > 0 || newSuspiciousProcesses.Count > 0)
            {
                _logger.LogWarning("Сканирование завершено. Найдено подозрительных процессов: {SuspiciousCount}, новых подозрительных: {NewSuspiciousCount}", 
                suspiciousProcesses.Count, newSuspiciousProcesses.Count);
            }
            else
            {
                _logger.LogDebug("Сканирование завершено. Подозрительные процессы не найдены.");
            }
        }
        
        private bool IsSuspiciousProcess(Process process, out string reason)
        {
            reason = "";
            
            try
            {
                string processName = process.ProcessName.ToLower();
                string processPath = GetProcessPath(process)?.ToLower() ?? "";
                
                var suspiciousPatterns = _configService.GetSuspiciousPatterns();
                
                // Проверяем имя процесса
                if (_configService.CheckProcessName)
                {
                    foreach (var pattern in suspiciousPatterns)
                    {
                        if (Regex.IsMatch(processName, pattern))
                        {
                            reason = $"Подозрительное имя процесса: {processName} (паттерн: {pattern})";
                            return true;
                        }
                    }
                }
                
                // Проверяем путь к исполняемому файлу
                if (_configService.CheckProcessPath && !string.IsNullOrEmpty(processPath))
                {
                    foreach (var pattern in suspiciousPatterns)
                    {
                        if (Regex.IsMatch(processPath, pattern))
                        {
                            reason = $"Подозрительный путь к файлу: {processPath} (паттерн: {pattern})";
                            return true;
                        }
                    }
                }
                
                // Дополнительная проверка на множественные .exe в имени
                if (_configService.CheckMultipleExeExtensions)
                {
                    var exeCount = Regex.Matches(processName, @"\.exe").Count;
                    if (exeCount > 1)
                    {
                        reason = $"Множественные .exe в имени процесса: {processName} (найдено: {exeCount})";
                        return true;
                    }
                }
                
                // Проверяем свойства файла (Type, File version, Original filename)
                if (_configService.CheckFileProperties && !string.IsNullOrEmpty(processPath))
                {
                    var fileProps = GetFileProperties(processPath);
                    if (fileProps != null)
                    {
                        // Проверяем подозрительные свойства файла
                        if (IsSuspiciousFileProperties(fileProps, out string fileReason))
                        {
                            reason = $"Подозрительные свойства файла: {fileReason}";
                            return true;
                        }
                    }
                }
                
                return false;
            }
            catch
            {
                return false;
            }
        }
        
        private string? GetProcessPath(Process process)
        {
            try
            {
                return process.MainModule?.FileName;
            }
            catch
            {
                try
                {
                    return GetProcessPathFromWMI(process.Id);
                }
                catch
                {
                    return null;
                }
            }
        }
        
        private string? GetProcessPathFromWMI(int processId)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {processId}"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        return obj["ExecutablePath"]?.ToString();
                    }
                }
            }
            catch
            {
                return null;
            }
            return null;
        }

        private FileProperties? GetFileProperties(string filePath)
        {
            try
            {
                if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                    return null;

                var fileInfo = FileVersionInfo.GetVersionInfo(filePath);
                
                return new FileProperties
                {
                    Type = GetFileType(filePath),
                    FileVersion = fileInfo.FileVersion,
                    OriginalFilename = fileInfo.OriginalFilename,
                    CompanyName = fileInfo.CompanyName,
                    ProductName = fileInfo.ProductName,
                    Description = fileInfo.FileDescription
                };
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Не удалось получить свойства файла: {FilePath}", filePath);
                return null;
            }
        }

        private string GetFileType(string filePath)
        {
            try
            {
                var extension = Path.GetExtension(filePath).ToLower();
                return extension switch
                {
                    ".exe" => "Application",
                    ".dll" => "Dynamic Link Library",
                    ".sys" => "System File",
                    ".ocx" => "ActiveX Control",
                    ".cpl" => "Control Panel",
                    ".scr" => "Screen Saver",
                    ".com" => "Command",
                    ".bat" => "Batch File",
                    ".cmd" => "Command Script",
                    ".msi" => "Windows Installer Package",
                    ".msu" => "Windows Update Package",
                    _ => "Unknown"
                };
            }
            catch
            {
                return "Unknown";
            }
        }

        private bool IsSuspiciousFileProperties(FileProperties fileProps, out string reason)
        {
            reason = "";
            
            try
            {
                // Проверяем подозрительные паттерны в свойствах файла
                var suspiciousFileVersions = _configService.GetSuspiciousFileVersions();
                var suspiciousOriginalFilenames = _configService.GetSuspiciousOriginalFilenames();
                
                // Проверяем версию файла
                if (!string.IsNullOrEmpty(fileProps.FileVersion))
                {
                    foreach (var pattern in suspiciousFileVersions)
                    {
                        if (Regex.IsMatch(fileProps.FileVersion, pattern, RegexOptions.IgnoreCase))
                        {
                            reason = $"Подозрительная версия файла: {fileProps.FileVersion} (паттерн: {pattern})";
                            return true;
                        }
                    }
                }
                
                // Проверяем оригинальное имя файла
                if (!string.IsNullOrEmpty(fileProps.OriginalFilename))
                {
                    foreach (var pattern in suspiciousOriginalFilenames)
                    {
                        if (Regex.IsMatch(fileProps.OriginalFilename, pattern, RegexOptions.IgnoreCase))
                        {
                            reason = $"Подозрительное оригинальное имя файла: {fileProps.OriginalFilename} (паттерн: {pattern})";
                            return true;
                        }
                    }
                }
                
                // Проверяем специфические комбинации свойств
                if (fileProps.Type == "Application" && 
                    !string.IsNullOrEmpty(fileProps.OriginalFilename) &&
                    fileProps.OriginalFilename.Contains("VisualStudio.Shell.Framework.dll"))
                {
                    reason = $"Подозрительное приложение с оригинальным именем VisualStudio.Shell.Framework.dll";
                    return true;
                }
                
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Ошибка при проверке свойств файла");
                return false;
            }
        }
        
        private async Task WriteToLogAsync(List<SuspiciousProcess> suspiciousProcesses, List<SuspiciousProcess> newSuspiciousProcesses, int totalProcessesScanned)
        {
            try
            {
                _logger.LogDebug("Начинаем запись в лог файл: {LogFilePath}", _logFilePath);
                
                using (var writer = new StreamWriter(_logFilePath, true, System.Text.Encoding.UTF8))
                {
                    await writer.WriteLineAsync($"=== СКАНИРОВАНИЕ ПРОЦЕССОВ - {DateTime.Now:yyyy-MM-dd HH:mm:ss} ===");
                    await writer.WriteLineAsync($"Всего просканировано процессов: {totalProcessesScanned}");
                    await writer.WriteLineAsync($"Найдено подозрительных процессов: {suspiciousProcesses.Count}");
                    await writer.WriteLineAsync($"Найдено новых подозрительных процессов: {newSuspiciousProcesses.Count}");
                    
                    if (suspiciousProcesses.Count == 0 && newSuspiciousProcesses.Count == 0)
                    {
                        await writer.WriteLineAsync("Подозрительные процессы не найдены.");
                        await writer.WriteLineAsync();
                    }
                    else
                    {
                        await writer.WriteLineAsync($"НАЙДЕНО ПОДОЗРИТЕЛЬНЫХ ПРОЦЕССОВ: {suspiciousProcesses.Count}");
                        await writer.WriteLineAsync($"НОВЫХ ПОДОЗРИТЕЛЬНЫХ ПРОЦЕССОВ: {newSuspiciousProcesses.Count}");
                        await writer.WriteLineAsync();
                    }
                    
                    await writer.WriteLineAsync();
                    
                    // Записываем подозрительные процессы
                    if (suspiciousProcesses.Count > 0)
                    {
                        await writer.WriteLineAsync("=== ПОДОЗРИТЕЛЬНЫЕ ПРОЦЕССЫ ===");
                        foreach (var process in suspiciousProcesses)
                        {
                            await writer.WriteLineAsync($"ПРОЦЕСС: {process.ProcessName}");
                            await writer.WriteLineAsync($"PID: {process.ProcessId}");
                            await writer.WriteLineAsync($"Путь: {process.MainModulePath ?? "Неизвестно"}");
                            await writer.WriteLineAsync($"Причина: {process.DetectionReason}");
                            await writer.WriteLineAsync($"Время обнаружения: {process.DetectionTime:yyyy-MM-dd HH:mm:ss}");
                            
                            // Записываем свойства файла если они есть
                            if (process.FileProperties != null)
                            {
                                await writer.WriteLineAsync($"Свойства файла:");
                                await writer.WriteLineAsync($"  Тип: {process.FileProperties.Type ?? "Неизвестно"}");
                                await writer.WriteLineAsync($"  Версия файла: {process.FileProperties.FileVersion ?? "Неизвестно"}");
                                await writer.WriteLineAsync($"  Оригинальное имя: {process.FileProperties.OriginalFilename ?? "Неизвестно"}");
                                await writer.WriteLineAsync($"  Компания: {process.FileProperties.CompanyName ?? "Неизвестно"}");
                                await writer.WriteLineAsync($"  Продукт: {process.FileProperties.ProductName ?? "Неизвестно"}");
                                await writer.WriteLineAsync($"  Описание: {process.FileProperties.Description ?? "Неизвестно"}");
                            }
                            
                            await writer.WriteLineAsync(new string('-', 50));
                        }
                        await writer.WriteLineAsync();
                    }
                    
                    // Записываем новые подозрительные процессы (если включено в настройках)
                    if (_configService.LogNewSuspiciousProcesses && newSuspiciousProcesses.Count > 0)
                    {
                        await writer.WriteLineAsync("=== НОВЫЕ ПОДОЗРИТЕЛЬНЫЕ ПРОЦЕССЫ ===");
                        foreach (var process in newSuspiciousProcesses)
                        {
                            await writer.WriteLineAsync($"ПРОЦЕСС: {process.ProcessName}");
                            await writer.WriteLineAsync($"PID: {process.ProcessId}");
                            await writer.WriteLineAsync($"Путь: {process.MainModulePath ?? "Неизвестно"}");
                            await writer.WriteLineAsync($"Причина: {process.DetectionReason}");
                            await writer.WriteLineAsync($"Время обнаружения: {process.DetectionTime:yyyy-MM-dd HH:mm:ss}");
                            await writer.WriteLineAsync(new string('-', 30));
                        }
                        await writer.WriteLineAsync();
                    }
                    
                    // Дополнительно записываем все подозрительные процессы, если есть новые
                    if (newSuspiciousProcesses.Count > 0)
                    {
                        await writer.WriteLineAsync("=== ДЕТЕКТИРОВАННЫЕ ПОДОЗРИТЕЛЬНЫЕ ПРОЦЕССЫ ===");
                        foreach (var process in suspiciousProcesses)
                        {
                            await writer.WriteLineAsync($"ПРОЦЕСС: {process.ProcessName}");
                            await writer.WriteLineAsync($"PID: {process.ProcessId}");
                            await writer.WriteLineAsync($"Путь: {process.MainModulePath ?? "Неизвестно"}");
                            await writer.WriteLineAsync($"Причина: {process.DetectionReason}");
                            await writer.WriteLineAsync($"Время обнаружения: {process.DetectionTime:yyyy-MM-dd HH:mm:ss}");
                            await writer.WriteLineAsync(new string('-', 50));
                        }
                        await writer.WriteLineAsync();
                    }
                    
                    await writer.WriteLineAsync();
                }
                
                _logger.LogInformation("Результаты записаны в файл: {LogFilePath}", _logFilePath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ошибка при записи в лог");
            }
        }
    }

    // Сервис для работы с конфигурацией
    public class ConfigurationService
    {
        private readonly IConfiguration _configuration;

        public ConfigurationService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public int GetScanInterval()
        {
            return _configuration.GetValue<int>("MonitoringSettings:ScanIntervalSeconds", 30);
        }

        public string[] GetSuspiciousPatterns()
        {
            return _configuration.GetSection("DetectionSettings:SuspiciousPatterns").Get<string[]>() ?? 
                   new[] { @"\.exe\.exe$", @"\.exe\.exe\.exe$", @"\.exe\.exe\.exe\.exe$", @"\.exe\.exe\.exe\.exe\.exe$" };
        }

        public bool CheckProcessName => _configuration.GetValue<bool>("DetectionSettings:CheckProcessName", true);
        public bool CheckProcessPath => _configuration.GetValue<bool>("DetectionSettings:CheckProcessPath", true);
        public bool CheckMultipleExeExtensions => _configuration.GetValue<bool>("DetectionSettings:CheckMultipleExeExtensions", true);
        public bool CheckFileProperties => _configuration.GetValue<bool>("DetectionSettings:CheckFileProperties", true);
        public bool LogNewSuspiciousProcesses => _configuration.GetValue<bool>("MonitoringSettings:LogNewSuspiciousProcesses", true);

        public string[] GetSuspiciousFileVersions()
        {
            return _configuration.GetSection("DetectionSettings:SuspiciousFileVersions").Get<string[]>() ?? 
                   new[] { @"16\.10\.31418\.88", @"16\.\d+\.\d+\.\d+" };
        }

        public string[] GetSuspiciousOriginalFilenames()
        {
            return _configuration.GetSection("DetectionSettings:SuspiciousOriginalFilenames").Get<string[]>() ?? 
                   new[] { @"VisualStudio\.Shell\.Framework\.dll", @"Microsoft\.VisualStudio\.Shell\.Framework\.dll" };
        }
        
        // Настройки безопасности
        public bool AutoKillSuspiciousProcesses => _configuration.GetValue<bool>("SecuritySettings:AutoKillSuspiciousProcesses", false);
        public bool AutoDeleteSuspiciousFiles => _configuration.GetValue<bool>("SecuritySettings:AutoDeleteSuspiciousFiles", false);
        public bool RequireConfirmation => _configuration.GetValue<bool>("SecuritySettings:RequireConfirmation", true);
        public bool BackupBeforeDelete => _configuration.GetValue<bool>("SecuritySettings:BackupBeforeDelete", true);
        public long MaxFileSizeToDelete => _configuration.GetValue<long>("SecuritySettings:MaxFileSizeToDelete", 104857600); // 100MB
    }

    // Сервис для управления безопасностью
    public class SecurityService
    {
        private readonly ILogger<SecurityService> _logger;
        private readonly ConfigurationService _configService;
        private readonly string _logFilePath;
        private readonly string _backupDirectory;
        private readonly string _deleteLogFilePath;

        public SecurityService(ILogger<SecurityService> logger, ConfigurationService configService)
        {
            _logger = logger;
            _configService = configService;
            _logFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "suspicious_processes.log");
            _backupDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "backups");
            _deleteLogFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "deleted_files.log");
            
            // Логируем настройки для отладки
            _logger.LogInformation("Настройки безопасности: AutoDeleteSuspiciousFiles = {AutoDelete}, BackupBeforeDelete = {Backup}", 
                _configService.AutoDeleteSuspiciousFiles, _configService.BackupBeforeDelete);
            
            // Создаем папку для бэкапов если нужно
            if (_configService.BackupBeforeDelete && !Directory.Exists(_backupDirectory))
            {
                Directory.CreateDirectory(_backupDirectory);
            }
        }

        public async Task<List<SecurityAction>> KillAndDeleteSuspiciousProcessesAsync()
        {
            var actions = new List<SecurityAction>();
            
            _logger.LogInformation("Начинаем поиск и удаление подозрительных процессов...");
            _logger.LogInformation("Настройки: AutoDeleteSuspiciousFiles = {AutoDelete}, AutoKillSuspiciousProcesses = {AutoKill}", 
                _configService.AutoDeleteSuspiciousFiles, _configService.AutoKillSuspiciousProcesses);

            // Создаем заголовок в логе удалений
            await InitializeDeleteLogAsync();

            // Сначала пытаемся прочитать процессы из лог файла
            var suspiciousProcessesFromLog = await ReadSuspiciousProcessesFromLogAsync();
            
            if (suspiciousProcessesFromLog.Count > 0)
            {
                _logger.LogInformation("Найдено {Count} подозрительных процессов в лог файле", suspiciousProcessesFromLog.Count);
                
                foreach (var logProcess in suspiciousProcessesFromLog)
                {
                    var action = new SecurityAction
                    {
                        ProcessName = logProcess.ProcessName,
                        ProcessId = logProcess.ProcessId,
                        FilePath = logProcess.MainModulePath,
                        DetectionReason = logProcess.DetectionReason,
                        ActionTime = DateTime.Now
                    };

                    // Пытаемся найти процесс по PID
                    Process? process = null;
                    try
                    {
                        process = Process.GetProcessById(logProcess.ProcessId);
                        
                        // Не пытаемся завершить сам себя
                        if (process.Id == Environment.ProcessId)
                        {
                            _logger.LogWarning("Пропускаем завершение собственного процесса (PID: {ProcessId})", process.Id);
                            process = null;
                        }
                    }
                    catch
                    {
                        _logger.LogWarning("Процесс {ProcessName} (PID: {ProcessId}) не найден, возможно уже завершен", 
                            logProcess.ProcessName, logProcess.ProcessId);
                    }

                    if (process != null)
                    {
                        // Завершаем процесс
                        if (await KillProcessAsync(process, action))
                        {
                            action.ProcessKilled = true;
                            
                            // Удаляем файл если есть путь и настройка включена
                            if (!string.IsNullOrEmpty(logProcess.MainModulePath) && _configService.AutoDeleteSuspiciousFiles)
                            {
                                if (await DeleteFileAsync(logProcess.MainModulePath, action))
                                {
                                    action.FileDeleted = true;
                                }
                            }
                        }
                    }
                    else
                    {
                        // Процесс не найден, но можем попробовать удалить файл
                        // Принудительно включаем удаление файлов для команды delete
                        if (!string.IsNullOrEmpty(logProcess.MainModulePath) && (_configService.AutoDeleteSuspiciousFiles || true))
                        {
                            if (await DeleteFileAsync(logProcess.MainModulePath, action))
                            {
                                action.FileDeleted = true;
                                action.ErrorMessage = "Процесс не найден, но файл удален";
                            }
                            else
                            {
                                // Попробуем найти файл по имени процесса в различных директориях
                                var fileName = $"{logProcess.ProcessName}";
                                var currentDir = AppDomain.CurrentDomain.BaseDirectory;
                                var possiblePaths = new List<string>
                                {
                                    Path.Combine(currentDir, fileName),
                                    Path.Combine(currentDir, $"{fileName}.exe"),
                                    Path.Combine(currentDir, $"{fileName}.exe.exe"),
                                    Path.Combine(currentDir, $"{fileName}.exe.exe.exe")
                                };
                                
                                // Добавляем поиск только в безопасных директориях
                                var safeDirs = new[]
                                {
                                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                                    Path.GetTempPath()
                                };
                                
                                foreach (var dir in safeDirs)
                                {
                                    if (Directory.Exists(dir))
                                    {
                                        possiblePaths.Add(Path.Combine(dir, fileName));
                                        possiblePaths.Add(Path.Combine(dir, $"{fileName}.exe"));
                                        possiblePaths.Add(Path.Combine(dir, $"{fileName}.exe.exe"));
                                        possiblePaths.Add(Path.Combine(dir, $"{fileName}.exe.exe.exe"));
                                    }
                                }
                                
                                foreach (var path in possiblePaths)
                                {
                                    if (File.Exists(path) && HasSuspiciousFileName(path))
                                    {
                                        _logger.LogInformation("Найден подозрительный файл по альтернативному пути: {FilePath}", path);
                                        if (await DeleteFileAsync(path, action))
                                        {
                                            action.FileDeleted = true;
                                            action.ErrorMessage = $"Процесс не найден, но файл удален по пути: {path}";
                                            break;
                                        }
                                    }
                                }
                                
                                // Если файл все еще не найден, попробуем поиск по всему диску C:
                                if (!action.FileDeleted)
                                {
                                    _logger.LogInformation("Ищем файл {FileName} по всему диску C:", fileName);
                                    var foundFiles = await SearchFileOnDiskAsync(fileName, "C:\\");
                                    if (foundFiles.Count > 0)
                                    {
                                        _logger.LogInformation("Найдено {Count} файлов с именем {FileName}", foundFiles.Count, fileName);
                                        foreach (var foundFile in foundFiles)
                                        {
                                            _logger.LogInformation("Удаляем найденный файл: {FilePath}", foundFile);
                                            if (await DeleteFileAsync(foundFile, action))
                                            {
                                                action.FileDeleted = true;
                                                action.ErrorMessage = $"Процесс не найден, но файл удален с диска: {foundFile}";
                                                break;
                                            }
                                        }
                                    }
                                    
                                    if (!action.FileDeleted)
                                    {
                                        action.ErrorMessage = "Процесс не найден, файл также не найден";
                                    }
                                }
                            }
                        }
                        else
                        {
                            action.ErrorMessage = $"Процесс не найден, автоудаление файлов отключено (AutoDeleteSuspiciousFiles = {_configService.AutoDeleteSuspiciousFiles})";
                        }
                    }

                    actions.Add(action);
                }
            }
            else
            {
                _logger.LogInformation("Подозрительные процессы в лог файле не найдены, выполняем поиск в системе...");
                
                // Если в логе ничего нет, ищем в системе
                var processes = Process.GetProcesses();
                
                foreach (var process in processes)
                {
                    try
                    {
                        // Не пытаемся завершить сам себя
                        if (process.Id == Environment.ProcessId)
                        {
                            _logger.LogWarning("Пропускаем собственный процесс при сканировании (PID: {ProcessId})", process.Id);
                            continue;
                        }
                        
                        if (IsSuspiciousProcess(process, out string reason))
                        {
                            var processPath = GetProcessPath(process);
                            var action = new SecurityAction
                            {
                                ProcessName = process.ProcessName,
                                ProcessId = process.Id,
                                FilePath = processPath,
                                DetectionReason = reason,
                                ActionTime = DateTime.Now
                            };

                            // Завершаем процесс
                            if (await KillProcessAsync(process, action))
                            {
                                action.ProcessKilled = true;
                                
                                // Удаляем файл если есть путь и настройка включена
                                if (!string.IsNullOrEmpty(processPath) && _configService.AutoDeleteSuspiciousFiles)
                                {
                                    if (await DeleteFileAsync(processPath, action))
                                    {
                                        action.FileDeleted = true;
                                    }
                                }
                            }

                            actions.Add(action);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Ошибка при обработке процесса {ProcessName}", process.ProcessName);
                    }
                }
            }

            // Записываем результаты в лог
            if (actions.Count > 0)
            {
                await WriteSecurityActionsToLogAsync(actions);
            }

            _logger.LogInformation("Обработано подозрительных процессов: {Count}", actions.Count);
            
            // Записываем итоговую статистику в лог удалений
            await WriteDeleteLogSummaryAsync(actions);
            
            return actions;
        }

        private bool IsSuspiciousProcess(Process process, out string reason)
        {
            reason = "";
            
            try
            {
                string processName = process.ProcessName.ToLower();
                string processPath = GetProcessPath(process)?.ToLower() ?? "";
                
                var suspiciousPatterns = _configService.GetSuspiciousPatterns();
                
                // Проверяем имя процесса
                if (_configService.CheckProcessName)
                {
                    foreach (var pattern in suspiciousPatterns)
                    {
                        if (Regex.IsMatch(processName, pattern))
                        {
                            reason = $"Подозрительное имя процесса: {processName} (паттерн: {pattern})";
                            return true;
                        }
                    }
                }
                
                // Проверяем путь к исполняемому файлу
                if (_configService.CheckProcessPath && !string.IsNullOrEmpty(processPath))
                {
                    foreach (var pattern in suspiciousPatterns)
                    {
                        if (Regex.IsMatch(processPath, pattern))
                        {
                            reason = $"Подозрительный путь к файлу: {processPath} (паттерн: {pattern})";
                            return true;
                        }
                    }
                }
                
                // Дополнительная проверка на множественные .exe в имени
                if (_configService.CheckMultipleExeExtensions)
                {
                    var exeCount = Regex.Matches(processName, @"\.exe").Count;
                    if (exeCount > 1)
                    {
                        reason = $"Множественные .exe в имени процесса: {processName} (найдено: {exeCount})";
                        return true;
                    }
                }
                
                return false;
            }
            catch
            {
                return false;
            }
        }

        private string? GetProcessPath(Process process)
        {
            try
            {
                return process.MainModule?.FileName;
            }
            catch
            {
                try
                {
                    return GetProcessPathFromWMI(process.Id);
                }
                catch
                {
                    return null;
                }
            }
        }

        private string? GetProcessPathFromWMI(int processId)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {processId}"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        return obj["ExecutablePath"]?.ToString();
                    }
                }
            }
            catch
            {
                return null;
            }
            return null;
        }

        private Task<bool> KillProcessAsync(Process process, SecurityAction action)
        {
            try
            {
                _logger.LogWarning("Завершаем подозрительный процесс: {ProcessName} (PID: {ProcessId})", 
                    process.ProcessName, process.Id);
                
                process.Kill();
                process.WaitForExit(5000); // Ждем 5 секунд
                
                _logger.LogInformation("Процесс {ProcessName} (PID: {ProcessId}) успешно завершен", 
                    process.ProcessName, process.Id);
                
                return Task.FromResult(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Не удалось завершить процесс {ProcessName} (PID: {ProcessId})", 
                    process.ProcessName, process.Id);
                action.ErrorMessage = ex.Message;
                return Task.FromResult(false);
            }
        }

        private async Task<bool> DeleteFileAsync(string filePath, SecurityAction action)
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    _logger.LogWarning("Файл не найден: {FilePath}", filePath);
                    return false;
                }

                // Проверяем, является ли файл системным - не удаляем системные файлы!
                if (IsSystemFile(filePath))
                {
                    _logger.LogWarning("Пропускаем удаление системного файла: {FilePath}", filePath);
                    action.ErrorMessage = "Системный файл - удаление запрещено";
                    await LogDeletedFileAsync(filePath, "ПРОПУЩЕН - Системный файл");
                    return false;
                }

                // Проверяем паттерн имени файла - удаляем только файлы с подозрительными паттернами
                if (!HasSuspiciousFileName(filePath))
                {
                    _logger.LogWarning("Пропускаем удаление обычного .exe файла: {FilePath}", filePath);
                    action.ErrorMessage = "Обычный .exe файл - удаление запрещено";
                    await LogDeletedFileAsync(filePath, "ПРОПУЩЕН - Обычный .exe файл");
                    return false;
                }

                var fileInfo = new FileInfo(filePath);
                
                // Проверяем размер файла
                if (fileInfo.Length > _configService.MaxFileSizeToDelete)
                {
                    _logger.LogWarning("Файл слишком большой для удаления: {FilePath} ({Size} bytes)", 
                        filePath, fileInfo.Length);
                    action.ErrorMessage = $"Файл слишком большой: {fileInfo.Length} bytes";
                    return false;
                }

                // Создаем бэкап если нужно
                if (_configService.BackupBeforeDelete)
                {
                    await CreateBackupAsync(filePath);
                }

                // Пытаемся удалить файл с несколькими попытками
                bool deleted = false;
                int attempts = 0;
                const int maxAttempts = 3;
                
                while (!deleted && attempts < maxAttempts)
                {
                    attempts++;
                    try
                    {
                        // Сначала пытаемся снять атрибуты только для чтения
                        if (fileInfo.IsReadOnly)
                        {
                            fileInfo.IsReadOnly = false;
                        }
                        
                        // Снимаем все возможные атрибуты файла
                        var attributes = File.GetAttributes(filePath);
                        if ((attributes & FileAttributes.ReadOnly) == FileAttributes.ReadOnly ||
                            (attributes & FileAttributes.Hidden) == FileAttributes.Hidden ||
                            (attributes & FileAttributes.System) == FileAttributes.System)
                        {
                            File.SetAttributes(filePath, FileAttributes.Normal);
                            _logger.LogDebug("Сняты атрибуты файла: {FilePath}", filePath);
                        }
                        
                        File.Delete(filePath);
                        deleted = true;
                _logger.LogInformation("Файл успешно удален: {FilePath}", filePath);
                        
                        // Записываем в лог удалений
                        await LogDeletedFileAsync(filePath, "Успешно удален");
                    }
                    catch (IOException ex) when (ex.Message.Contains("being used by another process"))
                    {
                        _logger.LogWarning("Файл используется другим процессом, попытка {Attempt}/{MaxAttempts}: {FilePath}", 
                            attempts, maxAttempts, filePath);
                        
                        if (attempts < maxAttempts)
                        {
                            // Ждем немного перед следующей попыткой
                            await Task.Delay(1000 * attempts);
                        }
                        else
                        {
                            _logger.LogError("Не удалось удалить файл после {MaxAttempts} попыток: {FilePath}", 
                                maxAttempts, filePath);
                            
                            // Попробуем запланировать удаление при перезагрузке
                            try
                            {
                                await ScheduleFileDeletionOnReboot(filePath);
                                action.ErrorMessage = $"Файл заблокирован, запланировано удаление при перезагрузке";
                                
                                // Записываем в лог удалений
                                await LogDeletedFileAsync(filePath, "Запланировано удаление при перезагрузке");
                            }
                            catch (Exception scheduleEx)
                            {
                                _logger.LogWarning(scheduleEx, "Не удалось запланировать удаление файла при перезагрузке: {FilePath}", filePath);
                                action.ErrorMessage = $"Файл заблокирован другим процессом после {maxAttempts} попыток";
                            }
                        }
                    }
                    catch (UnauthorizedAccessException ex)
                    {
                        _logger.LogError("Нет прав доступа для удаления файла: {FilePath}. Ошибка: {Error}", 
                            filePath, ex.Message);
                        action.ErrorMessage = $"Нет прав доступа: {ex.Message}";
                        break;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Неожиданная ошибка при удалении файла: {FilePath}", filePath);
                        action.ErrorMessage = ex.Message;
                        break;
                    }
                }
                
                return deleted;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Не удалось удалить файл: {FilePath}", filePath);
                action.ErrorMessage = ex.Message;
                return false;
            }
        }

        private bool HasSuspiciousFileName(string filePath)
        {
            try
            {
                var fileName = Path.GetFileName(filePath).ToLower();
                
                // Получаем паттерны из конфигурации
                var suspiciousPatterns = _configService.GetSuspiciousPatterns();
                
                // Проверяем каждый паттерн
                foreach (var pattern in suspiciousPatterns)
                {
                    if (Regex.IsMatch(fileName, pattern))
                    {
                        _logger.LogDebug("Файл соответствует подозрительному паттерну '{Pattern}': {FileName}", pattern, fileName);
                        return true;
                    }
                }
                
                // Дополнительная проверка на множественные .exe в имени
                if (_configService.CheckMultipleExeExtensions)
                {
                    var exeCount = Regex.Matches(fileName, @"\.exe").Count;
                    if (exeCount > 1)
                    {
                        _logger.LogDebug("Файл содержит множественные .exe ({Count}): {FileName}", exeCount, fileName);
                        return true;
                    }
                }
                
                _logger.LogDebug("Файл не соответствует подозрительным паттернам: {FileName}", fileName);
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Ошибка при проверке паттерна имени файла: {FilePath}", filePath);
                // В случае ошибки считаем файл безопасным
                return false;
            }
        }

        private bool IsSystemFile(string filePath)
        {
            try
            {
                var fullPath = Path.GetFullPath(filePath).ToLower();
                
                // Список защищенных системных директорий
                var protectedDirectories = new[]
                {
                    @"c:\windows\system32",
                    @"c:\windows\syswow64", 
                    @"c:\windows\system",
                    @"c:\windows\",
                    @"c:\program files\",
                    @"c:\program files (x86)\",
                    @"c:\programdata\",
                    @"c:\users\all users\",
                    @"c:\windows\winsxs\",
                    @"c:\windows\servicing\",
                    @"c:\windows\assembly\",
                    @"c:\windows\microsoft.net\",
                    @"c:\windows\servicing\",
                    @"c:\windows\boot\",
                    @"c:\windows\catroot\",
                    @"c:\windows\config\",
                    @"c:\windows\cursors\",
                    @"c:\windows\debug\",
                    @"c:\windows\diagnostics\",
                    @"c:\windows\downlevel\",
                    @"c:\windows\en-us\",
                    @"c:\windows\fonts\",
                    @"c:\windows\globalization\",
                    @"c:\windows\help\",
                    @"c:\windows\ime\",
                    @"c:\windows\inf\",
                    @"c:\windows\inputmethod\",
                    @"c:\windows\lsasetup\",
                    @"c:\windows\media\",
                    @"c:\windows\msagent\",
                    @"c:\windows\mui\",
                    @"c:\windows\oobe\",
                    @"c:\windows\performance\",
                    @"c:\windows\policydefinitions\",
                    @"c:\windows\prefetch\",
                    @"c:\windows\provisioning\",
                    @"c:\windows\registration\",
                    @"c:\windows\resources\",
                    @"c:\windows\security\",
                    @"c:\windows\servicing\",
                    @"c:\windows\setup\",
                    @"c:\windows\skins\",
                    @"c:\windows\software distribution\",
                    @"c:\windows\speech\",
                    @"c:\windows\systemapps\",
                    @"c:\windows\systemresources\",
                    @"c:\windows\winsxs\",
                    @"c:\windows\web\"
                };

                // Проверяем, находится ли файл в защищенной директории
                foreach (var protectedDir in protectedDirectories)
                {
                    if (fullPath.StartsWith(protectedDir))
                    {
                        return true;
                    }
                }

                // Дополнительная проверка на системные атрибуты файла
                try
                {
                    var attributes = File.GetAttributes(filePath);
                    if ((attributes & FileAttributes.System) == FileAttributes.System ||
                        (attributes & FileAttributes.Hidden) == FileAttributes.Hidden)
                    {
                        // Проверяем, является ли это действительно системным файлом
                        // Файлы с системными атрибутами в безопасных директориях можем удалять
                        var safeDirectories = new[]
                        {
                            @"c:\users\",
                            @"c:\temp\",
                            @"c:\windows\temp\",
                            Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)?.ToLower() + @"\"
                        };

                        foreach (var safeDir in safeDirectories)
                        {
                            if (!string.IsNullOrEmpty(safeDir) && fullPath.StartsWith(safeDir))
                            {
                                return false; // Файл в безопасной директории
                            }
                        }

                        return true; // Системный файл в защищенной директории
                    }
                }
                catch
                {
                    // Если не можем получить атрибуты, считаем файл потенциально опасным
                    return true;
                }

                return false;
            }
            catch
            {
                // В случае ошибки считаем файл потенциально системным для безопасности
                return true;
            }
        }

        private async Task InitializeDeleteLogAsync()
        {
            try
            {
                var header = $"{Environment.NewLine}" +
                           $"========================================{Environment.NewLine}" +
                           $"ЛОГ УДАЛЕНИЯ ФАЙЛОВ - {DateTime.Now:yyyy-MM-dd HH:mm:ss}{Environment.NewLine}" +
                           $"========================================{Environment.NewLine}" +
                           $"Формат: Время | Статус | Путь к файлу{Environment.NewLine}" +
                           $"========================================{Environment.NewLine}";
                
                await File.AppendAllTextAsync(_deleteLogFilePath, header);
                
                _logger.LogInformation("Инициализирован лог удалений: {DeleteLogPath}", _deleteLogFilePath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ошибка при инициализации лога удалений");
            }
        }

        private async Task WriteDeleteLogSummaryAsync(List<SecurityAction> actions)
        {
            try
            {
                var deletedCount = actions.Count(a => a.FileDeleted);
                var skippedCount = actions.Count(a => a.ErrorMessage?.Contains("ПРОПУЩЕН") == true);
                var scheduledCount = actions.Count(a => a.ErrorMessage?.Contains("перезагрузке") == true);
                var failedCount = actions.Count(a => !string.IsNullOrEmpty(a.ErrorMessage) && 
                                                   !a.ErrorMessage.Contains("ПРОПУЩЕН") && 
                                                   !a.ErrorMessage.Contains("перезагрузке"));

                var summary = $"{Environment.NewLine}" +
                            $"========================================{Environment.NewLine}" +
                            $"ИТОГОВАЯ СТАТИСТИКА УДАЛЕНИЯ{Environment.NewLine}" +
                            $"========================================{Environment.NewLine}" +
                            $"Всего обработано процессов: {actions.Count}{Environment.NewLine}" +
                            $"Успешно удалено файлов: {deletedCount}{Environment.NewLine}" +
                            $"Пропущено файлов: {skippedCount}{Environment.NewLine}" +
                            $"Запланировано на перезагрузку: {scheduledCount}{Environment.NewLine}" +
                            $"Не удалось удалить: {failedCount}{Environment.NewLine}" +
                            $"========================================{Environment.NewLine}" +
                            $"Завершено: {DateTime.Now:yyyy-MM-dd HH:mm:ss}{Environment.NewLine}" +
                            $"========================================{Environment.NewLine}{Environment.NewLine}";

                await File.AppendAllTextAsync(_deleteLogFilePath, summary);
                
                _logger.LogInformation("Записана итоговая статистика в лог удалений");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ошибка при записи итоговой статистики в лог удалений");
            }
        }

        private async Task LogDeletedFileAsync(string filePath, string status)
        {
            try
            {
                var logEntry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} | {status} | {filePath}";
                
                await File.AppendAllTextAsync(_deleteLogFilePath, logEntry + Environment.NewLine);
                
                _logger.LogDebug("Записано в лог удалений: {LogEntry}", logEntry);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ошибка при записи в лог удалений: {FilePath}", filePath);
            }
        }

        private async Task ScheduleFileDeletionOnReboot(string filePath)
        {
            try
            {
                // Используем MoveFileEx с MOVEFILE_DELAY_UNTIL_REBOOT для планирования удаления при перезагрузке
                var result = await Task.Run(() => 
                {
                    return NativeMethods.MoveFileEx(filePath, null, 
                        NativeMethods.MoveFileFlags.MOVEFILE_DELAY_UNTIL_REBOOT | 
                        NativeMethods.MoveFileFlags.MOVEFILE_REPLACE_EXISTING);
                });
                
                if (result)
                {
                    _logger.LogInformation("Файл запланирован для удаления при перезагрузке: {FilePath}", filePath);
                }
                else
                {
                    throw new InvalidOperationException($"Не удалось запланировать удаление файла: {filePath}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ошибка при планировании удаления файла при перезагрузке: {FilePath}", filePath);
                throw;
            }
        }

        private async Task CreateBackupAsync(string filePath)
        {
            try
            {
                var fileName = Path.GetFileName(filePath);
                var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                var backupFileName = $"{Path.GetFileNameWithoutExtension(fileName)}_{timestamp}{Path.GetExtension(fileName)}";
                var backupPath = Path.Combine(_backupDirectory, backupFileName);
                
                // Если файл бэкапа уже существует, добавляем уникальный суффикс
                int counter = 1;
                while (File.Exists(backupPath))
                {
                    var baseName = Path.GetFileNameWithoutExtension(backupFileName);
                    var extension = Path.GetExtension(backupFileName);
                    backupFileName = $"{baseName}_{counter:D3}{extension}";
                    backupPath = Path.Combine(_backupDirectory, backupFileName);
                    counter++;
                }
                
                // Создаем бэкап с обработкой ошибок
                try
                {
                    await Task.Run(() => File.Copy(filePath, backupPath));
                _logger.LogInformation("Создан бэкап файла: {BackupPath}", backupPath);
                }
                catch (UnauthorizedAccessException ex)
                {
                    _logger.LogWarning("Нет прав для создания бэкапа файла {FilePath}: {Error}", filePath, ex.Message);
                    // Не прерываем операцию удаления из-за ошибки бэкапа
                }
                catch (IOException ex) when (ex.Message.Contains("being used by another process"))
                {
                    _logger.LogWarning("Файл заблокирован, пропускаем создание бэкапа: {FilePath}", filePath);
                    // Не прерываем операцию удаления из-за ошибки бэкапа
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Не удалось создать бэкап файла: {FilePath}", filePath);
                // Не прерываем операцию удаления из-за ошибки бэкапа
            }
        }

        private Task<List<string>> SearchFileOnDiskAsync(string fileName, string rootPath)
        {
            var foundFiles = new List<string>();
            
            try
            {
                // Ограничиваем поиск только безопасными директориями
                var searchDirs = new[]
                {
                    Path.Combine(rootPath, "Users"),
                    Path.Combine(rootPath, "Temp"),
                    Path.Combine(rootPath, "Windows", "Temp"),
                    Path.Combine(rootPath, "ProgramData", "Temp")
                };

                foreach (var dir in searchDirs)
                {
                    if (Directory.Exists(dir))
                    {
                        try
                        {
                            // Ищем файлы с различными расширениями
                            var patterns = new[] { fileName, $"{fileName}.exe", $"{fileName}.exe.exe", $"{fileName}.exe.exe.exe" };
                            
                            foreach (var pattern in patterns)
                            {
                                var files = Directory.GetFiles(dir, pattern, SearchOption.TopDirectoryOnly);
                                
                                // Фильтруем только файлы с подозрительными именами
                                foreach (var file in files)
                                {
                                    if (HasSuspiciousFileName(file))
                                    {
                                        foundFiles.Add(file);
                                    }
                                }
                                
                                // Также ищем в поддиректориях (но ограниченно для производительности)
                                try
                                {
                                    var subDirs = Directory.GetDirectories(dir).Take(10); // Ограничиваем количество поддиректорий
                                    foreach (var subDir in subDirs)
                                    {
                                        var subFiles = Directory.GetFiles(subDir, pattern, SearchOption.TopDirectoryOnly);
                                        
                                        // Фильтруем только файлы с подозрительными именами
                                        foreach (var file in subFiles)
                                        {
                                            if (HasSuspiciousFileName(file))
                                            {
                                                foundFiles.Add(file);
                                            }
                                        }
                                    }
                                }
                                catch
                                {
                                    // Игнорируем ошибки доступа к поддиректориям
                                }
                            }
                        }
                        catch
                        {
                            // Игнорируем ошибки доступа к директориям
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ошибка при поиске файла {FileName} на диске {RootPath}", fileName, rootPath);
            }
            
            return Task.FromResult(foundFiles.Distinct().ToList());
        }

        private async Task<List<SuspiciousProcess>> ReadSuspiciousProcessesFromLogAsync()
        {
            var suspiciousProcesses = new List<SuspiciousProcess>();
            
            try
            {
                if (!File.Exists(_logFilePath))
                {
                    _logger.LogInformation("Лог файл не найден: {LogFilePath}", _logFilePath);
                    return suspiciousProcesses;
                }

                _logger.LogInformation("Читаем подозрительные процессы из лог файла: {LogFilePath}", _logFilePath);
                
                var lines = await File.ReadAllLinesAsync(_logFilePath);
                var currentProcess = new SuspiciousProcess();
                bool inSuspiciousSection = false;
                
                foreach (var line in lines)
                {
                    var trimmedLine = line.Trim();
                    
                    // Начало секции подозрительных процессов
                    if (trimmedLine.Contains("=== ПОДОЗРИТЕЛЬНЫЕ ПРОЦЕССЫ ==="))
                    {
                        inSuspiciousSection = true;
                        continue;
                    }
                    
                    // Конец секции подозрительных процессов
                    if (trimmedLine.StartsWith("===") && !trimmedLine.Contains("ПОДОЗРИТЕЛЬНЫЕ ПРОЦЕССЫ"))
                    {
                        inSuspiciousSection = false;
                        continue;
                    }
                    
                    // Пропускаем разделители
                    if (trimmedLine.StartsWith("-") || string.IsNullOrEmpty(trimmedLine))
                    {
                        if (currentProcess.ProcessName != "" && inSuspiciousSection)
                        {
                            suspiciousProcesses.Add(currentProcess);
                            currentProcess = new SuspiciousProcess();
                        }
                        continue;
                    }
                    
                    if (inSuspiciousSection)
                    {
                        if (trimmedLine.StartsWith("ПРОЦЕСС:"))
                        {
                            currentProcess.ProcessName = trimmedLine.Substring(8).Trim();
                        }
                        else if (trimmedLine.StartsWith("PID:"))
                        {
                            if (int.TryParse(trimmedLine.Substring(4).Trim(), out int pid))
                            {
                                currentProcess.ProcessId = pid;
                            }
                        }
                        else if (trimmedLine.StartsWith("Путь:"))
                        {
                            var path = trimmedLine.Substring(5).Trim();
                            if (path != "Неизвестно")
                            {
                                currentProcess.MainModulePath = path;
                            }
                        }
                        else if (trimmedLine.StartsWith("Причина:"))
                        {
                            currentProcess.DetectionReason = trimmedLine.Substring(8).Trim();
                        }
                        else if (trimmedLine.StartsWith("Время обнаружения:"))
                        {
                            if (DateTime.TryParse(trimmedLine.Substring(18).Trim(), out DateTime detectionTime))
                            {
                                currentProcess.DetectionTime = detectionTime;
                            }
                        }
                    }
                }
                
                // Добавляем последний процесс, если он есть
                if (currentProcess.ProcessName != "" && inSuspiciousSection)
                {
                    suspiciousProcesses.Add(currentProcess);
                }
                
                _logger.LogInformation("Прочитано {Count} подозрительных процессов из лог файла", suspiciousProcesses.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ошибка при чтении лог файла: {LogFilePath}", _logFilePath);
            }
            
            return suspiciousProcesses;
        }

        private async Task WriteSecurityActionsToLogAsync(List<SecurityAction> actions)
        {
            try
            {
                using (var writer = new StreamWriter(_logFilePath, true, System.Text.Encoding.UTF8))
                {
                    await writer.WriteLineAsync($"=== ОПЕРАЦИИ БЕЗОПАСНОСТИ - {DateTime.Now:yyyy-MM-dd HH:mm:ss} ===");
                    await writer.WriteLineAsync($"Обработано процессов: {actions.Count}");
                    await writer.WriteLineAsync();
                    
                    foreach (var action in actions)
                    {
                        await writer.WriteLineAsync($"ПРОЦЕСС: {action.ProcessName}");
                        await writer.WriteLineAsync($"PID: {action.ProcessId}");
                        await writer.WriteLineAsync($"Путь: {action.FilePath ?? "Неизвестно"}");
                        await writer.WriteLineAsync($"Причина: {action.DetectionReason}");
                        await writer.WriteLineAsync($"Процесс завершен: {(action.ProcessKilled ? "ДА" : "НЕТ")}");
                        await writer.WriteLineAsync($"Файл удален: {(action.FileDeleted ? "ДА" : "НЕТ")}");
                        if (!string.IsNullOrEmpty(action.ErrorMessage))
                        {
                            await writer.WriteLineAsync($"Ошибка: {action.ErrorMessage}");
                        }
                        await writer.WriteLineAsync($"Время операции: {action.ActionTime:yyyy-MM-dd HH:mm:ss}");
                        await writer.WriteLineAsync(new string('-', 50));
                    }
                    
                    await writer.WriteLineAsync();
                }
                
                _logger.LogInformation("Результаты операций безопасности записаны в файл: {LogFilePath}", _logFilePath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ошибка при записи операций безопасности в лог");
            }
        }
    }

    public class SecurityAction
    {
        public string ProcessName { get; set; } = "";
        public int ProcessId { get; set; }
        public string? FilePath { get; set; }
        public string DetectionReason { get; set; } = "";
        public DateTime ActionTime { get; set; }
        public bool ProcessKilled { get; set; }
        public bool FileDeleted { get; set; }
        public string? ErrorMessage { get; set; }
    }
    
    public class SuspiciousProcess
    {
        public string ProcessName { get; set; } = "";
        public int ProcessId { get; set; }
        public string? MainModulePath { get; set; }
        public string DetectionReason { get; set; } = "";
        public DateTime DetectionTime { get; set; }
        public FileProperties? FileProperties { get; set; }
    }

    public class FileProperties
    {
        public string? Type { get; set; }
        public string? FileVersion { get; set; }
        public string? OriginalFilename { get; set; }
        public string? CompanyName { get; set; }
        public string? ProductName { get; set; }
        public string? Description { get; set; }
    }

    // Windows API методы для работы с файлами
    internal static class NativeMethods
    {
        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        public static extern bool MoveFileEx(string lpExistingFileName, string? lpNewFileName, MoveFileFlags dwFlags);

        [System.Flags]
        public enum MoveFileFlags : uint
        {
            MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004,
            MOVEFILE_REPLACE_EXISTING = 0x00000001,
            MOVEFILE_WRITE_THROUGH = 0x00000008
        }
    }
}
