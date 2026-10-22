// База сигнатур. weight: 10-40, level: с какой модели правило активно (1,2,lite,pro по глубине)
export const LEVEL_NUM = { v1:1, v2:2, lite:3, pro:4 };
export const SIGNATURES = [
 // --- Уровень 1: базовые, грубые угрозы (BAT/PY) ---
 {min:1, w:35, cat:"Удаление данных", re:/(rd|rmdir)\s+\/s\s+\/q|del\s+\/[fq]|format\s+[a-z]:|shutil\.rmtree|os\.remove|os\.system\s*\(/i},
 {min:1, w:30, cat:"Загрузка из сети", re:/curl\s+.*-o|wget\s+http|urllib\.request|requests\.get\s*\(|powershell.*downloadstring|certutil\s+-urlcache/i},
 {min:1, w:30, cat:"Выполнение кода", re:/\beval\s*\(|\bexec\s*\(|subprocess\.(Popen|call|run)|os\.popen|start\s+.*\.exe/i},
 {min:1, w:25, cat:"Скрытый запуск", re:/start\s+\/min|start\s+\/b|windowstyle\s+hidden|-windowstyle\s+hidden|pythonw/i},
 {min:1, w:20, cat:"Изменение системы", re:/reg\s+add|regedit|net\s+user|vssadmin|bcdedit|schtasks/i},
 // --- Уровень 2: скриптовые угрозы JS/VBS/HTA ---
 {min:2, w:35, cat:"Download Cradle", re:/DownloadString|DownloadFile|Invoke-Expression|IEX\s*\(|Net\.WebClient|XMLHTTP|ADODB\.Stream|WScript\.Shell|ActiveXObject/i},
 {min:2, w:30, cat:"Обфускация", re:/String\.fromCharCode|chr\s*\(|unescape\s*\(|fromcharcode|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){4,}|[A-Za-z0-9+\/]{120,}={0,2}/i},
 {min:2, w:30, cat:"Автозапуск / закрепление", re:/CurrentVersion\\Run|Startup|shell:startup|CreateShortcut|\.lnk/i},
 {min:2, w:25, cat:"HTA / MSHTA", re:/mshta|application\.hta|<hta:/i},
 {min:2, w:25, cat:"Обход защиты", re:/Set-MpPreference|Add-MpPreference\s+-Exclusion|amsi|bypass|ExecutionPolicy\s+Unrestricted|-ExecutionPolicy\s+Bypass/i},
 // --- Уровень 3 Lite: глубокий анализ ---
 {min:3, w:40, cat:"Зашифрованный пейлоад", re:/base64|b64decode|a2b_base64|FromBase64String|::FromBase64String|\^.{0,3}\^|xor|RC4|AES|decrypt|decode\(\)/i},
 {min:3, w:35, cat:"Encoded PowerShell", re:/powershell(\.exe)?\s+.*-(enc|encodedcommand|e)\s+[A-Za-z0-9+\/=]{40,}/i},
 {min:3, w:35, cat:"Макросы Office", re:/Auto_Open|Workbook_Open|Document_Open|Shell\s*\(|CreateObject|Declare\s+PtrSafe|VirtualAlloc/i},
 {min:3, w:30, cat:"Инъекция в процесс", re:/VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection|ProcessHollowing|ReflectiveLoader/i},
 {min:3, w:30, cat:"Кража данных", re:/Login Data|Cookies|wallet|keychain|password.*steal|telegram|discord.*token|Local State/i},
 {min:3, w:25, cat:"Майнер", re:/xmrig|stratum\+tcp|minergate|coinhive|nicehash|pool\./i},
 {min:3, w:25, cat:"Ransomware-признаки", re:/\.locked|\.encrypted|ransom|bitcoin|wallet.*0x|vssadmin\s+delete\s+shadows|wbadmin\s+delete/i},
 // --- Уровень 3 Pro: максимум ---
 {min:4, w:40, cat:"Shellcode / PE-аномалии", re:/\x4d\x5a.{0,200}\x50\x45\x00\x00|This program cannot be run|UPX0|UPX1|\.vmp|Themida/i},
 {min:4, w:35, cat:"Анти-анализ / VM-evasion", re:/VirtualBox|VMware|vbox|vmtools|IsDebuggerPresent|CheckRemoteDebugger|cpuid|MAC.*00:05:69|sleep\s*\(\s*\d{5,}/i},
 {min:4, w:35, cat:"Keylogger / шпионаж", re:/GetAsyncKeyState|SetWindowsHookEx|keylog|getkeyboardstate|BitBlt|screenshot/i},
 {min:4, w:30, cat:"C2 / сеть", re:/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}|socket\.connect|reverse.*shell|bind.*shell|pastebin|ngrok|onion/i},
 {min:4, w:30, cat:"Кража крипты / клиппер", re:/clipboard|bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{20,}|0x[a-fA-F0-9]{40}/i},
];
export const SUSPICIOUS_WORDS = ["password","token","stealer","rat","trojan","keylogger","miner","exploit","payload","shellcode","inject","bypass","crack","free robux","cheat"];
