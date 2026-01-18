# PC-Diagnose en Onderhoud Script
# Versie: 0.12
# Auteur: Jeroen Neirinck
# Functies: Opschonen tijdelijke bestanden, Windows Update cache, Event logs, Prullenbak; SFC, DISM, Schijfopruiming; Hardware & Health check; IP-adres aanpassen; Computer uit domein verwijderen
# Logbestand: Gegevens en acties worden gelogd naar een bestand op het bureablad
# Opmerking: Dit script vereist PowerShell 5.1 of hoger en moet worden uitgevoerd met beheerdersrechten.

# Waarschuwing 
# Controleer execution policy
$policy = Get-ExecutionPolicy
if ($policy -eq 'Restricted' -or $policy -eq 'Undefined') {
    Write-Host "PowerShell scripts zijn momenteel geblokkeerd door de Execution Policy ($policy)." -ForegroundColor Yellow
    Write-Host "Voer dit script uit met: powershell.exe -ExecutionPolicy Bypass -File '$($MyInvocation.MyCommand.Definition)'" -ForegroundColor Yellow
    Pause
    Exit
}

# Controleer of script als administrator wordt uitgevoerd
function Test-IsAdministrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    Write-Host "Dit script moet worden uitgevoerd met administratorrechten!" -ForegroundColor Yellow
    Write-Host "Je kunt dit doen door rechts te klikken op PowerShell en 'Als administrator uitvoeren' te kiezen." -ForegroundColor Yellow

    # Optioneel: vraag herstart als admin
    $choice = Read-Host "Wil je dat het script zichzelf herstart met beheerdersrechten? (J/N)"
    if ($choice -match "^[Jj]$") {
        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "powershell.exe"
            $psi.Arguments = "-ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Definition)`""
            $psi.Verb = "runas"   # Forceert 'Run as Administrator'
            [System.Diagnostics.Process]::Start($psi) | Out-Null
            Exit
        }
        catch {
            Write-Host "Herstart als administrator is mislukt. Voer het script handmatig als beheerder uit." -ForegroundColor Red
            Pause
            Exit
        }
    }
    else {
        Write-Host "Script afgesloten — administratorrechten vereist." -ForegroundColor Yellow
        Pause
        Exit
    }
}

# === Logbestand per sessie (in ./logs map) ===
$TimeStamp    = Get-Date -Format "yyyyMMdd-HHmmss"
$ComputerName = $env:COMPUTERNAME

# Bepaal de hoofdmap van het script 
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Definieer de logdirectory
$LogDir = Join-Path $ScriptRoot "logs"

# Maak directory aan indien niet bestaat
if (!(Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir | Out-Null
}

# Stel logbestand in
$LogFile = Join-Path $LogDir "systemlog-$ComputerName-$TimeStamp.txt"

# Feedback bij start
Write-Host "Logbestand wordt aangemaakt in: $LogFile" -ForegroundColor DarkGray
Write-Host "Script gestart op $(Get-Date)" -ForegroundColor DarkGray
Write-Host "Even geduld, diagnostiek wordt verzameld..." -ForegroundColor DarkGray

# === Functies ===
# Universele loggingfunctie
function Write-Log {
    param (0
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet('INFO','WARNING','ERROR')]
        [string]$Level = 'INFO'
    )

    $Time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $LogLine = "[$Time] [$Level] $Message"

    # 1️⃣ Wegschrijven naar logbestand
    Add-Content -Path $LogFile -Value $LogLine

    # 2️⃣ Console-uitvoer met kleur per type
    switch ($Level) {
        'INFO'    { Write-Host $LogLine -ForegroundColor Gray }
        'WARNING' { Write-Host $LogLine -ForegroundColor Yellow }
        'ERROR'   { Write-Host $LogLine -ForegroundColor Red }
    }
}

function Clear-TempFiles {
    $Log = @()
    $Log += "=== OPSCHONEN TIJDELIJKE BESTANDEN - $ComputerName ==="
    $Log += "Start: $(Get-Date)"
    Write-Host "Verwijderen van tijdelijke bestanden..."
    $TempPaths = @(
        "$env:TEMP\*",
        "$env:WINDIR\Temp\*",
        "$env:LOCALAPPDATA\Temp\*"
    )
    foreach ($Path in $TempPaths) {
        try {
            Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
            $Log += "Opgeruimd: $Path"
            Write-Host "Opgeruimd: $Path"
        } catch {
            $Log += "Kon $Path niet verwijderen: $_"
            Write-Host "Kon $Path niet verwijderen: $_"
        }
    }
    $Log += "Voltooid: $(Get-Date)"
    $Log += ""
    $Log | Out-File -FilePath $LogFile -Encoding UTF8 -Append
}

function Clear-WindowsUpdateCache {
    $Log = @()
    $Log += "=== OPSCHONEN WINDOWS UPDATE CACHE - $ComputerName ==="
    $Log += "Start: $(Get-Date)"
    Write-Host "Opruimen van Windows Update cache..."
    try {
        Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
        $Log += "Service 'wuauserv' gestopt."
    } catch { $Log += "Kon service 'wuauserv' niet stoppen: $_" }
    try {
        Remove-Item "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
        $Log += "Cache verwijderd."
    } catch { $Log += "Kon cache niet verwijderen: $_" }
    try {
        Start-Service wuauserv -ErrorAction SilentlyContinue
        $Log += "Service 'wuauserv' teruggestart."
    } catch { $Log += "Kon service 'wuauserv' niet starten: $_" }
    $Log += "Einde: $(Get-Date)"
    $Log += ""
    $Log | Out-File -FilePath $LogFile -Encoding UTF8 -Append
    Write-Host "Windows Update cache opruimen voltooid."
}

function Run-SystemFileCheck {
    $Log = @()
    $Log += "=== SYSTEM FILE CHECK (SFC) - $ComputerName ==="
    $Log += "Start: $(Get-Date)"
    Write-Host "Uitvoeren van systeem bestand controle (sfc /scannow)..."
    try {
        $SfcResult = cmd /c "sfc /scannow"
        $Log += $SfcResult
        Write-Host $SfcResult
    } catch { $Log += "Fout bij uitvoeren van SFC: $_" }
    $Log += "Einde: $(Get-Date)"
    $Log += ""
    $Log | Out-File -FilePath $LogFile -Encoding UTF8 -Append
}

function Clear-EventLogs {
    $Log = @()
    $Log += "=== OPSCHONEN EVENT LOGS - $ComputerName ==="
    $Log += "Start: $(Get-Date)"
    Write-Host "WAARSCHUWING: Dit wist ALLE Windows Event Logs permanent!" -ForegroundColor Red
    $confirm = Read-Host "Weet je zeker dat je wilt doorgaan? (J/N)"
    if ($confirm -notmatch "^[Jj]$") { return }
    try {
        $Logs = wevtutil el
        foreach ($LogName in $Logs) {
            try { wevtutil cl "$LogName"; $Log += "Opgeruimd: $LogName" }
            catch { $Log += "Kon $LogName niet opruimen: $_" }
        }
    } catch { $Log += "Fout bij ophalen logs: $_" }
    $Log += "Einde: $(Get-Date)"
    $Log += ""
    $Log | Out-File -FilePath $LogFile -Encoding UTF8 -Append
}

function Clear-Recycle {
    $Log = @()
    $Log += "=== OPSCHONEN PRULLENBAK - $ComputerName ==="
    $Log += "Start: $(Get-Date)"
    try {
        Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        $Log += "Prullenbak succesvol leeggemaakt."
    } catch { $Log += "Kon prullenbak niet leegmaken: $_" }
    $Log += "Einde: $(Get-Date)"
    $Log += ""
    $Log | Out-File -FilePath $LogFile -Encoding UTF8 -Append
}

function Run-DismCleanup {
    $Log = @()
    $Log += "=== DISM CLEANUP - $ComputerName ==="
    $Log += "Start: $(Get-Date)"
    try { $Log += (cmd /c "Dism /Online /Cleanup-Image /StartComponentCleanup") }
    catch { $Log += "Fout bij StartComponentCleanup: $_" }
    try { $Log += (cmd /c "Dism /Online /Cleanup-Image /RestoreHealth") }
    catch { $Log += "Fout bij RestoreHealth: $_" }
    $Log += "Einde: $(Get-Date)"
    $Log += ""
    $Log | Out-File -FilePath $LogFile -Encoding UTF8 -Append
}

function Run-HardwareHealthCheck {
    $Log = @()
    $Log += "=== HARDWARE & HEALTH CHECK - $ComputerName ==="
    $Log += "Start: $(Get-Date)"
    try {
        $Uptime   = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        $CPUUsage = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
        $RAMUsage = Get-CimInstance Win32_OperatingSystem | ForEach-Object { ($_.TotalVisibleMemorySize - $_.FreePhysicalMemory) / $_.TotalVisibleMemorySize * 100 }
        $Disks    = Get-PhysicalDisk | Select-Object FriendlyName, MediaType, Size, HealthStatus, OperationalStatus
        $Log += "Uptime: $Uptime"
        $Log += ("CPU-belasting: {0:N2}%" -f $CPUUsage)
        $Log += ("RAM-gebruik: {0:N2}%" -f $RAMUsage)
        $Log += ($Disks | Format-Table -AutoSize | Out-String)
    } catch { $Log += "Fout bij health check: $_" }
    $Log += "Einde: $(Get-Date)"
    $Log += ""
    $Log | Out-File -FilePath $LogFile -Encoding UTF8 -Append
}

function Run-DiskCleanup {
    $Log = @()
    $Log += "=== SCHIJFOPRUIMING - $ComputerName ==="
    $Log += "Start: $(Get-Date)"
    try { cleanmgr /sagerun:1; $Log += "Schijfopruiming uitgevoerd." }
    catch { $Log += "Fout bij schijfopruiming: $_" }
    $Log += "Einde: $(Get-Date)"
    $Log += ""
    $Log | Out-File -FilePath $LogFile -Encoding UTF8 -Append
}
# === ASCII Logo ===
function Show-AsciiLogo {
    @(
        "       /\       ",
        "      //\\      ",
        "     ///\\\     ",
        "    ////\\\\    ",
        "       ||       ",
        "  VRIJE  SCHOOL ",
        "  H A V E R L O "
    )
}

# === Hoofdmenu ===
function Show-MainMenu {
    do {
        Clear-Host

        # --- Diagnostiek ophalen ---
        $CompName   = $env:COMPUTERNAME
        $UserName   = $env:USERNAME
        $OS         = (Get-ComputerInfo).OsName
        $Version    = (Get-ComputerInfo).WindowsVersion
        $Arch       = (Get-ComputerInfo).OsArchitecture
        $CPUInfo    = Get-CimInstance Win32_Processor
        $CPU        = $CPUInfo.Name
        $Cores      = $CPUInfo.NumberOfCores
        $Threads    = $CPUInfo.NumberOfLogicalProcessors
        $RAM        = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB,2)
        $Uptime     = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        $UptimeStr  = "{0}d {1}h {2}m" -f $Uptime.Days, $Uptime.Hours, $Uptime.Minutes

        $AllIPs     = (Get-NetIPAddress -AddressFamily IPv4 |
                      Where-Object { $_.IPAddress -notlike '169.*' -and $_.IPAddress -ne '127.0.0.1' } |
                      Select-Object -ExpandProperty IPAddress)

        $GW         = (Get-NetRoute -DestinationPrefix "0.0.0.0/0").NextHop | Select-Object -First 1
        $DNS        = (Get-DnsClientServerAddress -AddressFamily IPv4 |
                      Select-Object -ExpandProperty ServerAddresses) -join ", "

        # Netwerktests
        try {
            if (Test-Connection -ComputerName 1.1.1.1 -Count 1 -Quiet) { $PingResult = "Internet OK" }
            elseif (Test-Connection -ComputerName $GW -Count 1 -Quiet) { $PingResult = "($GW) Reachable" }
            else { $PingResult = "Network error" }
        } catch { $PingResult = "Ping test fout: $_" }

        try {
            $Resolve = Resolve-DnsName -Name "www.microsoft.com" -ErrorAction SilentlyContinue
            $DNSResult = if ($Resolve) { "DNS OK" } else { "DNS mislukt" }
        } catch { $DNSResult = "DNS test fout: $_" }

        # Schijven
        $Drives = Get-CimInstance Win32_LogicalDisk | ForEach-Object {
            $Free  = $_.FreeSpace
            $Total = $_.Size
            if ($Total -gt 0) {
                $PctUsed = [math]::Round((($Total - $Free) / $Total) * 100, 0)
                "{0}: {1}GB free / {2}GB total ({3}% used)" -f $_.DeviceID,
                    ([math]::Round($Free/1GB,0)),
                    ([math]::Round($Total/1GB,0)),
                    $PctUsed
            }
        }

     
        # Logo + menu (links)
        $LogoLines = Show-AsciiLogo
        $MenuLines = @(
            "[1]  Tijdelijke bestanden opruimen"
            "[2]  Windows Update cache opruimen"
            "[3]  Event logs opschonen"
            "[4]  Prullenbak leegmaken"
            "[5]  SFC uitvoeren"
            "[6]  DISM uitvoeren"
            "[7]  IP-adres aanpassen"
            "[8]  Computer uit domein verwijderen"
            "[9]  Schijfopruiming uitvoeren"
            "[10] Hardware & Health check"
            "[0]  Afsluiten"
        )

        $LeftBlock  = $LogoLines + "" + $MenuLines

        # Diagnostiek (rechts)
        $DiagLines = @(
            "Computernaam : $CompName"
            "Gebruiker    : $UserName"
            "OS           : $OS"
            "Versie       : $Version"
            "CPU          : $CPU"
            "Cores/Threads: $Cores/$Threads"
            "RAM (GB)     : $RAM"
            "IP-adressen  : $($AllIPs -join ', ')"
            "Gateway      : $GW"
            "Uptime       : $UptimeStr"
            "DNS server(s): $DNS"
            "Netwerkstatus: $PingResult"
            "DNS test     : $DNSResult"
            "Schijven:"
        )
        $Drives | ForEach-Object { $DiagLines += "  $_" }

        $MaxLines = [math]::Max($LeftBlock.Count, $DiagLines.Count)

        Write-Host ("{0,-40}   {1,-55}" -f "======================================", "===============================================")
        Write-Host ("{0,-40}   {1,-55}" -f "   HAVERLO ONDERHOUD & DIAGNOSTIEK",     "   TECHNISCHE GEGEVENS")
        Write-Host ("{0,-40}   {1,-55}" -f "======================================", "===============================================")

        for ($i=0; $i -lt $MaxLines; $i++) {
            $Left  = if ($i -lt $LeftBlock.Count) { $LeftBlock[$i] } else { "" }
            $Right = if ($i -lt $DiagLines.Count) { $DiagLines[$i] } else { "" }
            Write-Host ("{0,-40}   {1}" -f $Left, $Right)
        }

        Write-Host ("{0,-40}   {1,-55}" -f "======================================", "===============================================")

        # Keuze
        $Choice = Read-Host "Maak een keuze (0-10, 0 = afsluiten)"
        switch ($Choice) {
            "1"  { Clear-TempFiles; Pause }
            "2"  { Clear-WindowsUpdateCache; Pause }
            "3"  { Clear-EventLogs; Pause }
            "4"  { Clear-Recycle; Pause }
            "5"  { Run-SystemFileCheck; Pause }
            "6"  { Run-DismCleanup; Pause }
            "7"  { Set-ComputerIP; Pause }
            "8"  { Remove-FromDomain; Pause }
            "9"  { Run-DiskCleanup; Pause }
            "10" { Run-HardwareHealthCheck; Pause }
            "0"  { Write-Host "Script afgesloten."; break }
            default { Write-Host "Ongeldige keuze."; Pause }
        }
    } while ($true)
}



# Start hoofdmenu
Show-MainMenu
