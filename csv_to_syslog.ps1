<#
.SYNOPSIS
    CSV to Syslog Converter
    
.DESCRIPTION
    Parses a CSV file containing alarm data and converts it to syslog format.
    Can output to a file and optionally send to a syslog server.
    
.PARAMETER InputFile
    Input CSV file (required)
    
.PARAMETER Output
    Output syslog file
    
.PARAMETER Send
    Send to syslog server
    
.PARAMETER SyslogHost
    Syslog server host (default: localhost)
    
.PARAMETER Port
    Syslog server port (default: 514)
    
.PARAMETER Delimiter
    CSV delimiter (default: ;)
    
.PARAMETER Verbose
    Verbose output
    
.EXAMPLE
    .\csv_to_syslog.ps1 -InputFile alarms.csv -Output output.syslog
    
.EXAMPLE
    .\csv_to_syslog.ps1 -InputFile alarms.csv -Send -SyslogHost 192.168.1.100 -Port 514
    
.EXAMPLE
    .\csv_to_syslog.ps1 -InputFile alarms.csv -Output output.syslog -Send -SyslogHost 192.168.1.100
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$InputFile,
    
    [Parameter(Mandatory=$false)]
    [string]$Output,
    
    [Parameter(Mandatory=$false)]
    [switch]$Send,
    
    [Parameter(Mandatory=$false)]
    [string]$SyslogHost = "localhost",
    
    [Parameter(Mandatory=$false)]
    [int]$Port = 514,
    
    [Parameter(Mandatory=$false)]
    [string]$Delimiter = ";",
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowVerbose
)

function Find-FieldBySubstring {
    param(
        [hashtable]$Record,
        [string]$Substring
    )
    
    $substringLower = $Substring.ToLower()
    foreach ($key in $Record.Keys) {
        if ($key.ToLower().Contains($substringLower)) {
            $value = $Record[$key]
            if ($value) {
                return $value.ToString().Trim()
            }
        }
    }
    return ""
}

function Create-SyslogMessage {
    param(
        [int]$Facility,
        [int]$Severity,
        [string]$Hostname,
        [string]$Program,
        [string]$Message,
        [string]$MsgId,
        [DateTime]$Timestamp,
        [string]$UniqueHash
    )
    
    if (-not $Timestamp) {
        $Timestamp = Get-Date
    }
    
    # Format timestamp as RFC 3339
    $timestampStr = $Timestamp.ToString("yyyy-MM-ddTHH:mm:ss")
    
    # Syslog priority = facility * 8 + severity
    $priority = $Facility * 8 + $Severity
    
    # Version
    $version = "1"
    
    # Structured data
    $structuredDataParts = @()
    if ($MsgId) {
        $structuredDataParts += "ID=`"$MsgId`""
    }
    if ($UniqueHash) {
        $structuredDataParts += "HASH=`"$UniqueHash`""
    }
    
    if ($structuredDataParts.Count -gt 0) {
        $structuredData = "[" + ($structuredDataParts -join " ") + "]"
    } else {
        $structuredData = "-"
    }
    
    $syslogMsg = "<$priority>$version $timestampStr $Hostname $Program $structuredData $Message"
    return $syslogMsg
}

function ConvertTo-Syslog {
    param(
        [hashtable]$Record
    )
    
    # Extract relevant fields using substring matching for Unicode characters
    $alarmNum = ""
    foreach ($key in $Record.Keys) {
        $keyLower = $key.ToLower()
        if ($keyLower.Contains("n") -and ($keyLower.Contains("d'alarme") -or $keyLower.Contains("seq") -or $keyLower.Contains("séq")) -and -not $keyLower.Contains("texte")) {
            $alarmNum = $Record[$key].ToString().Trim()
            break
        }
    }
    
    $alarmObject = $Record["Objet"]
    if ($alarmObject) { $alarmObject = $alarmObject.ToString().Trim() } else { $alarmObject = "" }
    
    $dateStart = Find-FieldBySubstring -Record $Record -Substring "DateDebut"
    $timeStart = Find-FieldBySubstring -Record $Record -Substring "HreDebut"
    $dateFinish = Find-FieldBySubstring -Record $Record -Substring "DateFin"
    $timeFinish = Find-FieldBySubstring -Record $Record -Substring "HreFin"
    $priority = Find-FieldBySubstring -Record $Record -Substring "Priorit"
    $alarmText = Find-FieldBySubstring -Record $Record -Substring "Texte d'alarme"
    if (-not $alarmText) { $alarmText = Find-FieldBySubstring -Record $Record -Substring "Texte" }
    $zone = $Record["Zone"]
    if ($zone) { $zone = $zone.ToString().Trim() } else { $zone = "" }
    $description = $Record["Description"]
    if ($description) { $description = $description.ToString().Trim() } else { $description = "" }
    $alarmState = Find-FieldBySubstring -Record $Record -Substring "Etat d'alarme"
    if (-not $alarmState) { 
        $alarmState = Find-FieldBySubstring -Record $Record -Substring "Etat"
        if (-not $alarmState) { $alarmState = Find-FieldBySubstring -Record $Record -Substring "State" }
    }
    # Find arrival date and time specifically
    $dateArrival = ""
    $timeArrival = ""
    foreach ($key in $Record.Keys) {
        $keyLower = $key.ToLower()
        if ($keyLower.Contains("arriv")) {
            if ($keyLower.Contains("date")) {
                $dateArrival = $Record[$key].ToString().Trim()
            }
            if ($keyLower.Contains("heure") -or $keyLower.Contains("time")) {
                $timeArrival = $Record[$key].ToString().Trim()
            }
        }
    }
    
    # Build syslog message
    $messageParts = @()
    
    if ($alarmText) {
        $messageParts += $alarmText
    }
    
    $details = @()
    if ($alarmObject) { $details += "Objet=$alarmObject" }
    if ($zone) { $details += "Zone=$zone" }
    if ($description) { $details += "Description=$description" }
    if ($dateStart -and $timeStart) { $details += "DateDebut=$dateStart $timeStart" }
    if ($dateFinish -and $timeFinish) { $details += "DateFin=$dateFinish $timeFinish" }
    
    if ($details.Count -gt 0) {
        $messageParts += "| " + ($details -join " ")
    }
    
    if ($alarmState) {
        $messageParts += "[Etat=$alarmState]"
    }
    
    $message = $messageParts -join " "
    
    # Map priority to syslog severity
    $severityMap = @{
        1 = 2  # Critical
        2 = 3  # Error
        3 = 4  # Warning
        4 = 5  # Notice
        5 = 1  # Alert
        6 = 6  # Info
        7 = 7  # Debug
        8 = 7  # Debug
    }
    
    try {
        $alarmPriority = if ($priority) { [int]$priority } else { 6 }
        $syslogSeverity = $severityMap[$alarmPriority]
        if (-not $syslogSeverity) { $syslogSeverity = 4 }
    } catch {
        $syslogSeverity = 4
    }
    
    # Parse timestamp from record if available
    $timestamp = $null
    if ($dateArrival -and $timeArrival) {
        try {
            $timestampStr = "$dateArrival $timeArrival"
            $timestamp = [DateTime]::ParseExact($timestampStr, "dd/MM/yyyy HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
        } catch {
            # Ignore parse errors
        }
    }
    
    # Create unique hash from alarm name, date, and time to prevent duplicates
    $uniqueHash = $null
    if ($alarmText -and $dateArrival -and $timeArrival) {
        $hashInput = "$alarmText|$dateArrival|$timeArrival"
        $hashBytes = [System.Text.Encoding]::UTF8.GetBytes($hashInput)
        $hash = [System.Security.Cryptography.MD5]::Create().ComputeHash($hashBytes)
        $uniqueHash = ([System.BitConverter]::ToString($hash) -replace "-", "").Substring(0, 16)
    }
    
    # Create syslog message
    $facility = 1  # User facility
    $hostname = $env:COMPUTERNAME
    $program = "alarms"
    
    $syslogMsg = Create-SyslogMessage `
        -Facility $facility `
        -Severity $syslogSeverity `
        -Hostname $hostname `
        -Program $program `
        -Message $message `
        -MsgId $alarmNum `
        -Timestamp $timestamp `
        -UniqueHash $uniqueHash
    
    return $syslogMsg
}

function Send-SyslogMessage {
    param(
        [string]$Message,
        [string]$Host,
        [int]$Port
    )
    
    try {
        $client = New-Object System.Net.Sockets.UdpClient
        $endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($Host), $Port)
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Message)
        $client.Send($bytes, $bytes.Length, $endpoint) | Out-Null
        $client.Close()
        return $true
    } catch {
        Write-Error "Error sending syslog message: $_"
        return $false
    }
}

# Main script
try {
    # Parse CSV file
    if ($ShowVerbose) {
        Write-Host "Parsing CSV file: $InputFile"
    }
    
    if (-not (Test-Path $InputFile)) {
        Write-Error "Error: File '$InputFile' not found."
        exit 1
    }
    
    # Read CSV file
    $records = @()
    $content = Get-Content $InputFile -Encoding UTF8
    
    if ($content.Length -lt 2) {
        Write-Error "CSV file must have at least a header row and one data row"
        exit 1
    }
    
    # Parse header
    $header = $content[0] -split $Delimiter
    
    # Parse data rows
    for ($i = 1; $i -lt $content.Length; $i++) {
        $line = $content[$i].Trim()
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        
        $values = $line -split $Delimiter
        
        # Check if row has any non-empty values
        $hasData = $false
        foreach ($val in $values) {
            if ($val.Trim()) {
                $hasData = $true
                break
            }
        }
        
        if (-not $hasData) {
            continue
        }
        
        # Create hashtable for record
        $record = @{}
        for ($j = 0; $j -lt $header.Length; $j++) {
            $key = $header[$j].Trim()
            $value = if ($j -lt $values.Length) { $values[$j] } else { "" }
            $record[$key] = $value
        }
        $records += $record
    }
    
    if ($ShowVerbose) {
        Write-Host "Found $($records.Count) records"
    }
    
    # Convert to syslog format
    $syslogMessages = @()
    foreach ($record in $records) {
        $syslogMsg = ConvertTo-Syslog -Record $record
        $syslogMessages += $syslogMsg
    }
    
    # Output to file
    if ($Output) {
        try {
            $syslogMessages | Out-File -FilePath $Output -Encoding UTF8
            Write-Host "Wrote $($syslogMessages.Count) messages to $Output"
        } catch {
            Write-Error "Error writing to file: $_"
            exit 1
        }
    }
    
    # Send to syslog server
    if ($Send) {
        $sentCount = 0
        $failedCount = 0
        foreach ($msg in $syslogMessages) {
            if (Send-SyslogMessage -Message $msg -Host $SyslogHost -Port $Port) {
                $sentCount++
            } else {
                $failedCount++
            }
            if ($ShowVerbose) {
                $msgPreview = if ($msg.Length -gt 80) { $msg.Substring(0, 80) + "..." } else { $msg }
                Write-Host "Sending: $msgPreview"
            }
        }
        
        Write-Host "Sent $sentCount messages to ${SyslogHost}:$Port"
        if ($failedCount -gt 0) {
            Write-Host "Failed to send $failedCount messages"
        }
    }
    
    # If no output specified and not sending, print to stdout
    if (-not $Output -and -not $Send) {
        foreach ($msg in $syslogMessages) {
            Write-Output $msg
        }
    }
    
} catch {
    Write-Error "Error: $_"
    exit 1
}

