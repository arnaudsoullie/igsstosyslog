<#
.SYNOPSIS
    CSV to Syslog Converter
    
.DESCRIPTION
    Parses a CSV file containing alarm data and converts it to syslog format.
    Outputs syslog messages to a file.
    
.PARAMETER InputFile
    Input CSV file (required unless RunAlm is used)
    
.PARAMETER Output
    Output syslog file (if not specified, prints to stdout)
    
.PARAMETER Delimiter
    CSV delimiter (default: ;)
    
.PARAMETER ShowVerbose
    Verbose output
    
.PARAMETER RunAlm
    Run alm.exe first to generate CSV file
    
.PARAMETER AlmExePath
    Path to alm.exe (default: alm.exe, assumes it's in PATH)
    
.PARAMETER AlmOutputFile
    Output file path for alm.exe (required if RunAlm is specified)
    
.PARAMETER AlmTimeStart
    Time start offset for alm.exe (default: $-90 for 90 days ago)
    
.PARAMETER AlmTimeEnd
    Time end for alm.exe (default: $ for current time)
    
.EXAMPLE
    .\csv_to_syslog.ps1 -InputFile alarms.csv -Output output.syslog
    
.EXAMPLE
    .\csv_to_syslog.ps1 -RunAlm -AlmOutputFile "c:\Users\SoMachine\Desktop\yolo.csv" -Output output.syslog
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$InputFile,
    
    [Parameter(Mandatory=$false)]
    [string]$Output,
    
    [Parameter(Mandatory=$false)]
    [string]$Delimiter = ";",
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowVerbose,
    
    [Parameter(Mandatory=$false)]
    [switch]$RunAlm,
    
    [Parameter(Mandatory=$false)]
    [string]$AlmExePath = "C:\Program Files (x86)\Schneider Electric\IGSS32\V14.0\GSS\alm.exe",
    
    [Parameter(Mandatory=$false)]
    [string]$AlmOutputFile,
    
    [Parameter(Mandatory=$false)]
    [string]$AlmTimeStart = '$-90',
    
    [Parameter(Mandatory=$false)]
    [string]$AlmTimeEnd = '$'
)

# ============================================================================
# CONFIGURATION SECTION
# ============================================================================
# Set your default options here. Command-line parameters will override these values.
# ============================================================================

# Input CSV file path (leave empty to use command-line parameter or RunAlm)
$ConfigInputFile = ""

# Output syslog file path (leave empty to print to stdout)
$ConfigOutput = ""

# CSV delimiter
$ConfigDelimiter = ";"

# Run alm.exe first to generate CSV?
$ConfigRunAlm = $false

# Path to alm.exe
$ConfigAlmExePath = "C:\Program Files (x86)\Schneider Electric\IGSS32\V14.0\GSS\alm.exe"

# Output file path for alm.exe
$ConfigAlmOutputFile = "c:\Users\SoMachine\Desktop\yolo.csv"

# Time start offset for alm.exe (e.g., "$-90" for 90 days ago)
$ConfigAlmTimeStart = '$-90'

# Time end for alm.exe (use "$" for current time)
$ConfigAlmTimeEnd = '$'

# Show verbose output?
$ConfigShowVerbose = $false

# ============================================================================
# END CONFIGURATION SECTION
# ============================================================================

# Apply configuration: use command-line parameters if provided, otherwise use config values
if (-not $InputFile -and $ConfigInputFile) { $InputFile = $ConfigInputFile.ToString().Trim() }
if (-not $Output -and $ConfigOutput) { $Output = $ConfigOutput.ToString().Trim() }
if ($ConfigDelimiter) { $Delimiter = $ConfigDelimiter }
if (-not $RunAlm) { $RunAlm = $ConfigRunAlm }
if ($ConfigAlmExePath) { $AlmExePath = $ConfigAlmExePath }
if (-not $AlmOutputFile -and $ConfigAlmOutputFile) { $AlmOutputFile = $ConfigAlmOutputFile.ToString().Trim() }
if ($ConfigAlmTimeStart) { $AlmTimeStart = $ConfigAlmTimeStart }
if ($ConfigAlmTimeEnd) { $AlmTimeEnd = $ConfigAlmTimeEnd }
if (-not $ShowVerbose) { $ShowVerbose = $ConfigShowVerbose }

# Ensure string parameters are properly converted
if ($InputFile) { $InputFile = $InputFile.ToString().Trim() }
if ($Output) { $Output = $Output.ToString().Trim() }
if ($AlmOutputFile) { $AlmOutputFile = $AlmOutputFile.ToString().Trim() }

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

function Invoke-AlmExport {
    param(
        [string]$AlmExePath,
        [string]$OutputFile,
        [string]$TimeStart,
        [string]$TimeEnd
    )
    
    if (-not $OutputFile) {
        Write-Error "AlmOutputFile is required when RunAlm is specified."
        return $false
    }
    
    # Check if alm.exe exists
    if (-not (Test-Path $AlmExePath)) {
        Write-Error "Error: alm.exe not found at '$AlmExePath'. Please check the path."
        return $false
    }
    
    try {
        # Build the command arguments
        # Note: The original format is -file"path" without space between -file and the quoted path
        # Use escaped quotes to ensure paths with spaces are handled correctly
        $fileArg = "-file`"$OutputFile`""
        $arguments = @(
            "-csv",
            "-ftest",
            $fileArg,
            "-ts$TimeStart",
            "-te$TimeEnd",
            "-all"
        )
        
        if ($ShowVerbose) {
            Write-Host "Running alm.exe to export CSV..."
            Write-Host "Command: `"$AlmExePath`" $($arguments -join ' ')"
            Write-Host "Output file: $OutputFile"
        }
        
        # Execute alm.exe - FilePath parameter handles paths with spaces automatically
        $process = Start-Process -FilePath $AlmExePath -ArgumentList $arguments -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -eq 0) {
            if ($ShowVerbose) {
                Write-Host "alm.exe completed successfully. Output file: $OutputFile"
            }
            return $true
        } else {
            Write-Error "alm.exe exited with code $($process.ExitCode)"
            return $false
        }
    } catch {
        Write-Error "Error running alm.exe: $_"
        return $false
    }
}

# Main script
try {
    # Run alm.exe first if requested
    if ($RunAlm) {
        if (-not $AlmOutputFile) {
            Write-Error "Error: AlmOutputFile is required when RunAlm is specified."
            exit 1
        }
        
        if (-not (Invoke-AlmExport -AlmExePath $AlmExePath -OutputFile $AlmOutputFile -TimeStart $AlmTimeStart -TimeEnd $AlmTimeEnd)) {
            Write-Error "Error: Failed to run alm.exe. Exiting."
            exit 1
        }
        
        # Use AlmOutputFile as InputFile if InputFile wasn't specified
        if (-not $InputFile) {
            $InputFile = $AlmOutputFile.ToString()
        }
        
        # Wait a moment for file to be fully written
        Start-Sleep -Seconds 1
        
        # Verify the file was created
        if ($ShowVerbose) {
            Write-Host "Checking if CSV file was created: $InputFile"
        }
        if (-not (Test-Path $InputFile)) {
            Write-Error "Error: CSV file was not created at '$InputFile'. Please check alm.exe output."
            exit 1
        }
    }
    
    # Validate InputFile is provided
    if (-not $InputFile) {
        Write-Error "Error: InputFile is required (or use RunAlm with AlmOutputFile)."
        exit 1
    }
    
    # Ensure InputFile path is properly handled (trim any whitespace)
    if ($InputFile) {
        $InputFile = $InputFile.ToString().Trim()
    }
    
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
    } else {
        # If no output specified, print to stdout
        foreach ($msg in $syslogMessages) {
            Write-Output $msg
        }
    }
    
} catch {
    Write-Error "Error: $_"
    exit 1
}

