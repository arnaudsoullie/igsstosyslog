# igsstosyslog

A tool to convert CSV alarm files to syslog format and optionally send them to a syslog server.

## Description

This project provides scripts in both Python and PowerShell that parse CSV files containing alarm data (from IGSS or similar systems) and convert them to standard syslog format. The tools can output syslog messages to a file or send them directly to a syslog server.

## Features

- Parses CSV files with customizable delimiters (default: semicolon)
- Converts alarm data to RFC 5424 syslog format
- Maps alarm priorities to syslog severity levels
- Supports both file output and network transmission
- Preserves timestamps from the original alarm data
- Includes structured data with unique hash to prevent duplicates
- Uses actual machine hostname automatically

## Requirements

**Python Version:**
- Python 3.6 or higher
- No external dependencies (uses only Python standard library)

**PowerShell Version:**
- Windows PowerShell 5.1 or PowerShell 7+
- No additional modules required

## Installation

Clone this repository:

```bash
git clone https://github.com/arnaudsoullie/igsstosyslog.git
cd igsstosyslog
```

## Usage

### Python Script

**Basic Usage:**

Convert CSV to syslog file:
```bash
python csv_to_syslog.py -i alarms.csv -o output.syslog
```

Send directly to syslog server:
```bash
python csv_to_syslog.py -i alarms.csv --send --host 192.168.1.100 --port 514
```

Both output to file and send to server:
```bash
python csv_to_syslog.py -i alarms.csv -o output.syslog --send --host 192.168.1.100
```

**Python Command Line Options:**
```
-i, --input        Input CSV file (required)
-o, --output       Output syslog file
--send            Send to syslog server
--host            Syslog server host (default: localhost)
--port            Syslog server port (default: 514)
--delimiter       CSV delimiter (default: ;)
-v, --verbose     Verbose output
-h, --help        Show help message
```

### PowerShell Script

**Basic Usage:**

Convert CSV to syslog file:
```powershell
.\csv_to_syslog.ps1 -InputFile alarms.csv -Output output.syslog
```

Send directly to syslog server:
```powershell
.\csv_to_syslog.ps1 -InputFile alarms.csv -Send -SyslogHost 192.168.1.100 -Port 514
```

Both output to file and send to server:
```powershell
.\csv_to_syslog.ps1 -InputFile alarms.csv -Output output.syslog -Send -SyslogHost 192.168.1.100
```

Run alm.exe first to generate CSV, then convert to syslog:
```powershell
.\csv_to_syslog.ps1 -RunAlm -AlmOutputFile "c:\Users\SoMachine\Desktop\yolo.csv" -Output output.syslog
```

**PowerShell Command Line Options:**
```
-InputFile        Input CSV file (required unless RunAlm is used)
-Output           Output syslog file
-Send             Send to syslog server
-SyslogHost       Syslog server host (default: localhost)
-Port             Syslog server port (default: 514)
-Delimiter        CSV delimiter (default: ;)
-ShowVerbose      Verbose output
-RunAlm           Run alm.exe first to generate CSV file
-AlmExePath       Path to alm.exe (default: alm.exe)
-AlmOutputFile    Output file path for alm.exe (required if RunAlm is specified)
-AlmTimeStart     Time start offset for alm.exe (default: $-90 for 90 days ago)
-AlmTimeEnd       Time end for alm.exe (default: $ for current time)
```

### CSV File Format

The script expects a CSV file with semicolon delimiters and columns such as:
- `N° d'alarme`: Alarm number
- `Texte d'alarme`: Alarm text
- `Priorité`: Priority level
- `Zone`: Zone information
- `Date d'arrivée`, `Heure d'arrivée`: Timestamp
- `Etat d'alarme`: Alarm state

## Example Output

```
<9>1 2025-10-27T18:47:21 HOSTNAME alarms [ID="104" HASH="2699278932B8639B"] PLC not running | Objet=controller_status Zone=Global [Etat=Terminé]
<12>1 2025-10-27T18:54:33 HOSTNAME alarms [ID="90" HASH="D83AA6E44576641B"] PLC progam change | Objet=System Zone=Global [Etat=Terminé]
```

Note: HOSTNAME will be replaced with the actual hostname of the machine running the script. The HASH field contains a unique identifier based on alarm name, date, and time to help prevent duplicate entries.

## Syslog Severity Mapping

The script maps alarm priorities to syslog severity levels:
- Priority 5 → Severity 1 (Alert)
- Priority 3 → Severity 4 (Warning)
- Priority 2 → Severity 3 (Error)
- Priority 1 → Severity 2 (Critical)

## License

This project is open source. See LICENSE file for details.

