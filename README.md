# igsstosyslog

A tool to convert CSV alarm files to syslog format and optionally send them to a syslog server.

## Description

This project provides a Python script that parses CSV files containing alarm data (from IGSS or similar systems) and converts them to standard syslog format. The tool can output syslog messages to a file or send them directly to a syslog server.

## Features

- Parses CSV files with customizable delimiters (default: semicolon)
- Converts alarm data to RFC 5424 syslog format
- Maps alarm priorities to syslog severity levels
- Supports both file output and network transmission
- Preserves timestamps from the original alarm data
- Includes structured data for better log management

## Requirements

- Python 3.6 or higher
- No external dependencies (uses only Python standard library)

## Installation

Clone this repository:

```bash
git clone https://github.com/arnaudsoullie/igsstosyslog.git
cd igsstosyslog
```

## Usage

### Basic Usage

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

### Command Line Options

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
<10>1 2025-10-27T18:47:21 igs-alarm-system alarms [ID="104"] PLC not running | Objet=controller_status Zone=Global [Etat=Terminé]
<9>1 2025-10-27T18:54:33 igs-alarm-system alarms [ID="90"] PLC progam change | Objet=System Zone=Global [Etat=Terminé]
```

## Syslog Severity Mapping

The script maps alarm priorities to syslog severity levels:
- Priority 5 → Severity 1 (Alert)
- Priority 3 → Severity 4 (Warning)
- Priority 2 → Severity 3 (Error)
- Priority 1 → Severity 2 (Critical)

## License

This project is open source. See LICENSE file for details.

