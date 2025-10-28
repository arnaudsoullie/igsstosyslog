#!/usr/bin/env python3
"""
CSV to Syslog Converter

This script parses a CSV file containing alarm data and converts it to syslog format.
It can output to a file and optionally send to a syslog server.
"""

import argparse
import csv
import socket
import sys
from datetime import datetime
from typing import List, Dict, Optional

def parse_csv(filename: str, delimiter: str = ';') -> List[Dict[str, str]]:
    """Parse CSV file and return list of dictionaries."""
    records = []
    try:
        with open(filename, 'r', encoding='utf-8-sig') as f:
            # Skip BOM if present
            reader = csv.DictReader(f, delimiter=delimiter)
            for row in reader:
                # Filter out empty rows
                if any(value.strip() for value in row.values()):
                    records.append(row)
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        sys.exit(1)
    
    return records

def create_syslog_message(facility: str, severity: str, hostname: str, 
                         program: str, message: str, msgid: Optional[str] = None,
                         timestamp: Optional[datetime] = None) -> str:
    """Create a syslog message in RFC 5424 format."""
    if timestamp is None:
        timestamp = datetime.now()
    
    # Format timestamp as RFC 3339
    timestamp_str = timestamp.strftime('%Y-%m-%dT%H:%M:%S')
    
    # Syslog priority = facility * 8 + severity
    # Default severity 6 (INFO), facility 1 (user)
    if not facility:
        facility = "1"
    if not severity:
        severity = "6"
    
    priority = int(facility) * 8 + int(severity)
    
    # Version
    version = "1"
    
    # Structured data - basic format
    structured_data = "-"
    if msgid:
        structured_data = f'[ID="{msgid}"]'
    
    syslog_msg = f"<{priority}>{version} {timestamp_str} {hostname} {program} {structured_data} {message}"
    
    return syslog_msg

def convert_to_syslog(record: Dict[str, str]) -> str:
    """Convert a CSV record to syslog format."""
    # Extract relevant fields
    alarm_num = record.get('N° d\'alarme', record.get('N° séq.', '')).strip()
    alarm_object = record.get('Objet', '').strip()
    date_start = record.get('DateDébut', '').strip()
    time_start = record.get('HreDébut', '').strip()
    date_finish = record.get('DateFin', '').strip()
    time_finish = record.get('HreFin', '').strip()
    priority = record.get('Priorité', '').strip()
    alarm_text = record.get('Texte d\'alarme', '').strip()
    zone = record.get('Zone', '').strip()
    description = record.get('Description', '').strip()
    alarm_state = record.get('Etat d\'alarme', '').strip()
    
    # Build syslog message
    message_parts = []
    
    if alarm_text:
        message_parts.append(f"{alarm_text}")
    
    details = []
    if alarm_object:
        details.append(f"Objet={alarm_object}")
    if zone:
        details.append(f"Zone={zone}")
    if description:
        details.append(f"Description={description}")
    if date_start and time_start:
        details.append(f"DateDebut={date_start} {time_start}")
    if date_finish and time_finish:
        details.append(f"DateFin={date_finish} {time_finish}")
    
    if details:
        message_parts.append("| " + " ".join(details))
    
    if alarm_state:
        message_parts.append(f"[Etat={alarm_state}]")
    
    message = " ".join(message_parts)
    
    # Map priority (higher number = lower priority in standard priority, but this seems reversed)
    # 1-8 are used for syslog severity (0=emergency, 1=alert, 2=critical, 3=error, 4=warning, 5=notice, 6=info, 7=debug)
    # Convert alarm priority to syslog severity
    try:
        alarm_priority = int(priority) if priority else 6
        # Map inverse: alarm priority 5 -> syslog severity 1 (alert), etc.
        severity_map = {1: 2, 2: 3, 3: 4, 4: 5, 5: 1, 6: 6, 7: 7, 8: 7}
        syslog_severity = severity_map.get(alarm_priority, 4)
    except (ValueError, TypeError):
        syslog_severity = 4
    
    # Parse timestamp from record if available
    date_arrival = record.get('Date d\'arrivée', '').strip()
    time_arrival = record.get('Heure d\'arrivée', '').strip()
    timestamp = None
    
    if date_arrival and time_arrival:
        try:
            # Parse French date format DD/MM/YYYY HH:MM:SS
            timestamp_str = f"{date_arrival} {time_arrival}"
            timestamp = datetime.strptime(timestamp_str, '%d/%m/%Y %H:%M:%S')
        except ValueError:
            pass
    
    # Create syslog message
    facility = "1"  # User facility
    hostname = "igs-alarm-system"
    program = "alarms"
    
    syslog_msg = create_syslog_message(
        facility=facility,
        severity=str(syslog_severity),
        hostname=hostname,
        program=program,
        message=message,
        msgid=alarm_num,
        timestamp=timestamp
    )
    
    return syslog_msg

def send_syslog(message: str, host: str, port: int):
    """Send syslog message to a syslog server."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(message.encode('utf-8'), (host, port))
        sock.close()
        return True
    except Exception as e:
        print(f"Error sending syslog message: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description='Convert CSV alarm file to syslog format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Convert CSV to syslog file
  python csv_to_syslog.py -i alarms.csv -o output.syslog
  
  # Send directly to syslog server
  python csv_to_syslog.py -i alarms.csv --send --host 192.168.1.100 --port 514
  
  # Both output to file and send to server
  python csv_to_syslog.py -i alarms.csv -o output.syslog --send --host 192.168.1.100
        """
    )
    
    parser.add_argument('-i', '--input', required=True, help='Input CSV file')
    parser.add_argument('-o', '--output', help='Output syslog file')
    parser.add_argument('--send', action='store_true', help='Send to syslog server')
    parser.add_argument('--host', default='localhost', help='Syslog server host (default: localhost)')
    parser.add_argument('--port', type=int, default=514, help='Syslog server port (default: 514)')
    parser.add_argument('--delimiter', default=';', help='CSV delimiter (default: ;)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Parse CSV file
    if args.verbose:
        print(f"Parsing CSV file: {args.input}")
    
    records = parse_csv(args.input, delimiter=args.delimiter)
    
    if args.verbose:
        print(f"Found {len(records)} records")
    
    # Convert to syslog format
    syslog_messages = []
    for record in records:
        syslog_msg = convert_to_syslog(record)
        syslog_messages.append(syslog_msg)
    
    # Output to file
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                for msg in syslog_messages:
                    f.write(msg + '\n')
            print(f"Wrote {len(syslog_messages)} messages to {args.output}")
        except Exception as e:
            print(f"Error writing to file: {e}")
            sys.exit(1)
    
    # Send to syslog server
    if args.send:
        sent_count = 0
        failed_count = 0
        for msg in syslog_messages:
            if send_syslog(msg, args.host, args.port):
                sent_count += 1
            else:
                failed_count += 1
            if args.verbose:
                print(f"Sending: {msg[:80]}...")
        
        print(f"Sent {sent_count} messages to {args.host}:{args.port}")
        if failed_count > 0:
            print(f"Failed to send {failed_count} messages")
    
    # If no output specified and not sending, print to stdout
    if not args.output and not args.send:
        for msg in syslog_messages:
            print(msg)

if __name__ == '__main__':
    main()

