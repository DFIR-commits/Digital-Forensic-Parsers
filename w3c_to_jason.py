import csv
import json
import os
import glob
import sys
from datetime import datetime

def parse_w3c_log(filepath):
    records = []
    fields = []
    
    with open(filepath, 'r', encoding='utf-8-sig') as f:
        for line in f:
            line = line.rstrip('\n')
            
            # Skip comment lines except #Fields
            if line.startswith('#Fields:'):
                fields = line[9:].strip().split(' ')
                continue
            if line.startswith('#'):
                continue
            if not line.strip():
                continue
            
            # Parse data line
            values = line.split(' ')
            if len(values) != len(fields):
                continue
            
            record = dict(zip(fields, values))
            
            # Combine date and time if both present
            if 'date' in record and 'time' in record:
                record['timestamp'] = f"{record['date']}T{record['time']}Z"
            
            # Replace dashes (IIS null values) with None
            record = {k: (None if v == '-' else v) for k, v in record.items()}
            
            records.append(record)
    
    return records

def convert_directory(input_dir, output_file):
    all_records = []
    log_files = glob.glob(os.path.join(input_dir, '*.log'))
    
    if not log_files:
        print(f"No .log files found in {input_dir}")
        return
    
    for filepath in log_files:
        print(f"Parsing: {filepath}")
        records = parse_w3c_log(filepath)
        all_records.extend(records)
        print(f"  -> {len(records)} records")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(all_records, f, indent=2)
    
    print(f"\nDone. {len(all_records)} total records written to {output_file}")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python w3c_to_json.py <input_dir> <output.json>")
        sys.exit(1)
    
    convert_directory(sys.argv[1], sys.argv[2])
