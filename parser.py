import re
import csv
import json
from collections import Counter

def open_log():
    try:
        with open("sample_logs.txt", "r") as file:
            lines = file.readlines()
            #print("Log file opened successfully.") 
            for line in lines[:1]: # Display the first 1 lines
                print(line.strip()) # Used to debug and print each line
    except Exception as e:
        raise RuntimeError(f"Failed to open log file: {e}")
    
    
    
def parse_ips():
    ips_data = []
    try:
        with open("sample_logs.txt", "r") as file:
            lines = file.readlines()
            #print("Log file opened successfully.") 
            #print("\n")
            #print("-" * 20)
            #print(f"IP's Detected: {total_ips}")
            #print("-" * 20)
            #print("\n")
            for line in lines[:25]: # Display the first 25 lines
                #print(line.strip()) # Used to debug and print each line
                ips = re.findall(ip_pattern, line)
                if ips:
                    #print(f"IP: {ips}")
                    ips_data.extend(ips)  # Add found IPs to the list
        ip_counter = Counter(ips_data)  # Count occurrences of each IP
        total_ips = sum(ip_counter.values())  # Total number of IPs found
        print(f"\nTotal IPs found: {total_ips}\n")
        print("-" * 20)
        print("IP Counts:")
        print("-" * 20)
        print("\n")
        for ip, count in ip_counter.items():
            print(f"{ip}: {count}")
        return ips_data, ip_counter, total_ips
    except Exception as e:
        raise RuntimeError(f"Failed to parse log file: {e}")
    

# ---------------
# Parse logs
# ---------------
def parse_logs():
    timestamp_data = []
    try:
        with open("sample_logs.txt", "r") as file:
            lines = file.readlines()
            #print("Log file opened successfully.")
            print("\n")
            print("-" * 20)
            print(f"Timestamps")
            print("-" * 20)
            print("\n") 
            for idx, line in enumerate(lines, start=-7): 
                #print(line.strip()) # Used to debug and print each line
                date_match = re.match(date_pattern, line)
                if date_match:
                    timestamp = date_match.group(1)
                    log_level = date_match.group(2)
                    message = date_match.group(3)
                    print(f"{idx}: {timestamp}, Log Level: {log_level}, Message: {message}")
                    timestamp_data.append({
                        'timestamp': timestamp,
                        'level': log_level,
                        'message': message,
                        'ips': []
                    })
            return timestamp_data
    except Exception as e:
        raise RuntimeError(f"Failed to parse log file: {e}")
    

# ---------------
# Match on error string
# ---------------
def parse_errors():
    error_data = []
    try:
        with open("sample_logs.txt", "r") as file:
            lines = file.readlines()
            #print("Log file opened successfully.")
            print("\n")
            print("-" * 20)
            print(f"Errors Detected")
            print("-" * 20)
            print("\n") 
            for idx, line in enumerate(lines, start=1): 
                #print(line.strip()) # Used to debug and print each line
                error_match = re.match(error_pattern, line)
                if error_match:
                    print(f"{idx}: {line.strip()}")
                    error_data.append(line.strip())  # Add the entire line to the error data
            return error_data
    except Exception as e:
        raise RuntimeError(f"Failed to parse log file: {e}")
    
    
# ---------------
# Save logs to CSV
# ---------------    
def save_logs_to_csv(timestamp_data, filename = "parsed_logs.csv"):
    # error_data: list of dictionaries
    # filename: output CSV filename
    
    # Define the headers based on what your log dict contains
    headers = ['timestamp', 'level', 'message', 'ips']
    try:
        with open("parsed_logs.csv", 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()   # Write column headers
            for log in timestamp_data:
                # Join list of IPs into a single string for CSV
                log_copy = log.copy()
                log_copy['ips'] = ', '.join(log['ips'])
                writer.writerow(log_copy)
            print(f"Logs saved to {filename} successfully.")
    except Exception as e:
        print(f"\nFailed to save logs to CSV: {e}")


# ---------------
# Save logs to JSON
# ---------------
def save_logs_to_json(logs, filename):
    # Save the list of dicts as a JSON file
    with open(filename, 'w') as jsonfile:
        json.dump(logs, jsonfile, indent=4)


#def parse_username():


#def count(ips)

# Regular expression pattern to match the log format
date_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\w+) (.+)' 
ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
error_pattern = r'\bERROR\b'


    


if __name__ == "__main__":
    open_log()
    #parse_ips()
    parse_logs()
    #errors =  parse_errors()
    
    #timestamp_and_error = parse_timestamp()
    