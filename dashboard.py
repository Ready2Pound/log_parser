import streamlit as st
import re
from collections import Counter 

# Regular expression pattern to match the log format
date_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\w+) (.+)' 
ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
error_pattern = r'\bERROR\b'


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
# Match lines with IP
# ---------------
def parse_ips():
    ips_data = []
    try:
        with open("sample_logs.txt", "r") as file:
            lines = file.readlines()
            for line in lines[:25]: # Display the first 25 lines
                #print(line.strip()) # Used to debug and print each line
                ips = re.findall(ip_pattern, line)
                if ips:
                    #print(f"IP: {ips}")
                    ips_data.extend(ips)  # Add found IPs to the list
        ip_counter = Counter(ips_data)  # Count occurrences of each IP
        total_ips = sum(ip_counter.values())  # Total number of IPs found
        unique_ips = len(ip_counter)  # Count unique IPs
        print(f"\nTotal IPs found: {total_ips}\n")
        print("-" * 20)
        print("IP Counts:")
        print("-" * 20)
        print("\n")
        for ip, count in ip_counter.items():
            print(f"{ip}: {count}")
        return unique_ips, total_ips, ip_counter
    except Exception as e:
        raise RuntimeError(f"Failed to parse log file: {e}")
    
# ---------------
# Streamlit app 
# ---------------
def main():
    st.title("Lightweight SIEM Dashboard")
    st.write("Upload your log file to analyze IP addresses and visualize insights.")

    # File uploader widget
    uploaded_file = st.file_uploader("Choose a log file (.log or .txt)", type=["log", "txt"])
    
    if uploaded_file:
        # Read the file as text
        log_lines = uploaded_file.read().decode('utf-8').splitlines()
        st.success(f"Loaded {len(log_lines)} lines from the log file.")
        
        # Parse each line
        parsed_logs = parse_logs()
        
        # Analyze IPs
        unique_ips, total_ips, ip_counter = parse_ips()
        
        # # Display metrics
        st.metric("Total IPs (including duplicates)", total_ips)
        st.metric("Unique IPs", unique_ips)
        
        # # Show top IPs
        if ip_counter:
            top_ips = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:10]
            ip_labels, ip_values = zip(*top_ips)
            st.bar_chart(dict(top_ips))
        else:
            st.write("No IP addresses found.")
        
        # Display first 20 parsed logs as a table
        st.write("Sample parsed logs")
        st.dataframe(parsed_logs[:20])
    else:
        st.info("Please upload a log file to get started.")
    

if __name__ == "__main__":
    main()