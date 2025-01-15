import csv
from datetime import datetime

# Function to log IP address with user_id and timestamp
def log_ip(user_id, ip_address):
    timestamp = datetime.now().timestamp()
    with open('IP_dataset.csv', mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([user_id, ip_address, timestamp])

# Example usage
log_ip(101, '192.168.1.100')
