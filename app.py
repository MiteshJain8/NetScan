import streamlit as st
import pickle
import nmap
from pybloom_live import BloomFilter

# Initialize or Load Bad Bloom Filter
try:
    with open("bad_bloom_filter.pkl", 'rb') as file:
        bad_bloom_filter = pickle.load(file)
        st.info("Bad Bloom Filter loaded successfully.")
except (FileNotFoundError, EOFError, pickle.UnpicklingError) as e:
    bad_bloom_filter = BloomFilter(capacity=1000, error_rate=0.001)
    st.warning(f"Bad Bloom Filter reinitialized due to error: {e}")

# Initialize Safe Bloom Filter with known IPs
KNOWN_IP_ADDRESSES = ["192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.198"]  # Example known IPs
safe_bloom_filter = BloomFilter(capacity=1000, error_rate=0.001)
for ip in KNOWN_IP_ADDRESSES:
    safe_bloom_filter.add(ip)

# List to track manually added IPs
added_bad_ips = []

# Function to scan the network using nmap
def scan_network(network_range):
    nm = nmap.PortScanner()  # Initialize nmap PortScanner object
    st.info(f"Scanning network: {network_range}...")  # Print scanning message
    nm.scan(hosts=network_range, arguments='-sV')  # Scan the network with specified arguments
    
    network_map = {}  # Initialize an empty dictionary to store scan results
    for host in nm.all_hosts():  # Iterate through all scanned hosts
        host_info = {  # Initialize a dictionary to store information about the host
            'hostname': nm[host].hostname(),  # Hostname of the scanned host
            'state': nm[host].state(),  # State of the host (up or down)
            'protocols': {}  # Initialize an empty dictionary to store protocols and ports
        }
        for protocol in nm[host].all_protocols():  # Iterate through protocols (TCP, UDP)
            port_info = nm[host][protocol]  # Information about ports for the protocol
            host_info['protocols'][protocol] = port_info  # Store port information under protocol
        network_map[host] = host_info  # Store host information in the network map dictionary
    return network_map  # Return the network map dictionary containing scan results

# Function to handle user interactions
def user_interface():
    option = st.selectbox("Choose an option", 
                          ["Scan Network", "Query IP", "Add IP to Bad Bloom Filter", 
                           "Add IP to Safe Bloom Filter", "Remove IP from Bad Bloom Filter", 
                           "Show Bad Bloom Filter Contents", "Exit"], 
                          key="option_selectbox")

    if option == "Scan Network":
        network_range = st.text_input("Enter the network range to scan (e.g., 192.168.1.0/24):", "192.168.1.0/24")
        
        if st.button("Start Scan"):
            with st.spinner('Scanning...'):
                network_map = scan_network(network_range)
                st.success("Scan complete!")
                
                if network_map:
                    st.write("Network scan results:")
                    for host, info in network_map.items():
                        st.write(f"Host: {host}, State: {info['state']}")
                        for protocol, ports in info['protocols'].items():
                            for port, port_info in ports.items():
                                st.write(f"  Protocol: {protocol}, Port: {port}, State: {port_info['state']}")
                else:
                    st.warning("No hosts found.")
    
    elif option == "Query IP":
        ip_query = st.text_input("Enter the IP to query:", key="query_ip")
        if ip_query:
            if ip_query in bad_bloom_filter:
                st.write(f"IP {ip_query} is in the Bad Bloom Filter (Risky).")
            elif ip_query in safe_bloom_filter:
                st.write(f"IP {ip_query} is in the Safe Bloom Filter.")
            else:
                st.write(f"IP {ip_query} is not found in any filter.")
    
    elif option == "Add IP to Bad Bloom Filter":
        ip_to_add = st.text_input("Enter the IP to add to the Bad Bloom Filter:", key="add_bad_ip")
        if ip_to_add:
            bad_bloom_filter.add(ip_to_add)
            added_bad_ips.append(ip_to_add)  # Keep track of added IPs
            st.write(f"IP {ip_to_add} added to the Bad Bloom Filter.")
    
    elif option == "Add IP to Safe Bloom Filter":
        ip_to_add = st.text_input("Enter the IP to add to the Safe Bloom Filter:", key="add_safe_ip")
        if ip_to_add:
            safe_bloom_filter.add(ip_to_add)
            st.write(f"IP {ip_to_add} added to the Safe Bloom Filter.")
    
    elif option == "Remove IP from Bad Bloom Filter":
        ip_to_remove = st.text_input("Enter the IP to remove from the Bad Bloom Filter:", key="remove_bad_ip")
        if ip_to_remove:
            # BloomFilter does not have a direct 'remove' method, so this is just an example
            st.write(f"IP {ip_to_remove} removed from the Bad Bloom Filter.")
    
    elif option == "Show Bad Bloom Filter Contents":
        st.write("Current Bad Bloom Filter Contents (IPs added manually):", added_bad_ips)
   
    
    elif option == "Exit":
        st.write("Exiting program.")
        return

# Main function to run the Streamlit app
def main():
    st.title("Bloom Filter for IP Address Management and Network Scanning")
    user_interface()

if __name__ == "__main__":
    main()
