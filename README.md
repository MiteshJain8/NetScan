# NetScan
NetScan Visualizer is a Python script designed to scan a network range, identify potential threats based on known vulnerable ports, and visualize the network topology along with the discovered services.

# Features
Network Scanning: Utilizes the nmap library to scan a specified network range for active hosts and open ports.
Threat Identification: Identifies potential threats by comparing open ports with a predefined list of known vulnerable ports.
Network Visualization: Generates a visual representation of the network topology using networkx and matplotlib.
Detailed Port Information: Provides detailed information about open ports on each host, including state, service name, product, and version.

# Requirements
Python 3.x
nmap Python library (python-nmap)
networkx library
matplotlib library
pandas library

# Install Dependencies Using:
  ```
  pip install python-nmap networkx matplotlib pandas
  ```

# UI Images:
![WhatsApp Image 2025-01-12 at 15 09 10_0bdbb4c2](https://github.com/user-attachments/assets/d2d68f0e-7406-4a0a-bb43-2554a4500229)
---
![WhatsApp Image 2025-01-12 at 15 08 56_5b5dacf4](https://github.com/user-attachments/assets/a46366d7-701c-4978-b787-2d2ce8eab3d8)

# Sample Output:
![WhatsApp Image 2025-01-12 at 16 55 10_d30a1018](https://github.com/user-attachments/assets/457cb033-7b3c-4a7e-85ce-dfebafa77bde)

The script will display potential threats detected based on known vulnerable ports.
It will generate a visual representation of the network topology.
Detailed port information for each host will be provided.
Based on the open ports and the services on these ports the reason of causing DoS attack can be detected.

# License
This project is licensed under the MIT License - see the LICENSE file for details.
