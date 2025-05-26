# [RDS - 2425 Task #3] - Extended Topology
In this task, you will design and implement the suggested topology in Mininet. This includes defining ports (interfaces), links, MAC addresses, and IP addresses as needed. Additionally, two different types of P4 devices will be deployed within the same network, requiring proper configuration to ensure connectivity and functionality.


## **Objectives**
- Plan and create complex topologies
- Manage different types of P4 devices
- Consolidate control plane rules design.


## Topology:
     h1     h2
       \   /
         s1
         |
         r1
       /   \
     r6     r2
     |      |
     r5     r3
       \   /
         r4
         |
         h3

### Network Configuration

| Device    |    Port<br>(Interface)     |  Connects To<br>(Device_Port)  |   IP Address   |   MAC Address          |
|-----------|-------------|---------------|----------------|------------------------|
|     h1    |      1      |     s1_1      |  10.0.1.1/24   | 00:04:00:00:00:01      |
|     h2    |      1      |     s1_2      |  10.0.1.2/24   | 00:04:00:00:00:02      |
|     s1    |      1      |     h1_1      |   NA | ... |
| s1 | 2 | h2_1 | NA | ... |
| s1 | 3 | r1_1 | NA | ... |
| r1 | 1 | s1_3 | 10.0.1.254/24 | ... |
| ... | 

`Define the network configuration as you see fit, use the above table as a template.`

## Task Description
### **Create the Topology**
- Define the network configuration, use the above table as a template. 
- Create the network topology in mininet, ensuring that each P4 device is instantiated correctly.
- Your mininet script needs to receive two jsons, one for the l2switch and another for all the l3switchs.
- Assign a unique Thrift port to each P4 device to prevent any conflicts during runtime.
- Since the exercise does not implement ARP, manually configure the ARP table for each host to correctly map gateway IP addresses to their MAC addresses.
- Set the default route manually on the host so that traffic is correctly forwarded through the designated gateway.

### **All the P4 code is given**

### **Rules**
   - Under `flows/` create files for `s1, r1, r2, r3, r4, r5 and r6`.
   - Define the rules following the usual syntax, lookup the P4 programs for table and actions names. 

### **Test your setup**
1. **Compile the P4 code**
```bash
p4c-bm2-ss --std p4-16  p4/l2switch.p4 -o json/l2switch.json
p4c-bm2-ss --std p4-16  p4/l3switch.p4 -o json/l3switch.json
```
2. **Run Mininet script**
```bash
sudo python3 mininet/task3-topo.py --json1 json/l2switch.json --json2 json/l3switch.json
```
3. **Inject the flows rules for each device**
```bash
simple_switch_CLI --thrift-port 909X < flows/r1-flows.txt
simple_switch_CLI --thrift-port 909Y < flows/r2-flows.txt
...
``` 
4. **Test**
```bash
mininet> xterm h1 h3
xterm h3> python3 -m http.server 8080
xterm h1> wget <h3_ip_addr>:8080
```
5. **Exit and Clean**
```bash
mininet> exit
$ sudo mn -c
```

## Debugging Tips

Here are some useful commands to help troubleshoot and verify your topology:

### 1. **Wireshark (Packet Capture)**

### 2. **ARP Table Inspection**
   - **Command:** `arp -n`
   - **Usage:** Check the ARP table on any Mininet host to ensure proper IP-to-MAC Default gateway resolution.
   - Example:
     ```bash
     mininet> h1 arp -n
     ```

### 3. **Interface Information**
   - **Command:** `ip link`
   - **Usage:** Display the state and configuration of network interfaces for each host or router.
   - Example:
     ```bash
     mininet> r1 ip link
     ```

### 4. **P4 Runtime Client for Monitoring**
   - **Command:** `sudo ./tools/nanomsg_client.py --thrift-port <r1_port or r2_port>`
   - **Usage:** Interact with the P4 runtime to inspect flow tables and rules loaded on each router.
   - Example:
     ```bash
     sudo ./tools/nanomsg_client.py --thrift-port 909X
     ```

These commands will help you inspect network traffic, verify ARP entries, check interface states, and interact directly with the P4 routers.
