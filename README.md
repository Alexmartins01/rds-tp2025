# [RDS - 2425 Task #4] - Stateful Firewall

In this task we will develop a Stateful Firewall applying Bloom Filters by using P4 Registers. This type of firewall keeps track of active connections and makes filtering decisions based on the state of a connection rather than just individual packets. Bloom Filters are a probabilistic data structure that efficiently checks membership in a set with minimal memory usage. It can determine whether an element might be in a set (with some false positives) or definitely isn’t. Registers in P4 are stateful memory elements that can store values across different packet processing stages, unlike standard P4 tables, which are stateless.

## Objectives
- Learn about TCP and UDP header.
- Learn how to store state in a P4 program.
- Learn how to implement Bloom Filters using P4 Registers.
- Create a Stateful Firewall that blocks incoming TCP and UDP traffic that was not initiated by the host behind the firewall (h2).

## Topology
`h1 -- r1 -- r2+firewall -- h2`


### Network Configuration

| Device   | Interface/Port        | MAC Address          | IP Address       |
|----------|-----------------------|----------------------|------------------|
| h1       | h1-eth0               | 00:04:00:00:00:01    | 10.0.1.1/24      |
| r1       | r1-eth1               | aa:00:00:00:01:01    | 10.0.1.254/24    |
| r1       | r1-eth2               | aa:00:00:00:01:02    | 10.0.12.12/24    |
| r2       | r2-eth1               | aa:00:00:00:02:01    | 10.0.12.21/24    |
| r2       | r2-eth2               | aa:00:00:00:02:02    | 10.0.2.254/24    |
| h2       | h2-eth0               | 00:04:00:00:00:02    | 10.0.2.1/24      |


## Task Description
### **Create the Topology**
- Everything is given. `mininet/task4-topo.py`
### **P4 l3 switch for R1**
- Everything is given. `p4/l3switch.p4`
### **P4 l3 switch + firewall for R2**
#### copy l3switch.p4
```bash
cp p4/l3switch.p4 p4/l3switch_firewall.p4
```
#### TCP and UDP Header
- Define TCP and UDP headers in `p4/l3switch_firewall.p4`.
#### TCP and UDP Parsers
- Define the parser for TCP and UDP in `p4/l3switch_firewall.p4`.
### Ingress
- Declare two Registers (Bloom Filter) with 4096 bit in length(entries) and 1 bit width (entry size) 
- Declare two 32 bit variables that will work as indexes for the Bloom Filter.
- Declare two 1 bit variables to collect the values of the Bloom Filter.
- Declare an Action that computes the hashes, define which protocol fields will be used to compute the hashes. Use 2 hash algorithms for the Bloom Filter, one for each Register.
- Define the needed logic, in the control block (apply), so when a packet arrives from port 2 (port connected to host 2), we compute the hashes and write on the Bloom Filter, otherwise, compute the hashes and read from the bloom filters checking if the stream/flow exist. Block the traffic if it does not exist.


### Compile P4
```bash
p4c-bm2-ss --std p4-16  p4/l3switch.p4 -o json/l3switch.json
```
```bash
p4c-bm2-ss --std p4-16  p4/l3switch_firewall.p4 -o json/l3switch_firewall.json
```
```bash
p4c-bm2-ss --std p4-16  p4/l2switch.p4 -o json/l2switch.json
```
### Run
```bash
sudo python3 mininet/task4-topo.py --jsonR1 json/l3switch.json --jsonR2 json/l3switch_firewall.json --jsonS1 json/l2switch.json
```

### Load flow rules
```bash
simple_switch_CLI --thrift-port 9090 < flows/s1-flows.txt
```
```bash
simple_switch_CLI --thrift-port 9091 < flows/r1-flows.txt
```
```bash
simple_switch_CLI --thrift-port 9092 < flows/r2-flows.txt
```
```bash
simple_switch_CLI --thrift-port 9093 < flows/r3-flows.txt
```
```bash
simple_switch_CLI --thrift-port 9094 < flows/r4-flows.txt
```
```bash
simple_switch_CLI --thrift-port 9095 < flows/r5-flows.txt
```
```bash
simple_switch_CLI --thrift-port 9096 < flows/r6-flows.txt
```
## Tests
### ICMP Test (ALLOWED)
```bash
mininet> h1 ping h3 -c 5
```
```bash
mininet> h3 ping h1 -c 5
```
### TCP Test - h1 as server (ALLOWED)
```bash
mininet> xterm h1 h3
```
***h1 as server*** 
```bash
xterm-h1> iperf3 -s
```
***h3 as client***
```bash
xterm-h3> iperf3 -c 10.0.1.1
```
### TCP Test - h3 as server (DENIED)

***h3 as server*** 
```bash
xterm-h3> iperf3 -s
```
***h1 as client***
```bash
xterm-h1> iperf3 -c 10.0.2.1
```

### UDP Test - h1 as server (ALLOWED)

***h1 as server*** 
```bash
xterm-h1> iperf3 -s
```
***h3 as client***
```bash
xterm-h3> iperf3 -c 10.0.1.1 -u
```

### UDP Test - h3 as server (DENIED)

***h2 as server*** 
```bash
xterm-h2> iperf3 -s
```
***h1 as client***
```bash
xterm-h1> iperf3 -c 10.0.2.1 -u
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
     sudo ./tools/nanomsg_client.py --thrift-port 9090
     ```

These commands will help you inspect network traffic, verify ARP entries, check interface states, and interact directly with the P4 routers.
