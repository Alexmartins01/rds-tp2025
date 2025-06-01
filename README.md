# [RDS - 2425 Pratical Assignment] - Data Plane Programming

In this assignment, you will explore the practical aspects of data plane programming by implementing a custom
tunneling mechanism using the P4 programming language. The focus will be on designing and implementing
the My Sequence Label Protocol (MSLP), a simplified protocol for tunneling packets across a network with
multiple tunnels.
The task involves creating a custom packet header format and programming the dataplane to handle, encapsulate,
decapsulate, and route packets according to the MSLP protocol. This will require you to use the features of P4
to manipulate packet headers, manage metadata, and apply statically defined routing decisions.
In addition to implementing MSLP, you will also develop a stateful firewall capable of managing UDP traffic by
selectively opening UDP ports based on defined rules. This firewall will demonstrate your ability to implement
stateful processing and enforce basic security policies within the data plane.
As a final step, you will need to create a controller for your network. This controller must be capable of injecting
the flows in the data plane tables and balancing the usage of the tunnels.
This assignment provides an opportunity to work on critical aspects of programmable networking: creating
custom protocols, implementing stateful data plane functionalities, and adjusting your network according
to traffic demand. By working on these concepts, we aim to reinforce your understanding of advanced P4
programming techniques.

## Objectives
- MPLS
- Firewall
- Controller

## Topology
     h1 h2  h3
       \ | /
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
         h4


### Network Configuration

| DEVICE | PORT | CONNECTS_TO | IP_ADDRESS    | MAC_ADDRESS        |
|--------|------|--------------|---------------|---------------------|
| h1     | 1    | s1_1         | 10.0.1.1/24    | 00:04:00:00:00:01   |
| h2     | 1    | s1_2         | 10.0.1.2/24    | 00:04:00:00:00:02   |
| h3     | 1    | s1_4         | 10.0.1.3/24    | 00:04:00:00:00:03   |
| s1     | 1    | h1_1         | NA             | 00:aa:bb:00:00:01   |
| s1     | 2    | h2_1         | NA             | 00:aa:bb:00:00:02   |
| s1     | 2    | h3_1         | NA             | 00:aa:bb:00:00:03   |
| s1     | 3    | r1_1         | NA             | 00:aa:bb:00:00:03   |
| r1     | 1    | s1_3         | 10.0.1.254/24  | aa:00:00:00:01:01   |
| r1     | 2    | r2_1         | NA             | aa:00:00:00:01:02   |
| r1     | 3    | r6_1         | NA             | aa:00:00:00:01:03   |
| r2     | 1    | r1_2         | NA             | aa:00:00:00:02:01   |
| r2     | 2    | r3_1         | NA             | aa:00:00:00:02:02   |
| r3     | 1    | r2_2         | NA             | aa:00:00:00:03:01   |
| r3     | 2    | r4_1         | NA             | aa:00:00:00:03:02   |
| r4     | 1    | r3_2         | NA             | aa:00:00:00:04:01   |
| r4     | 2    | r5_2         | NA             | aa:00:00:00:04:02   |
| r4     | 3    | h3_1         | 10.0.8.254/24  | aa:00:00:00:04:03   |
| r5     | 1    | r6_2         | NA             | aa:00:00:00:05:01   |
| r5     | 2    | r4_2         | NA             | aa:00:00:00:05:02   |
| r6     | 1    | r1_3         | NA             | aa:00:00:00:06:01   |
| r6     | 2    | r5_1         | NA             | aa:00:00:00:06:02   |
| h4     | 1    | r4_3         | 10.0.8.1/24    | 00:04:00:00:00:03   |





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
```bash
p4c-bm2-ss --std p4-16  p4/l3switch_r1.p4 -o json/l3switch_r1.json
```
### Run
```bash
sudo python3 mininet/task4-topo.py --jsonR1 json/l3switch.json --jsonR2 json/l3switch_firewall.json --jsonR3 json/l3switch_r1.json --jsonS1 json/l2switch.json
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
mininet> h1 ping h4 -c 5
```
```bash
mininet> h4 ping h1 -c 5
```
### TCP Test - h1 as server (ALLOWED)
```bash
mininet> xterm h1 h4
```
***h1 as server*** 
```bash
xterm-h1> iperf3 -s
```
***h4 as client***
```bash
xterm-h4> iperf3 -c 10.0.1.1
```
### TCP Test - h4 as server (DENIED)

***h4 as server*** 
```bash
xterm-h4> iperf3 -s
```
***h1 as client***
```bash
xterm-h1> iperf3 -c 10.0.8.1
```

### UDP Test - h1 as server (ALLOWED)

***h1 as server*** 
```bash
xterm-h1> iperf3 -s
```
***h4 as client***
```bash
xterm-h4> iperf3 -c 10.0.1.1 -u
```

### UDP Test - h4 as server (DENIED)

***h2 as server*** 
```bash
xterm-h2> iperf3 -s
```
***h1 as client***
```bash
xterm-h1> iperf3 -c 10.0.8.1 -u
```

### Exit and Clean
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
     sudo ./tools/nanomsg_client.py --thrift-port 9090
     ```

These commands will help you inspect network traffic, verify ARP entries, check interface states, and interact directly with the P4 routers.
