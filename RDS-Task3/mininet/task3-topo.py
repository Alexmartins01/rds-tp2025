#!/usr/bin/env python3
"""
P4 Mininet Integration Script

Description:
This script sets up a Mininet topology with a P4-enabled software switch. 
It parses command-line arguments to configure the switch architecture, 
Thrift communication, and JSON configuration for P4 execution.

Usage:
python script.py --json <path_to_compiled_p4_json> [--behavioral-exe <switch_exe>] [--thrift-port <port_number>]

Arguments:
- --json1: Path to the compiled P4 JSON configuration file (required).
- --json2: Path to the compiled P4 JSON configuration file (required).
- --behavioral-exe: Software switch executable (default: 'simple_switch').
- --thrift-port: Thrift server port for runtime switch communication (default: 9090).

Dependencies:
- Mininet
- P4 (BMv2, Thrift)
- Python 3.x

Author: jfpereira
Date: 17-02-2025
"""

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI

from p4_mininet import P4Switch, P4Host

import argparse
from time import sleep

# This parser identifies three arguments:  
#  
# --behavioral-exe (default: 'simple_switch')  
## Specifies the architecture of our software switch as 'simple_switch'.  
## Any P4 program targeting this architecture must be compiled against 'v1model.p4'.  
#  
# --thrift-port (default: 9090)  
## Defines the default server port for a Thrift server.  
## The P4Switch instantiates a Thrift server, enabling runtime communication with the software switch.  
#  
# --json (required)  
## Specifies the path to the JSON configuration file, which is the output of the P4 program compilation.  
## This is the only mandatory argument needed to run the script.
parser = argparse.ArgumentParser(description='Task 1')
parser.add_argument('--behavioral-exe', help='Path to behavioral executable',
                    type=str, action="store", default='simple_switch')
parser.add_argument('--thrift-port', help='Thrift server port for table updates',
                    type=int, action="store", default=9090)
parser.add_argument('--json1', help='Path to JSON config file',
                    type=str, action="store", required=True)
parser.add_argument('--json2', help='Path to JSON config file',
                    type=str, action="store", required=True)

args = parser.parse_args()

# Mininet assigns MAC addresses automatically, but we need to control this process  
# to ensure that the MAC addresses match our network design.  
# This is crucial because the rules we set in the data plane tables must use  
# the exact MAC addresses of the network.
sw_mac_base = "00:aa:bb:00:01:%02x"
router_mac_base = "aa:00:00:00:%02x:%02x"
host_mac_base = "00:04:00:00:00:%02x"

# In Mininet, IP addresses are assigned only to hosts.  
# Any other IP-related tasks, if required, are handled by the controller.
host_ip_base =  "10.0.%d.%d/24"

class SingleSwitchTopo(Topo):
    def __init__(self, sw_path, json1, json2, thrift_port, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)
        
        # In Mininet, we create switches, hosts, and links.
        # Every network device — whether it's an L2 switch, L3 switch, firewall, or load balancer — is treated as a switch in Mininet.        

        # TASK: follow the topology presented in the README.md
        s1 = self.addSwitch('s1',
                        sw_path = sw_path,
                        json_path = json1,
                        thrift_port = thrift_port)
        
        r1 = self.addSwitch('r1',
                        sw_path = sw_path,
                        json_path = json2,
                        thrift_port = thrift_port+1)
        r2 = self.addSwitch('r2',
                        sw_path = sw_path,
                        json_path = json2,
                        thrift_port = thrift_port+2)
        r3 = self.addSwitch('r3',
                        sw_path = sw_path,
                        json_path = json2,
                        thrift_port = thrift_port+3)
        r4 = self.addSwitch('r4',
                        sw_path = sw_path,
                        json_path = json2,
                        thrift_port = thrift_port+4)
        r5 = self.addSwitch('r5',
                        sw_path = sw_path,
                        json_path = json2,
                        thrift_port = thrift_port+5)
        r6 = self.addSwitch('r6',
                        sw_path = sw_path,
                        json_path = json2,
                        thrift_port = thrift_port+6)

        h1 = self.addHost('h1',
                    ip = host_ip_base % (1,1),
                    mac = host_mac_base % 1)
        h2 = self.addHost('h2',
                    ip = host_ip_base % (1,2),
                    mac = host_mac_base % 2)
        h3 = self.addHost('h3',
                    ip = host_ip_base % (8,1),
                    mac = host_mac_base % 3)
        
        self.addLink(h1, s1, port2= 1, addr2= sw_mac_base % 1)
        self.addLink(h2, s1, port2= 2, addr2= sw_mac_base % 2)

        self.addLink(s1, r1, port1= 3, port2= 1, addr1= sw_mac_base % 1, addr2= router_mac_base % (1,1))
        self.addLink(r1, r2, port1= 2, port2= 1, addr1= router_mac_base % (1,2), addr2= router_mac_base % (2,1))
        self.addLink(r1, r6, port1= 3, port2= 1, addr1= router_mac_base % (1,3), addr2= router_mac_base % (6,1))
        self.addLink(r2, r3, port1= 2, port2= 1, addr1= router_mac_base % (2,2), addr2= router_mac_base % (3,1))
        self.addLink(r3, r4, port1= 2, port2= 1, addr1= router_mac_base % (3,2), addr2= router_mac_base % (4,1))
        self.addLink(r4, r5, port1= 3, port2= 2, addr1= router_mac_base % (4,3), addr2= router_mac_base % (5,2))
        self.addLink(r5, r6, port1= 1, port2= 2, addr1= router_mac_base % (5,1), addr2= router_mac_base % (6,2))
        
        self.addLink(h3, r4, port2= 2, addr2= router_mac_base % (4,2))


def main():
    # The 'topo' instance represents the network topology in Mininet.
    # It defines the structure of switches, hosts, and links in the simulation.
    topo = SingleSwitchTopo(args.behavioral_exe,
                            args.json1,
                            args.json2,  # new arg
                            args.thrift_port)

    # The host class used in this topology is P4Host.  
    # The switch class used is P4Switch.  
    # 'net' is the instance that represents our Mininet simulation.  
    net = Mininet(topo = topo,
                  host = P4Host,
                  switch = P4Switch,
                  controller = None)

    net.start()

    # Allow time for the host and switch configurations to take effect.
    sleep(1)

    # In this setup, we're not implementing the ARP protocol. Therefore, we manually configure the ARP entry
    # so that host h1 can correctly resolve the MAC address for the gateway when sending packets.

    # TASK: add arp entries and gateways to all hosts according to the topology
    h1 = net.get('h1')
    h1.setARP("10.0.1.254", "aa:00:00:00:01:01")
    h1.setDefaultRoute("dev eth0 via 10.0.1.254")
    
    h2 = net.get('h2')
    h2.setARP("10.0.1.254", "aa:00:00:00:01:01")
    h2.setDefaultRoute("dev eth0 via 10.0.1.254")
    
    h3 = net.get('h3')
    h3.setARP("10.0.8.254", "aa:00:00:00:04:02")
    h3.setDefaultRoute("dev eth0 via 10.0.8.254")


    print("Ready !")

    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()
    