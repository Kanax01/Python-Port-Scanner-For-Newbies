# This program is a simple port scanner made by Kanax01 to teach people about Scapy and how to make a simple port scanner
# Visit my org Vulcan Security at https://github.com/Vulcan-Security
# My github is https://github.com/Kanax01


#----------------------------------------------------------------------------------------------------------------


# Basic libraries most projects will use that deal with the internet
import os
import threading
import time
import sys # allows for cli args but not ones like -p -C only ones like port.py help <-- only regular word no dashes
import ipaddress


# if doing something that requires making network packets or networking in general Scapy is the best
#import socket <--- Works too but is more limited and harder to use not to mention that Scapy is very optimised to make
#                                                                                                          python fast

# Scapy Library Imports
import scapy
from scapy import packet
from scapy.layers.inet import IP, TCP, ICMP
from scapy.sendrecv import send, sr1
from scapy.volatile import RandShort

#Cool Libraries
import pyfiglet # Turns regular text into ACSII art like what you see on the main screen
import argparse # Allows for -p -A and other cli args

from datetime import datetime

#helps scapy not spit error messages at least on replit
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

art1 = pyfiglet.figlet_format("PortPY")
art2 = pyfiglet.figlet_format("PortPY Help Menu")

print_lock = threading.Lock()

#these are the CLI Args which uses the ArgParser Libarary this allows us to control what is done
#by doing things like $ python3 port.py example.com -C (the -C tells us to scan the common open ports)
parser = argparse.ArgumentParser()

parser.add_argument("target", nargs='?', type = str)
parser.add_argument("-p", "--range", nargs='+', type = int) # allows the user to input a specific port range to scan
parser.add_argument("-C", "--common", action='store_true')
parser.add_argument("-A", "--all", action='store_true')
parser.add_argument("-t", "--timeout", type = int) #this tells the scanner how long to wait until it marks a port closed

args = parser.parse_args()


#Args To Vars
target = args.target
portRange = args.range
common = args.common
scan_all = args.all
timeout = args.timeout



#Port arrays
commonPorts = [80, 443, 21, 25, 22]
allPossible = range(1, 65535)

def clear_terminal(): #this clears the terminal so you screen isent clogged up with crap
    os.system('cls' if os.name == 'nt' else 'clear')


def portScanner(): # this is th acual functionality part of the scanner
    
    if scan_all: # scans all possible ports
        for port in allPossible:
            packet1 = IP(dst=target)/TCP(dport=port, flags="S")
            response1 = sr1(packet1, timeout, verbose=0)

            if response1 is None:
                continue
            elif response1.haslayer(TCP) and response1[TCP].flags == 0x12: # detects if port is open
                print(f"Port {port} Is Open")
                continue

    elif common: #scans common ports
        for port in commonPorts:
            packet1 = IP(dst=target)/TCP(dport=port, flags="S")
            response1 = sr1(packet1, timeout, verbose=0)

            if response1 is None:
                continue
            elif response1.haslayer(TCP) and response1[TCP].flags == 0x12:
                print(f"Port {port} Is Open")
                
    elif portRange:
        if len(portRange) == 2:
        # If user provides 2 numbers, create a range between them
            start_port, end_port = portRange
            ports_to_scan = range(start_port, end_port + 1)
            print(f"Scanning ports {start_port} to {end_port}")

            for ports in ports_to_scan:
                packet1 = IP(dst=target)/TCP(dport=ports, flags="S")
                response1 = sr1(packet1, timeout=2, verbose=0)

                if response1 is None:
                    continue
                elif response1.haslayer(TCP) and response1[TCP].flags == 0x12:
                    print(f"Port {ports} Is Open")
                
        else:
        # If user provides specific ports like -p 80 443 22
            ports_to_scan = portRange
            print(f"Scanning specific ports: {portRange}")

            for port in ports_to_scan:
                packet1 = IP(dst=target)/TCP(dport=port, flags="S")
                response1 = sr1(packet1, timeout=2, verbose=0)

                if response1 is None:
                    continue
                    
                elif response1.haslayer(TCP) and response1[TCP].flags == 0x12:
                    print(f"Port {port} Is Open")
        


def helpMenu(): # this is the help menu function that tells users how to use the tool
    clear_terminal()
    print(art2)
    print("A Simple Port Scanner Using Scapy")
    print("-----------------------------------------------------------------------------")
    print("")
    print("Root access needed so run with sudo or in a root access terminal if on Kali")
    print("")
    print("Example Uses:")
    print("")
    print("$ sudo python port.py example.com -C -t 3")
    print("$ sudo python port.py 123.56.78.9 -p 10 20")
    print("")
    print("-----------------------------------------------------------------------------")
    print("")
    print("Operators:")
    print("")
    print("-A <-- Scan all possible ports")
    print("")
    print("-p <-- type port range e.g:")
    print(">> $ sudo python port.py 192.168.1.1 -p 10 2090")
    print("")
    print("In -p if you add more than 2 numbers it will scan those specific ports")
    print(">> $ sudo python port.py example.com -p 80 443 53")
    print("")
    print("-C <-- Scans all common ports")
    print("")
    print("-t <-- Timeout time, set how long before port is marked offline e.g:")
    print(">> $ sudo python port.py 123.73.83.2 -C -t 2 (in seconds)")
    print("")
    print("-----------------------------------------------------------------------------")
    os._exit # exits program

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "help": # detects if help is used to redirect to help menu
        helpMenu()
        
    if not args.target: # this tells people that u can use (port.py help) to go to help menu
        print("")
        clear_terminal()
        print(art1)
        print("-----------------------------------------------------------------------------")
        print("Root access needed so run with sudo or in a root access terminal if on Kali") # Scapy needs root perms
        print("Use:")
        print("python port.py help")
        print("To view the help menu")
        sys.exit(1)

    
    portScanner()

if __name__ == "__main__":
    main()
