import sys
import re
from socket import *
from struct import *
import subprocess
import time
import threading
import argparse
from queue import Queue
from services import services

def UserInput():
    #Cài đặt tham số khi dùng trên terminal
    parser = argparse.ArgumentParser("MTA SCANNING TOOL")
    parser.add_argument("-t", "--target", help="Specify target IP", required=False)
    parser.add_argument("-p", "--ports", type=int, nargs="+")
    parser.add_argument("-s", "--scantype", help="Scan type, connect/ack/syn/fin/window", required=False)
    parser.add_argument("-d", "--delay", help="Processing Delay", required=False)
    args = parser.parse_args()

    if args.target:
        arg_target  = args.target
        error = ("Invalid Input")
        try:
            target = gethostbyname(arg_target )
        except (UnboundLocalError, gaierror):
            print("\n[-]Invalid format. Please use a correct IP or web address[-]\n")
            sys.exit()
        if args.scantype:
            scantype = args.scantype.lower()
        else:
            print("Scan type, connect/ack/syn/fin/window")
            sys.exit()
        if args.ports:
            ports = args.ports
        else:
            ports = range(1, 1024)
    else:
        # User input: Target
        input_target = input("Enter your target IP address or URL here: ")
        error = ("Invalid Input")
        try:
            target = gethostbyname(input_target)
        except (UnboundLocalError, socket.gaierror):
            print("\n[-]Invalid format. Please use a correct IP or web address[-]\n")
            sys.exit()

        #User input validation: IP & End port --> target must be a valid IPv4 address AND portnumber is integer with a maximum of 65535.
        port_range_min = int(input('MIN Port # : '))
        port_range_max = int(input('MAX Port # : '))
        ports = range(port_range_min, port_range_max)

        #User input: Scan type
        scantype = input("Enter the Scan-type (connect = c / ack = a / syn = s / fin = f / window = w): ")

    if scantype == "connect" or scantype == "c" or scantype == "C":
        scan_method = 1
    elif scantype == "ack" or scantype == "a" or scantype == "A":
        scan_method = 2
    elif scantype == "syn" or scantype == "s" or scantype == "S":
        scan_method = 3
    elif scantype == "fin" or scantype == "f" or scantype == "F":
        scan_method = 4
    elif scantype == "window" or scantype == "w" or scantype == "W":
        scan_method = 5
    else:
        print("Scan type not supported, Usage: (connect = c / ack = a / syn = s / fin = f / window = w)")
    return target, ports, scan_method

if __name__ == "__main__":
    dst_ip, all_ports, scan_method = UserInput()
    print(str(dst_ip))
    print((all_ports))
    print(scan_method)