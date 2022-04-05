from re import M
from socket import *
from struct import *
import sys
import argparse
import time
import threading
from queue import Queue
import json
import os
from datetime import datetime
from report import CreatePDF

class IpTcpAssembler:
    def __init__(self, src_ip, dest_ip, dest_port, method):
        # packet
        self.ip_header = b""
        self.tcp_header = b""
        self.packet = b""

        # ip header fields
        self.ip_ver = 4  # four-bit version field. For IPv4, this is always equal to 4.
        self.ip_ihl = 5  # 4 bits that specify the size of the IPv4 header (the number of 32-bit words in the header)
        self.ip_ver_ihl = (self.ip_ver << 4) + self.ip_ihl
        self.ip_tos = 0
        self.ip_total_len = (20 + 20)  # kernel will fill the correct total length
        self.ip_id = 54321  # uniquely identifying the group of fragments of a single IP datagram.
        self.ip_frag_flag_off = 0
        self.ip_ttl = 255
        self.ip_protocol = IPPROTO_TCP
        self.ip_header_checksum_placeholder = 0  # kernel will fill the correct checksum
        # inet_aton(...) -> Convert an IPv4 address from dotted-quad string format to 32-bit packed binary format
        self.ip_src_ip = inet_aton(src_ip)  # Spoof the source ip address if you want to
        self.ip_dst_ip = inet_aton(dest_ip)
        # the ! in the pack format string means network byte order (big-endian)
        self.ip_tmp_header = pack('! B B H H H B B H 4s 4s', self.ip_ver_ihl, self.ip_tos, self.ip_total_len,
                                  self.ip_id, self.ip_frag_flag_off, self.ip_ttl, self.ip_protocol,
                                  self.ip_header_checksum_placeholder, self.ip_src_ip, self.ip_dst_ip)

        self.ip_final_header = pack('! B B H H H B B H 4s 4s', self.ip_ver_ihl, self.ip_tos, self.ip_total_len,
                                    self.ip_id, self.ip_frag_flag_off, self.ip_ttl, self.ip_protocol,
                                    self.calc_checksum(self.ip_tmp_header), self.ip_src_ip, self.ip_dst_ip)

        # tcp header fields
        self.tcp_src_port = 1234
        self.tcp_dst_port = dest_port
        self.tcp_seq_bytenum = 0
        self.tcp_ack_bytenum = 0
        # the size of the TCP header in 32-bit words. min=5 words(20 Bytes) , max=15 words(60 Bytes)
        self.tcp_dataoffset = 5  # 4 bit field, size of tcp header, 5 * 4 = 20 bytes
        self.tcp_dataoffset_reserved_ns = (self.tcp_dataoffset << 4) + 0
        # tcp flags
        self.tcp_cwr = 0
        self.tcp_ece = 0
        self.tcp_urg = 0
        self.tcp_psh = 0
        self.tcp_rst = 0
        # 2 - ACK, 3 - SYN, 4 - FIN
        if (method == 2) or (method == 5):
            self.tcp_ack = 1
            self.tcp_syn = 0
            self.tcp_fin = 0
        elif method == 3:
            self.tcp_ack = 0
            self.tcp_syn = 1
            self.tcp_fin = 0
        elif method == 4:
            self.tcp_ack = 0
            self.tcp_syn = 0
            self.tcp_fin = 1
        self.tcp_flags = self.tcp_fin + (self.tcp_syn << 1) + (self.tcp_rst << 2) + (self.tcp_psh << 3) + (self.tcp_ack << 4) + (self.tcp_urg << 5) + (self.tcp_ece << 6) + (self.tcp_cwr << 7)

        self.tcp_rwnd = htons(5840)  # maximum allowed window size
        self.tcp_header_data_checksum_placeholder = 0
        self.tcp_urg_pointer = 0

        # the ! in the pack format string means network order
        self.tcp_tmp_header = pack('! H H L L B B H H H', self.tcp_src_port, self.tcp_dst_port, self.tcp_seq_bytenum,
                                   self.tcp_ack_bytenum, self.tcp_dataoffset_reserved_ns, self.tcp_flags, self.tcp_rwnd,
                                   self.tcp_header_data_checksum_placeholder, self.tcp_urg_pointer)

        # self.user_data = ''
        self.tcp_header_data_len = len(self.tcp_tmp_header)  # + len(self.user_data)

        self.pseudo_header = pack('! 4s 4s B B H', self.ip_src_ip, self.ip_dst_ip,
                                  self.tcp_header_data_checksum_placeholder, self.ip_protocol, self.tcp_header_data_len)

        self.psh = self.pseudo_header + self.tcp_tmp_header  # + user_data

        # make the tcp header again and fill the correct checksum - checksum is NOT in network byte order
        self.tcp_final_header = pack('! H H L L B B H H H', self.tcp_src_port, self.tcp_dst_port, self.tcp_seq_bytenum,
                                     self.tcp_ack_bytenum, self.tcp_dataoffset_reserved_ns, self.tcp_flags,
                                     self.tcp_rwnd, self.calc_checksum(self.psh), self.tcp_urg_pointer)

        # final full packet - scan packets don't have any data
        self.packet = self.ip_final_header + self.tcp_final_header  # + user_data

    # checksum functions needed for calculation checksum
    def calc_checksum(self, msg):  # complement sum of all 16-bit words in the header
        s = 0
        # loop taking 2 step characters at a time
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + msg[i + 1]  # 16-bit words
            s = s + w

        s = (s >> 16) + (s & 0xffff)  # carry check and correction can be performed after all additions.
        s = s + (s >> 16)  # if another carry is generated by this addition, another 1 must be added to the sum
        s = ~s & 0xffff  # complement and mask to 4 byte short
        return s


class IpTcpParser:
    def __init__(self, raw_data):
        # parse ethernet header
        self.eth_length = 14
        self.eth_header_pack = raw_data[:self.eth_length]
        self.eth_h_unp = unpack('! 6s 6s H', self.eth_header_pack)
        # EtherType, to indicate which protocol is encapsulated in the payload of the frame
        self.eth_protocol = self.eth_h_unp[2]

        # Parse IPv4 packets, IPv4 Protocol number = 0x0800
        if self.eth_protocol == 0x0800:
            # Parse IPv4 header
            # take first 20 characters for the ipv4 header
            self.ipv4_header_pack = raw_data[self.eth_length: self.eth_length + 20]
            self.ipv4_h_unp = unpack('! B B H H H B B H 4s 4s', self.ipv4_header_pack)

            self.version_ihl = self.ipv4_h_unp[0]
            self.ihl32 = self.version_ihl & 0xF  # 4 bits that specify the size of the IPv4 header (the number of 32-bit words in the header)
            self.ipv4_h_length = self.ihl32 * 4  # the size of the IPv4 header (in Bytes)
            self.header_offset_ip = self.ipv4_h_length + self.eth_length

            self.trans_protocol = self.ipv4_h_unp[6]  # the protocol used in the data portion of the IP datagram.

            self.rc_src_ip = inet_ntoa(self.ipv4_h_unp[8])
            # print("1 "+str(self.ipv4_h_unp[8]))
            # print("rc_src_ip: "+str(self.rc_src_ip))
            self.rc_dst_ip = inet_ntoa(self.ipv4_h_unp[9]) 
            # print("rc_dst_ip: "+str(self.rc_dst_ip))
            # Parse TCP Packets, TCP Protocol Number = 6
            # print("TCP trans protocol: " + str(self.trans_protocol))
            if self.trans_protocol == 6:
                self.tcp_header_pack = raw_data[self.header_offset_ip: self.header_offset_ip + 20]
                self.tcp_h_unp = unpack('! H H L L B B H H H', self.tcp_header_pack)

                self.rc_src_port = self.tcp_h_unp[0]
                self.rc_dst_port = self.tcp_h_unp[1]

                self.rc_tcp_flags = self.tcp_h_unp[5]
                self.cwr = self.rc_tcp_flags >> 7 &0x01
                self.ece = (self.rc_tcp_flags >> 6) & 0x01
                self.urg = (self.rc_tcp_flags >> 5) & 0x01
                self.ack = (self.rc_tcp_flags >> 4) & 0x01
                self.psh = (self.rc_tcp_flags >> 3) & 0x01
                self.rst = (self.rc_tcp_flags >> 2) & 0x01
                self.syn = (self.rc_tcp_flags >> 1) & 0x01
                self.fin = self.rc_tcp_flags & 0x01

                self.rwnd = self.tcp_h_unp[6]

def Json_Parse(port, service, state, victim_ip, attack_ip, fin, syn, rst, ack):
    object = {}
    object["port"] = port
    object["service"] = service
    object["state"] = state
    object["victim_ip"] = victim_ip
    object["attack_ip"] = attack_ip
    object["fin"] = fin
    object["syn"] = syn
    object["rst"] = rst
    object["ack"] = ack
    # json_object = json.dumps(object)
    # print(json_object)
    return object

def write_json(data, filename):
    cur_path = os.path.dirname(__file__)
    new_path = os.path.join(cur_path, '..', 'log', filename)
    # data = "["+ data + "]"
    # print(data)
    with open(new_path,"w") as f:
        json.dump(data,f)

# major drawback :
# If a firewall is running on the victim,
# attempts to connect() to every port on the system will almost always trigger a warning.
# Indeed, with modern firewalls, an attempt to connect to a single port which has been blocked or
# has not been specifically "opened" will usually result in the connection attempt being logged.
# Additionally, most servers will log connections and their source IP,
# so it would be easy to detect the source of a TCP connect() scan.

def connect_scan(port):
    with socket(AF_INET, SOCK_STREAM) as s:
        try:
            s.connect((dst_ip, port))
            
            try:
                service = getservbyport(port, "tcp")
                
            except:
                service = '----'
            with print_lock:
                print('{:<8} {:<15} {:<10}'.format(str(port), service, 'open'))
                

                # time.sleep(processing_delay)
        except:
            pass  # the remote system is offline, the port is closed, or some other error occurred along the way


def ack_syn_fin_window_scan(port):
    with socket(AF_INET, SOCK_RAW, IPPROTO_RAW) as a:  # create a raw socket of type IPPROTO_RAW that is a raw IP packet
        # tell kernel not to put in headers, since we are providing it, when using IPPROTO_RAW this is not necessary
        a.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
        # now start constructing the packet
        myscan = IpTcpAssembler(src_ip, dst_ip, port, scan_method)

        # Send the packet finally - the port specified has no effect
        a.sendto(myscan.packet, (dst_ip, port))  # put this in a loop if you want to flood the target
        time.sleep(int(processing_delay))
        # print(str(myscan.tcp_dst_port))


# The threader thread pulls an worker_send from the queue and processes it
def threader_sender():
    while True:
        # gets an worker_send from the queue
        worker_send = q.get()

        if scan_method == 1:
            # Run the job with the avail worker_send in queue (thread)
            connect_scan(worker_send)

        elif (scan_method == 2) or (scan_method == 3) or (scan_method == 4) or (scan_method == 5):
            ack_syn_fin_window_scan(worker_send)

        # completed with the job
        q.task_done()





def threader_receiver(json_vars):
    # create a AF_PACKET type raw socket (thats basically packet level)
    # define ETH_P_ALL    0x0003    Every packet
    s = socket(AF_PACKET, SOCK_RAW, ntohs(3))
    
    # infinite loop to receive packets
    while True:
        raw_data, addr = s.recvfrom(65535)
        myreceive = IpTcpParser(raw_data)
        try:
            if(myreceive.rc_src_port >= all_ports[-1]):
                break
        except:
            None
        
        if (myreceive.eth_protocol == 0x0800) and (str(myreceive.rc_src_ip) == str(dst_ip)) and (myreceive.trans_protocol == 6) :
            # print(myreceive.rc_src_port)
            # print("DST PORT: " + str(myreceive.rc_dst_port))
            # print(myreceive.rc_src_ip)
            

            try:
                service = getservbyport(myreceive.rc_src_port, "tcp")
            except:
                service = ''

            responsed_ports.append(myreceive.rc_src_port)
            # print(myreceive.ack)
            # print(myreceive.syn)
            # print(myreceive.fin)
            # 2- ACK, 3- SYN, 4- FIN, 5- Window
            if (scan_method == 2) and (myreceive.rst == 1):
                # If an RST comes back, the port is classified "unfiltered".
                # If nothing comes back, the port is said to be "filtered".
                # This scan type can help determine if a firewall is stateless (just blocks incoming SYN packets) or stateful (tracks connections and also blocks unsolicited ACK packets).
                print('{:<8} {:<15} {:<10}'.format(str(myreceive.rc_src_port), service, 'Unfiltered'))
                json_vars.append(Json_Parse(str(myreceive.rc_src_port),service,'Unfiltered',str(myreceive.rc_src_ip),str(myreceive.rc_dst_ip),str(myreceive.fin),str(myreceive.syn),str(myreceive.rst),str(myreceive.ack)))

                # json_var += Json_Parse(str(myreceive.rc_src_port),service,'Unfiltered')

            elif scan_method == 3:
                # If SYN/ACK is received, the port is open.
                if (myreceive.syn == 1) and (myreceive.ack == 1):
                    print('{:<8} {:<15} {:<10}'.format(str(myreceive.rc_src_port), service, 'Open'))
                    json_vars.append(Json_Parse(str(myreceive.rc_src_port),service,'Open',str(myreceive.rc_src_ip),str(myreceive.rc_dst_ip),str(myreceive.fin),str(myreceive.syn),str(myreceive.rst),str(myreceive.ack)))
                # If RST is received, the port is close.
                elif myreceive.rst == 1:
                    # print('{:<8} {:<15} {:<10}'.format(str(myreceive.rc_src_port), service, 'Close'))
                    json_vars.append(Json_Parse(str(myreceive.rc_src_port),'','Close',str(myreceive.rc_src_ip),str(myreceive.rc_dst_ip),str(myreceive.fin),str(myreceive.syn),str(myreceive.rst),str(myreceive.ack)))

            elif scan_method == 4:
                # FIN scan will work against any system where the TCP/IP implementation follows RFC 793
                # On some systems, a closed port responds with an RST upon receiving FIN packets
                # Microsoft Windows does not follow the RFC, and will ignore these packets even on closed ports.
                if myreceive.rst == 1:
                    print('{:<8} {:<15} {:<10}'.format(str(myreceive.rc_src_port), service, 'close on Linux OS'))
                    json_vars.append(Json_Parse(str(myreceive.rc_src_port),'','Close',str(myreceive.rc_src_ip),str(myreceive.rc_dst_ip),str(myreceive.fin),str(myreceive.syn),str(myreceive.rst),str(myreceive.ack)))
                else: 
                    json_vars.append(Json_Parse(str(myreceive.rc_src_port),'','Open',str(myreceive.rc_src_ip),str(myreceive.rc_dst_ip),str(myreceive.fin),str(myreceive.syn),str(myreceive.rst),str(myreceive.ack)))

                # an open or filtered or MW systems port should just drop them (it’s listening for packets with SYN set)

            elif scan_method == 5:
                # On some systems, open ports use a positive window size (even for RST packets)
                # while closed ones have a zero window. Window scan sends the same bare ACK probe as ACK scan
                if myreceive.rst == 1:
                    # If TCP RST response with zero window field is received, the port is close.
                    if myreceive.rwnd == 0:
                        # print('{:<8} {:<15} {:<10}'.format(str(myreceive.rc_src_port), service, 'close'))
                        # None
                        json_vars.append(Json_Parse(str(myreceive.rc_src_port),'','Closed',str(myreceive.rc_src_ip),str(myreceive.rc_dst_ip),str(myreceive.fin),str(myreceive.syn),str(myreceive.rst),str(myreceive.ack)))

                    # If TCP RST response with non-zero window field is received, the port is open.
                    else:
                        print('{:<8} {:<15} {:<10}'.format(str(myreceive.rc_src_port), service, 'Open'))
                        json_vars.append(Json_Parse(str(myreceive.rc_src_port),'','Open',str(myreceive.rc_src_ip),str(myreceive.rc_dst_ip),str(myreceive.fin),str(myreceive.syn),str(myreceive.rst),str(myreceive.ack)))

    
    # current_time = datetime.now().strftime("%H:%M_%m-%d-%Y")
    # write_json(json_vars,"scan_"+current_time+".json")
    write_json(json_vars,"scan_temp.json")
    CreatePDF('scan')


def UserInput():
    #Cài đặt tham số khi dùng trên terminal
    parser = argparse.ArgumentParser("MTA SCANNING TOOL")
    parser.add_argument("-t", "--target", help="Specify target IP", required=False)
    parser.add_argument("-n", "--min", type=int, required=False)
    parser.add_argument("-x", "--max", type=int, required=False)
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
        if args.min:
            if args.max:
                ports = range(int(args.min), int(args.max))
            else:
                ports = range(1,1024)
        else:
            ports = range(1,1024)
        if args.delay:
            processing_delay = args.delay
        else:
            processing_delay = 1
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

        #Delay Processing
        processing_delay = int(input('Enter the Processing Delay between each batch scan in second ( e.g. : 2 ) : '))

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
    return target, ports, scan_method, processing_delay


if __name__ == '__main__':
    src_ip = '192.168.133.145'
    json_vars = []
    
    dst_ip, all_ports, scan_method, processing_delay = UserInput()
    
    

    num_threads = 500

    print('Scan report for : ' + dst_ip)
    print('{:<8} {:<15} {:<10}'.format('PORT', 'SERVICE', 'STATE'))

    # a print_lock is what is used to prevent "double" modification of shared variables.
    # this is used so while one thread is using a variable, others cannot access
    # it. Once done, the thread releases the print_lock.
    # to use it, you want to specify a print_lock per thing you wish to print_lock.
    print_lock = threading.Lock()

    if scan_method != 1:
        responsed_ports = []

        # 1 thread for receiving
        tr = threading.Thread(target=threader_receiver, daemon=True, args=(json_vars,))  # classifying as a daemon, so they will die when the main dies
        tr.start()


    # Create the queue
    q = Queue()

    # jobs assigned.
    for worker_send in all_ports:
        q.put(worker_send)

    # how many threads are we going to allow for
    for x in range(num_threads):
        ts = threading.Thread(target=threader_sender, daemon=True)  # classifying as a daemon, so they will die when the main dies
        ts.start()

    start = time.time()

    # wait until the thread terminates.
    q.join()


    if scan_method != 1:

        other_ports = [x for x in all_ports if x not in responsed_ports]
        # 2 - ACK, 3 - SYN, 4 - FIN, 5 - Window
        if scan_method == 2:
            print('# of Not Shown : ' + str(len(other_ports)) + ' filtered')

        elif scan_method == 3:
            print('# of Not Shown : ' + str(len(other_ports)) + ' filtered')

        elif scan_method == 4:
            print('# of Not Shown : ' + str(len(other_ports)) + ' open or filtered or Microsoft Windows systems')

        elif scan_method == 5:
            print('# of Not Shown : ' + str(len(other_ports)) + ' filtered')

    print('Elapsed time : ' + str(time.time()-start))
