#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

from socket import *
import socket
import os
import sys
import struct
import time
import select
import binascii


ICMP_ECHO_REQUEST = 8 #ICMP type code for echo request messages
ICMP_ECHO_REPLY = 0 #ICMP type code for echo reply messages
MAX_HOPS = 30
PORT = 33434

def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2  
    count = 0

    while count < countTo:
        thisVal = string[count+1] * 256 + string[count]
        csum = csum + thisVal 
        csum = csum & 0xffffffff  
        count = count + 2
    
    if countTo < len(string):
        csum = csum + string[len(string) - 1]
        csum = csum & 0xffffffff 
    
    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum 
    answer = answer & 0xffff 
    answer = answer >> 8 | (answer << 8 & 0xff00)

    answer = socket.htons(answer)

    return answer
    
def receiveOnePing(icmpSocket, destinationAddress, ID, timeout, timeSent):
    curr_addr = None
    curr_host = None
    tries = 3
    done = False

    while not done and tries > 0:
        try:
            recvPacket, curr_addr = icmpSocket.recvfrom(512)
            done = True
            timeRecieved = time.time() * 1000
            curr_addr = curr_addr[0]

            try:
                curr_name = socket.gethostbyaddr(curr_addr)[0]
            except socket.error:
                curr_name = curr_addr
        
            curr_host = "("+curr_name+") - "+"["+curr_addr+"]"
            sys.stdout.write(str(timeRecieved-timeSent)+"ms ")
        except socket.timeout:
            tries-=1
            sys.stdout.write("* ")
    
    sys.stdout.write(str(curr_host)+"\n")
    return curr_addr
    
def sendOnePing(icmpSocket, destinationAddress, ID):

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, ID, 1)
    data = struct.pack("d", time.time())

    chkSum = checksum(bytearray(header+data))

    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, chkSum, ID, 1)
    packet = header+data

    icmpSocket.sendto(packet, (destinationAddress, PORT))

    return time.time() * 1000

    
def doOnePing(destinationAddress, timeout, ttl, protocol): 
    protocol = socket.getprotobyname(protocol)

    # UDP protocol
    if (protocol == 17):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, protocol)
    else: # ICMP protocol
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol) 
    s.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

    r = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("ICMP"))
    r.settimeout(timeout)

    sys.stdout.write(str(ttl)+" ")

    ID = os.getpid() & 0xFFFF

    timeSent = sendOnePing(s, destinationAddress, ID)
    curr_addr = receiveOnePing(r, destinationAddress, ID, timeout, timeSent)

    s.close()
    return curr_addr

def ping(host, timeout=1, protocol="udp"):
    try:
        ip = socket.gethostbyname(host)
    except:
        print("IP not found for address: "+host)
        return

    print("Tracing route to '"+host+"' over a maximum of "+str(MAX_HOPS)+" hops:")

    curr_addr = None
    ttl = 1
    while curr_addr != ip and ttl < MAX_HOPS:
        curr_addr = doOnePing(ip,timeout, ttl, protocol)
        ttl+=1
    

#ping("localhost", 5, "udp")
ping("files.anifox.moe", 5, "icmp")
ping("lancaster.ac.uk", 5)
#ping("google.co.uk",1, "icmp")
#ping("google.co.uk",1, "udp")

