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
TIMEOUTS = 0

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
    curr_name = None
    tries = 3
    done = False

    while not done and tries > 0:
        try:
            curr_addr = icmpSocket.recvfrom(512)[1][0]
            done = True
            timeRecieved = time.time() * 1000

            try:
                curr_name = socket.gethostbyaddr(curr_addr)[0]
            except socket.error:
                curr_name = curr_addr

            # Round to 2dp
            sys.stdout.write(str("{0:.2f}".format(timeRecieved-timeSent))+"ms ")
        except socket.timeout:
            tries-=1
            sys.stdout.write("* ")
    
    timeouts = 3 - tries

    return (str(curr_addr), str(curr_name), timeouts)
    
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

    # Do this 3 times so we can get an average ping delay
    timeouts = 0 # Keep track of the amount of timeouts occuring
    for x in range(0, 3):
        timeSent = sendOnePing(s, destinationAddress, ID) # Send the trace packet to destination address
        addresses = receiveOnePing(r, destinationAddress, ID, timeout, timeSent) # Attempt to receive packet
        curr_name = addresses[1]
        curr_addr = addresses[0]
        curr_host = "("+curr_name+") - "+"["+curr_addr+"]"
        if x == 1:
            timeouts+= addresses[2]

    # After 3 pings have been listed, print the current host
    sys.stdout.write(str(curr_host)+"\n")

    # Close sockets
    s.close()
    r.close()
    return (curr_addr, timeouts)

def ping(host, timeout=1, protocol="udp"):
    try:
        ip = socket.gethostbyname(host)
    except:
        print("IP not found for address: "+host)
        return

    print("Tracing route to '"+host+"' over a maximum of "+str(MAX_HOPS)+" hops:")

    curr_addr = None
    ttl = 1
    timeouts = 0
    while curr_addr != ip and ttl < MAX_HOPS:
        trace = doOnePing(ip,timeout, ttl, protocol)
        curr_addr = trace[0]
        timeouts+=trace[1]
        ttl+=1
    print(timeouts)
    

#ping("localhost", 5, "udp")
#ping("files.anifox.moe", 5, "icmp")
#ping("lancaster.ac.uk", 1, "udp")
ping("google.co.uk",1, "udp")
#ping("google.co.uk",1, "udp")

