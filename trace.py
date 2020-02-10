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
    
def receiveOnePing(icmpSocket, destinationAddress, timeout, timeSent):
    curr_addr = None
    curr_name = None
    tries = 3
    done = False

    # Attempt to receive trace 3 times, if successfully received then break loop
    while not done and tries > 0:
        try:
            curr_addr = icmpSocket.recvfrom(512)[1][0] # Get the address from the packet
            timeRecieved = time.time() * 1000 # Record time of receiving
            done = True

            # Resolve name from IP
            try:
                curr_name = socket.gethostbyaddr(curr_addr)[0]
            except socket.error:
                curr_name = curr_addr

            # Round to 2DP
            sys.stdout.write(str("{0:.2f}".format(timeRecieved-timeSent))+"ms ")
        except socket.timeout: # If the socket times-out then decrement the 'tries' counter, write a * to console
            tries-=1
            sys.stdout.write("* ")
    
    timeouts = 3 - tries # Work out the amount of timeouts

    return (str(curr_addr), str(curr_name), timeouts)
    
def sendOnePing(icmpSocket, destinationAddress):

    ID = os.getpid() & 0xFFFF # Generate system identifer

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, ID, 1) # Create dummy header packet
    data = struct.pack("d", time.time()) #  Data packet

    chkSum = checksum(bytearray(header+data)) # Work out the checksum for the packet

    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, chkSum, ID, 1) # Remake the header with the checksum
    packet = header+data # Include both header and body

    icmpSocket.sendto(packet, (destinationAddress, PORT)) # Send to address

    return time.time() * 1000 # Record time of sending

    
def doOnePing(destinationAddress, timeout, ttl, protocol):

    # Depending on the provided socket type, create a UDP or ICMP protocol
    protocol = socket.getprotobyname(protocol)

    if protocol == 17:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, protocol) # UDP protocol
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol) # ICMP protocol
    s.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl) # Configure socket with TTL

    r = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("ICMP")) # Create receiving socket
    r.settimeout(timeout) # Set timeout on receiving socket

    sys.stdout.write(str(ttl)+" ")

    timeouts = 0 # Keep track of the amount of timeouts occuring
    for x in range(0, 3): # Do this 3 times so we can get an average ping delay
        timeSent = sendOnePing(s, destinationAddress) # Send the trace packet to destination address
        addresses = receiveOnePing(r, destinationAddress, timeout, timeSent) # Attempt to receive packet
        curr_name = addresses[1]
        curr_addr = addresses[0]
        curr_host = "("+curr_name+") - "+"["+curr_addr+"]"
        timeouts+= addresses[2] # Keep track of the timeouts

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
    print("Total timeouts: "+str(timeouts))
    

#ping("localhost", 5, "udp")
#ping("files.anifox.moe", 5, "icmp")
#ping("lancaster.ac.uk", 1, "udp")
ping("google.co.uk",1, "udp")
#ping("google.co.uk",1, "udp")

