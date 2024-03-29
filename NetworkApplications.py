#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import socket
import os
import sys
import struct
import time
import random
import traceback # useful for exception handling
import threading


def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.203.')
        parser.set_defaults(func=ICMPPing, hostname='lancaster.ac.uk')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=4)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=4, protocol='icmp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)
        
        parser_pt = subparsers.add_parser('paris-traceroute', aliases=['pt'],
                                         help='run paris-traceroute')
        parser_pt.set_defaults(timeout=4, protocol='icmp')
        parser_pt.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_pt.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_pt.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_pt.set_defaults(func=ParisTraceroute)

        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        args = parser.parse_args()
        return args


class NetworkApplication:

    def checksum(self, dataToChecksum: str) -> str:
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): ttl=%d time=%.2f ms" % (packetLength, destinationHostname, destinationAddress, ttl, time))
        else:
            print("%d bytes from %s: ttl=%d time=%.2f ms" % (packetLength, destinationAddress, ttl, time))

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))

    def printMultipleResults(self, ttl: int, destinationAddress: str, measurements: list, destinationHostname=''):
        latencies = ''
        noResponse = True
        for rtt in measurements:
            if rtt is not None:
                latencies += str(round(rtt, 3))
                latencies += ' ms  '
                noResponse = False
            else:
                latencies += '* ' 

        if noResponse is False:
            print("%d %s (%s) %s" % (ttl, destinationHostname, destinationAddress, latencies ))
        else:
            print("%d %s" % (ttl, latencies))

class ICMPPing(NetworkApplication):
    

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout):
        # 1. Wait for the socket to receive a reply
        icmpSocket.settimeout(timeout)
        start_time = time.time()
        data, addr = icmpSocket.recvfrom(1024)
        # 2. Once received, record time of receipt, otherwise, handle a timeout
        
        end_time = time.time()
        time_received = end_time - start_time
        print("time received: " , time_received)
        # 3. Compare the time of receipt to time of sending, producing the total network delay
        # 4. Unpack the packet header for useful information, including the ID
        icmp_header = data[20:28]
        icmp_type, icmp_code, icmp_cheksum, id, icmp_seq = struct.unpack("BBHHH", icmp_header)
        print("Ping Received ! ID:",id)
        # 5. Check that the ID matches between the request and reply
        # 6. Return total network delay
        return time_received
    pass

    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        # 1. Build ICMP header
        icmp_type = 8
        icmp_code = 0
        icmp_checksum = 0
        icmp_seq = 1
        icmp_header = struct.pack("BBHHH",icmp_type, icmp_code,icmp_checksum, ID, icmp_seq)
        #print("one ping called")
        # 2. Checksum ICMP packet using given function
        icmp_checksum = NetworkApplication.checksum(self,icmp_header)
        # 3. Insert checksum into packet
        icmp_header = struct.pack("BBHHH",icmp_type, icmp_code,icmp_checksum, ID, icmp_seq)
        startTime = time.time()
        icmpSocket.sendto(icmp_header, (destinationAddress,1))
        # 5. Record time of sending
        endTime = time.time()
        elapsedTime = (endTime - startTime)
        print("One Ping Sent ! ID:",ID)
     #   self.printOneResult(destinationAddress, len(icmp_header),20,)
       


        return elapsedTime
       # print("time Elapsed: ",(elapsedTime),"seconds")
    pass

    def doOnePing(self, destinationAddress, timeout):
        # 1. Create ICMP socket
        icmpS = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        #print("do one ping")
        icmpS.settimeout(timeout)
        # 2. Call sendOnePing function
        sent = self.sendOnePing(icmpS,destinationAddress,1)
        # 3. Call receiveOnePing function
        recv = self.receiveOnePing(icmpS,destinationAddress,1,5)
        # 4. Close ICMP socket
        icmpS.close()
        # 5. Return total network delay
        print("Total Network Delay :", (recv - sent) * 1000 ,"seconds")
        pass

    def __init__(self, args):
        print('Ping to: %s...' % (args.hostname))
        # 1. Look up hostname, resolving it to an IP address
        hostName = socket.gethostbyname(args.hostname)
        print(hostName)
        # 2. Call doOnePing function, approximately every second
        stop = False
        while not stop:
         self.doOnePing(hostName,5)
         time.sleep(1)
        # 3. Print out the returned delay (and other relevant details) using the printOneResult method
          # Example use of printOneResult - complete as appropriate
        # 4. Continue this process until stopped

        


class Traceroute(NetworkApplication):

    def __init__(self, args):
        # Please ensure you print each result using the printOneResult method!
        hostName = socket.gethostbyname(args.hostname)
        print('Traceroute to: %s...' % (args.hostname),hostName,"30 max hops") 
        ttl = 1
        icmpS = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) 
        
        while True:
         ovr_time = [] # making a list to store the times 
         recv_time = 0
         time_sent = 0
         checksum = 0
         icmpS.setsockopt(socket.SOL_IP,socket.IP_TTL,ttl)
         send_data = struct.pack("BBHHH", 8, checksum,0,ttl, 1)
         checksum = NetworkApplication.checksum(self,send_data)
         send_data = struct.pack("BBHHH", 8, 0,checksum,ttl, 1)

         for i in range(3):
          icmpS.sendto(send_data ,(hostName,1))
          time_sent = time.time() ## record time
          recv_data, address = icmpS.recvfrom(1024)
          recv_time = time.time() # stop the tim
          ovr_time.append((recv_time - time_sent)*1000) #appends the time value to the list
          
         try:  
           addrName = address[0] 
           icmp_type, code, checksume, id, seq = struct.unpack("BBHHH",recv_data[20:28])
           host = socket.gethostbyaddr(addrName)[0]
           #print(f"{ttl}: {host} ({addrName})   {ovr_time} ms")
           self.printMultipleResults(ttl,addrName, ovr_time ,host)
           icmpS.settimeout(5)
         except socket.herror:
            hosterr = address[0]
            #print(f"{ttl}: {hosterr}, {addrName}")
            self.printMultipleResults(ttl,addrName, ovr_time ,hosterr)
            icmpS.settimeout(5)
         if icmp_type == 0:
            break
        
         ttl += 1
        if __name__ == "__main__":
         self.printOneResult(address,len(recv_data),20,ttl,hostName)






class ParisTraceroute(NetworkApplication):

    def __init__(self, args):
        # Please ensure you print each result using the printOneResult method!
        hostName = socket.gethostbyname(args.hostname)
        print('Traceroute to: %s...' % (args.hostname),hostName,"30 max hops") 
        ttl = 1
        icmpS = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) 
        packet_loss = 0
        
        while True:
            
         checksum = 0
         ovr_time = [] # making a list to store the times 
         recv_time = 0
         time_sent = 0
         packetSent = 0
         packetRecvd = 0
         rtt = [] # round trip time
         icmpS.setsockopt(socket.SOL_IP,socket.IP_TTL,ttl)
         send_data = struct.pack("BBHHH", 8, 0,checksum,ttl, 1)
         checksum = NetworkApplication.checksum(self,send_data)
         send_data = struct.pack("BBHHH", 8, 0,checksum,ttl, 1)

         for i in range(3):
          icmpS.settimeout(5)
          icmpS.sendto(send_data ,(hostName,1))
          packetSent += 1
          time_sent = time.time() ## record time
          recv_data, address = icmpS.recvfrom(1024)
         
          packetRecvd += 1
          recv_time = time.time() # stop the time  
          ovr_time.append((recv_time - time_sent)*1000) #appends the time value to the list
          rtt.append((sorted(ovr_time)[len(ovr_time)//2]))
          packet_loss  = (packetSent - packetRecvd ) / packetSent * 100 
         
         if ovr_time:
            
          try:  
           #rtt = ovr_time[1]
           icmpS.settimeout(5)
           addrName = address[0] 
           icmp_type, code, checksume, id, seq = struct.unpack("BBHHH",recv_data[20:28])
           host = socket.gethostbyaddr(addrName)[0] 
           #print(f"{ttl}: {host} ({addrName})   {ovr_time} ms")
           self.printMultipleResults(ttl,addrName, rtt ,host)
           pass
           
          except socket.herror:
            icmpS.settimeout(5)
            hosterr = address[0]
            #print(f"{ttl}: {hosterr}, {addrName}")
            self.printMultipleResults(ttl,addrName, rtt ,hosterr)
            pass
 
 
         if icmp_type == 0:
            break
        
         ttl += 1
        if __name__ == "__main__":
         #self.printOneResult(address,len(recv_data),20,ttl,hostName)
         self.printAdditionalDetails(packet_loss)
        else:
         self.printMultipleResults(ttl,addrName,rtt,host)





class WebServer(NetworkApplication):

    def handleRequest(self,tcpSocket,connection):
        # 1. Receive request message from the client on connection socket
        data = connection.recv(1024)
        #print(data)
        # 2. Extract the path of the requested object from the message (second part of the HTTP header)
        path = data.split()
        
        print(path[1].decode('utf-8'))
        # 3. Read the corresponding file from disk
        try:
              fullPath = '/home/elghamma/h-drive/Term2/203scc' +  path[1].decode('utf-8')
              print(fullPath)
              f = open(fullPath,'rb') 
              content = f.read()  # 4. Store in temporary buffer
              response = ("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}".format(len(content), content.decode('utf-8')))   # 5. Send the correct HTTP response error
              response = response.encode() 
        except FileNotFoundError:
              print("file not found")

         
        
      
        # 6. Send the content of the file to the socket
        #tcpSocket.sendall(response.encode())
        print(response)
        connection.sendall(response)
        connection.close()
        # 7. Close the connection socket
        
        pass
    

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))
        # 1. Create server socket
        hostName = '127.0.0.1'
        Port = 8080
        Server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        Server_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        # 2. Bind the server socket to server address and server port
        Server_socket.bind((hostName,Port))
        # 3. Continuously listen for connections to server socket
        Server_socket.listen()
        # 4. When a connection is accepted , call handleRequest function, passing new connection socket (see https://docs.python.org/3/library/socket.html#socket.socket.accept)
        connected, address = Server_socket.accept() 
        if connected:
         self.handleRequest(Server_socket,connected)
         print(f"Connected from {address}")
         Server_socket.close()
        # 5. Close server socket


class Proxy(NetworkApplication):

    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))


if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)
