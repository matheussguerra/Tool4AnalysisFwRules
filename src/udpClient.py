 #!/usr/bin/python
 # -*- coding: utf-8 -*-
import socket
import sys
import time

#python udpClient.py ip:port
SOURCE_PORT = False

try:
    host = sys.argv[1].split(':')
    ip = host[0]
    port = int(host[1])
except Exception as err1:
    print('especificar ip do servidor e porta no formato ip:port (Ex: 192.168.0.2:80)')
    exit(1)

try:
    source_port = sys.argv[2]
    ip_local = socket.gethostbyname(socket.gethostname())
    SOURCE_PORT = True
except Exception as err2:
    pass


udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
if(SOURCE_PORT == True):
    udp.bind((ip_local, int(source_port)))

dest = (ip, port)
msg = "test"
udp.sendto (msg, dest)
udp.close()