 #!/usr/bin/python
 # -*- coding: utf-8 -*-
import socket
import sys
import time

#python udpClient.py ip:port


try:
    host = sys.argv[1].split(':')
    ip = host[0]
    port = int(host[1])
except Exception as err1:
    print('especificar ip do servidor e porta no formato ip:port (Ex: 192.168.0.2:80)')
    exit(1)

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(2)
orig = (ip, port)
udp.bind(orig)
msg, cliente = udp.recvfrom(1024)
print(str(cliente) + ":" + str(msg))
if(msg == 'test'):
    print('conectou')
    udp.close()
else:
    print('erro')
    udp.close()