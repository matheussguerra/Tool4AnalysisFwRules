 #!/usr/bin/python
 # -*- coding: utf-8 -*-
import socket
import sys
import time

#python tcpServer.py ip:port

try:
    host = sys.argv[1].split(':')
    ip = host[0]
    port = int(host[1])
except Exception as err1:
    print('especificar ip do servidor e porta no formato ip:port (Ex: 192.168.0.2:80)')
    exit(1)



tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.settimeout(1)
sv_address = (ip, port)
tcp.bind(sv_address)
tcp.listen(1)

print("Aguardando por conexão de clientes...")
connection, client_address = tcp.accept()
print ("Concetado por: " + str(client_address))
time.sleep(1)
connection.close()
tcp.close()