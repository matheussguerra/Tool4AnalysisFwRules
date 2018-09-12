 #!/usr/bin/python
 # -*- coding: utf-8 -*-
import socket
import sys

try:
	HOST = sys.argv[1]			#IP do server
	PORT = int(sys.argv[2])		#Porta do server
except Exception as e:
	print("Erro de argumentos\nUtilizar o formato tcpServer.py <HOST> <PORT>")


tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #cria um socket tcp
sv_address = (HOST, PORT) #define o endereço do server
tcp.bind(sv_address) #bind do socket para a porta
tcp.listen(1)#ouvindo em busca de conexões

while True:
	print("Aguardando por conexão de clientes...")
	connection, client_address = tcp.accept()
	print ("Concetado por: " + str(client_address))

	while True:
		msg = connection.recv(1024)
		if not msg:
			break
		print client_address, msg
		print 'Finalizando conexao do cliente', client_address
		connection.close()
