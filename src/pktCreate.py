 #!/usr/bin/python
 # -*- coding: utf-8 -*-
import socket
import sys
import time

#script --es --tcp <ip sv> --sport 80
#script --ec --tcp <ip sv> --dport 80

#see argparse
def clientSide():
	try:
		host = sys.argv[3]
	except Exception as err1:
		print('especificar endereço de servidor')
		exit(1)

	try:		
		dport = sys.argv[5]
	except Exception as err2:
		print('especificar porta de destino do servidor')
		exit(1)

	try:
		sport = sys.argv[7]
	except Exception as err3:
		pass

	tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		client_address = ('192.168.0.2', int(sport))
		tcp.bind(client_address)
	except Exception as nobind:
		pass
	sv = (host, int(dport))
	tcp.connect(sv)
	time.sleep(1)
	tcp.close()



def serverSide():
	try:
		host = sys.argv[3]
	except Exception as err1:
		print('especificar endereço do servidor')
		exit(1)

	try:		
		sport = int(sys.argv[5])
	except Exception as err2:
		print('especificar porta de escuta do servidor')
		exit(1)


	tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #cria um socket tcp
	sv_address = (host, sport) #define o endereço do server
	tcp.bind(sv_address) #bind do socket para a porta
	tcp.listen(1)#ouvindo em busca de conexões

	while True:
		print("Aguardando por conexão de clientes...")
		connection, client_address = tcp.accept()
		print ("Concetado por: " + str(client_address))
		time.sleep(1)
		connection.close()



echo_type = sys.argv[1]

if(echo_type == '--ec'):
	clientSide()

elif(echo_type == '--es'):
	serverSide()