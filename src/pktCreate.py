 #!/usr/bin/python
 # -*- coding: utf-8 -*-
import socket
import sys
import time
import argparse

#script --es --tcp <ip sv> --sport 80
#script --ec --tcp <ip sv> --dport 80

# parser = argparse.ArgumentParser(description = 'Tool for packet creation.')

# parser.add_argument('-es', action = 'store', dest = 'es',
#                            default = 'es', required = False,
#                            help = 'Habilitar modo de escuta')

# parser.add_argument('-ec', action = 'store', dest = 'ec',
#                            default = 'ec', required = False,
#                            help = 'Habilitar modo client')

# parser.add_argument('-prot', action = 'store', dest = 'protocol',
#                            required = True,
#                            help = 'Protocolo: -prot tcp|udp')

# parser.add_argument('-ip', action = 'store', dest = 'ip',
#                            required = True,
#                            help = 'Informar ip de destino, caso esteja no modo -es informe o ip do servidor')						


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
	sv = (host, int(dport))
	tcp.settimeout(5)
	tcp.connect(sv)
	tcp.settimeout(None)
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
	tcp.settimeout(5)
	sv_address = (host, sport) #define o endereço do server
	tcp.bind(sv_address) #bind do socket para a porta
	tcp.listen(1)#ouvindo em busca de conexões

	#while True:
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