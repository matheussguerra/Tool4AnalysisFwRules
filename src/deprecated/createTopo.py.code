#!/usr/bin/python
# -*- coding: utf-8 -*-

from mininet.net import Mininet
from mininet.node import Controller
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.node import OVSSwitch, Controller, RemoteController
import time
import os


listHosts = []		# Lista de hosts (node)
listLink = []		# Lista de arestas (link entre hosts)
listTests = [] 		# Lista de testes a ser realizado

##########################################################################################################


class Command():
	"""
	Esta classe tem por objetivo implementar comandos linux necessários para configuração de hosts.
	É necessário passar um objeto iface (O objeto iface contém ip, mascára, gateway e um nome) por paramentro.	
	"""

	def __init__(self, iface):
		self.ip = iface.get_ip()
		self.mask = iface.get_mask()
		self.gateway = iface.get_gateway()
		self.name = iface.get_ifaceName()

	def addGateway(self):
		return "route add default gw " + self.gateway

	def configMask(self):
		return "ifconfig " + self.name + " netmask " + self.mask

	def configRouter(self):
		return "echo 1 > /proc/sys/net/ipv4/ip_forward"

	def configIface(self):
		return "ifconfig " + self.name + " " + self.ip

	def start_tcpdump(self):
		return "sudo tcpdump -i " + self.name + " -w " + self.name + ".log &"

	def stop_tcpdump(self):
		return "killall tcpdump"

	def convertLogTcpdump(self):
		return "sudo tcpdump -r " + self.name + ".log >> " + self.name + ".txt"	



class Host:
	"""
	Esta classe tem por objetivo abstrair um host, contendo os atributos necessários para configuração do mesmo.
	Type: é o tipo do host, que pode ser usado como um host simples ou roteador (host|router).
	Label: é o nome do host na estrutura.
	dns: Configuração de DNS do host.
	fwCommand: Lista contendo políticas/regras a ser inserida em um firewall.
	listIfaces: Lista contendo interfaces de um host, podendo ter mais de uma interface.

	É necessário passar o tipo, label e dns para criar um host.
	"""
	def __init__(self, type, label, dns):
		self.type = type
		self.label = label
		self.dns = dns
		self.fwCommand = []
		self.listIfaces = []

	def __str__(self):
		try:
			strIface = ""
			for interface in self.listIfaces:
				strIface = strIface + "\n" + str(interface)

			strfwCommand = ""
			for fwCommand in self.fwCommand:
				strfwCommand = strfwCommand + "\n" + fwCommand

			return "Type: " + self.type	+ "\nLabel: " + self.label + "\nPrimary DNS: " + self.dns + "\nInterfaces: " + strIface + "\n\nFirewall commands: " + strfwCommand
		
		except Exception as e:
			return "Type: " + self.type	+ "\nLabel: " + self.label + "\nPrimary DNS: " + self.dns + "\nThere are no interfaces to show!"

	def set_interface(self, iface, counter):
		iface = iface.split(',')
		self.listIfaces.append(Interface(iface, self.label, counter))

	def set_fwCommand(self, fwCommand):
		self.fwCommand = fwCommand.split(',')

	def get_type(self):
		return self.type

	def get_label(self):
		return self.label

	def get_dns(self):
		return self.dns

	def get_iface(self):
		return self.listIfaces	

	def get_fwCmd(self):
		return self.fwCommand



class Interface():
	"""
	Esta classe tem por objetivo abstrair o conceito de interface (de rede), contendo seus principais atributos.
	Uma interface coném um:
	- ip: ip(ipv4)
	- mask: mascára do ip
	- gateway: gateway padrão.
	- name: nome da interface (ex.: eth0)
	"""
	def __init__(self, iface, label, counter):
		self.ip = iface[0]
		self.mask = iface[1]
		self.gateway = iface[2]
		self.name = label + "-eth" + str(counter)

	def __str__(self):
		return "\nName: " + self.name + "\nIP: " + self.ip + "\nMask: " + self.mask + "\nGateway: " + self.gateway
		
	def get_ip(self):
		return self.ip

	def get_mask(self):
		return self.mask

	def get_gateway(self):
		return self.gateway

	def get_ifaceName(self):
		return self.name


class Link():
	"""
	Esta classe tem por objetivo criar arestas, que são utilizadas para conecetar dois nodes.
	seus atributos são:
	- label: nome da aresta.
	- source: node de origem da aresta.
	- dest: node de destino da aresta

	Como a rede implementa um conceito de dígrafo, a ordem de source e dest não é relevante, podendo então ser invertido.
	"""
	def __init__(self, label, source, dest):
		self.label = label
		self.source = source
		self.dest = dest
		
	def __str__(self):
		return "Aresta: " + self.label + "\nde: " + self.source + "\npara: " + self.dest

	def get_from(self):
		return self.source

	def get_to(self):
		return self.dest

	def get_label(self):
		return self.label


class Tests:
	"""
	Esta classe implementa o conceito de um teste.

	"""
	def __init__(self, sourceIP, destinationIP, protocol, sourcePort, destinationPort, expected):
		self.sourceIP = sourceIP
		self.destinationIP = destinationIP
		self.protocol = protocol
		self.sourcePort = sourcePort
		self.destinationPort = destinationPort
		self.expected = expected


	def __str__(self):
		return "Source IP: " + self.sourceIP + "\nDestination IP: " + self.destinationIP + "\nProtocol: " + self.protocol + "\nSource port: " + self.sourceIP + "\nDestination Port: " + self.destinationPort + "\nWhat i want?: " + self.expected


	def get_sourceIP(self):
		return self.sourceIP
		
	def get_destinationIP(self):
		return self.destinationIP

	def get_protocol(self):
		return self.protocol

	def get_sourcePort(self):
		return self.sourcePort

	def get_destionationPort(self):
		return self.destinationPort

	def get_expected(self):
		return self.expected

		
################################################################################################################



def createHosts():
	count = 0
	arq = open('hosts.csv', 'r') # Abre o csv de hosts
	for line in arq:
		if count > 0:	#ignora a linha contendo o nome das colunas		
			attributes = line.split(";") 	#quebra a linha por ';' e armazena em um array
			host = Host(attributes[0], attributes[1], attributes[2]) #instancia um novo node/host passando o tipo, nome e dns
			ifaceCounter = 0 # como pode ter mais de uma interface, há uma iteração sobre os elementos restantes do array
			for i in range(3, len(attributes)):
				host.set_interface(attributes[i], ifaceCounter) # chama o método de criação de interface para um host, passando um array contendo os atributos de uma interface
				ifaceCounter += 1

			listHosts.append(host) #adiciona o host em uma lista

		count += 1
		
	arq.close()

	count = 0
	arq = open('fw.csv', 'r')
	for line in arq:
		if count > 0:
			attributes = line.split(";")
			hostName = attributes[0]
			fwCommand = attributes[1]

			for host in listHosts:
				if host.get_label() == hostName:

					host.set_fwCommand(fwCommand)

		count += 1

	arq.close()


def createTests():
	count = 0
	arq = open('test.csv', 'r')
	for line in arq:
		if count > 0:
			testAttributes = line.split(';')
			test = Tests(testAttributes[0], testAttributes[1], testAttributes[2], testAttributes[3], testAttributes[4], testAttributes[5])
			listTests.append(test)

		count += 1

	arq.close()


def createLinks():
	count = 0
	arq = open('link.csv', 'r')
	for line in arq:
		if count > 0:
			linkAttributes = line.split(";")
			link = 	Link(linkAttributes[0], linkAttributes[1], linkAttributes[2])
			listLink.append(link)

		count += 1

	arq.close()


def createObjects():
	createHosts()
	createTests()
	createLinks()


def tests(net):
	for host in listHosts:
		for iface in list_iface_hosts:
                        cmd = Command(iface)
                        hostNET.cmd(cmd.start_tcpdump())

	for test in listTests:
		



def emptyNet():
	net = Mininet(controller=Controller)

	info('*** Adding hosts ***\n')
	for host in listHosts:
		net.addHost(host.get_label())

	info('*** Creating links ***\n')
	for link in listLink:
		hostFrom = link.get_from().replace("\n", "")
		hostTo = link.get_to().replace("\n", "")
		net.addLink(hostFrom, hostTo)

	info('*** Configuring hosts ***\n')
	for host in listHosts:
		hostNET = net.getNodeByName(host.get_label())
		list_fw_cmd = host.get_fwCmd()
		list_iface_hosts = host.get_iface()

		for iface in list_iface_hosts:
			cmd = Command(iface)
			hostNET.cmd(cmd.configIface())
			hostNET.cmd(cmd.configMask())
			hostNET.cmd(cmd.addGateway())

			hostNET.config()

		for fwCmd in list_fw_cmd:
			hostNET.cmd(fwCmd)

		if host.get_type() == 'router':
			hostNET.cmd(cmd.configRouter())

	info ('*** Init tests ***\n')
	tests(net)

	#info('*** Starting CLI ***\n')
	CLI(net)

	info('*** Stopping newtwork ***\n')
	net.stop()
	exit()



createObjects()

#for host in listHosts:
#	print str(host)
#	print "--------"

setLogLevel('info')
emptyNet()
