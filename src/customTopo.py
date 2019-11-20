#!/usr/bin/python
# -*- coding: utf-8 -*-

from mininet.net import Mininet
from mininet.node import Controller
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.node import OVSSwitch, Controller, RemoteController
from threading import Thread
import time
import os
import json
import time
import timeit


listHosts = []		# Lista de hosts (node)
listLink = []		# Lista de arestas (link entre hosts)
listTests = [] 		# Lista de testes a ser realizado
listSwitch = []
swAux = []

class Command():
	"""
	Esta classe tem por objetivo implementar comandos linux necessários para configuração de hosts.
	É necessário passar um objeto iface (O objeto iface contém ip, mascára, gateway e um nome) por paramentro.	
	"""

	def __init__(self, iface):
		self.ip = iface.ip
		self.mask = iface.mask
		self.gateway = iface.gateway
		self.name = iface.name

	def addGateway(self):
		return "route add default gw " + self.gateway

	def configMask(self):
		return "ifconfig " + self.name + " netmask " + self.mask

	def configRouter(self):
		return "echo 1 > /proc/sys/net/ipv4/ip_forward"

	def configIface(self):
		return "ifconfig " + self.name + " " + self.ip

	def start_tcpdump(self):
		return "sudo tcpdump -tt -n -i " + self.name + " -w " + self.name + ".log not arp &"

	def stop_tcpdump(self):
		return "killall -1 tcpdump"

	def convertLogTcpdump(self):
		return "sudo tcpdump -n -tt -r " + self.name + ".log > " + self.name + ".txt"		
		#return "sudo tcpdump -n -tt -r " + self.name + ".log >> log.txt"
	


class Host():
	"""
	Esta classe tem por objetivo abstrair um host, contendo os atributos necessários para configuração do mesmo.
	Type: é o tipo do host, que pode ser usado como um host simples ou roteador (host|router).
	Label: é o nome do host na estrutura.
	dns: Configuração de DNS do host.
	fwCommand: Lista contendo políticas/regras a ser inserida em um firewall.
	listIfaces: Lista contendo interfaces de um host, podendo ter mais de uma interface.

	É necessário passar o tipo, label e dns para criar um host.
	"""
	def __init__(self, type, label, dns, iface):
		self.type = type
		self.label = label
		self.dns = dns
		self.fwCommand = []
		self.iface = iface

	def __str__(self):
		output = ("Type: " +self.type + "\n"
		 +"Name: " + self.label + "\n"
		 +"DNS: " + self.dns + "\n")

		auxFwCommand = ""
		for i in range(0,len(self.fwCommand)):
			auxFwCommand = auxFwCommand + str(self.fwCommand[i])
			

		auxIface = ""
		for i in range(0, len(self.iface)):
		 	auxIface = auxIface + str(self.iface[i])
		
		return output + auxFwCommand + auxIface

	def set_fwCommand(self, commands):
		self.fwCommand = commands


class Switch():
	def __init__(self, label):
		self.label = label

	def __str__(self):
		return "\nName: " + self.label


class Interface():
	"""
	Esta classe tem por objetivo abstrair o conceito de interface (de rede), contendo seus principais atributos.
	Uma interface contém um:
	- ip: ip(ipv4)
	- mask: mascára do ip
	- gateway: gateway padrão.
	- name: nome da interface (ex.: eth0)
	"""
	def __init__(self, ip, mask, gw, counter, label):
		self.ip = ip
		self.mask = mask
		self.gateway = gw
		self.name = str(label) + "-eth" + str(counter)

	def __str__(self):
		return "\nName: " + self.name + "\nIP: " + self.ip + "\nMask: " + self.mask + "\nGateway: " + self.gateway


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
		return "Source IP: " + self.sourceIP + "\nDestination IP: " + self.destinationIP + "\nProtocol: " + self.protocol + "\nSource port: " + self.sourcePort + "\nDestination Port: " + self.destinationPort + "\nWhat i want?: " + self.expected





def readJsonFile():
	with open('2redes.json') as f:
		data = json.load(f)
	
	return data




def createHosts(hosts):
	for i in range(0, len(hosts)):
		attrIface = []
		attrCommands = []
		attrType = hosts[i]["type"]
		attrLabel = hosts[i]["label"]
		attrDNS = (hosts[i]["dns"])
		attrIface = createIface(hosts[i]["iface"], attrLabel)

		host = Host(attrType, attrLabel, attrDNS, attrIface)

		try:
			for j in range(0, len(hosts[i]["fwCommand"])):
				attrCommands.append(hosts[i]["fwCommand"][j])				
				host.set_fwCommand(attrCommands)

		except Exception as e:
			pass
		listHosts.append(host)		


def createIface(ifaces, label):
	attrIface = []
	for i in range(0, len(ifaces)):
		ip = ifaces[i]["ip"]
		mask = ifaces[i]["mask"]
		gw = ifaces[i]["gw"]

		attrIface.append(Interface(ip, mask, gw, i, label))

	return attrIface
	
def createSwitch(data):
	for i in range(0, len(data)):
		label = data[i]["label"]

		listSwitch.append(Switch(label))



def createLinks(data):
	for i in range(0, len(data)):
		label = data[i]["label"]
		source = data[i]["to"]
		dest = data[i]["from"]
		listLink.append(Link(label, source, dest))


def createObjects(data):
	createHosts(data["hosts"])
	createSwitch(data["switchs"])
	createLinks(data["links"])
	


def createTests(data):
	for i in range(0, len(data)):
		sourceIP = data[i]["sourceIP"]
		destIP = data[i]["destIP"]
		protocol = data[i]["protocol"]
		sPort = data[i]["sPort"]
		dPort = data[i]["dPort"]
		expected = data[i]["expected"]
		listTests.append(Tests(sourceIP, destIP, protocol, sPort, dPort, expected))

		
def startTcpdumAllIface(net):
	for host in listHosts:
		for iface in host.iface:
			command = Command(iface)
			hostNET = net.getNodeByName(host.label)
			hostNET.cmd(command.start_tcpdump())


def tcpServer(host, ip, port):
	host.cmd("python tcpServer.py " + str(ip) + ":" + str(port) + " &")


def tcpClient(host, ip, port):
	host.cmd("python tcpClient.py " + str(ip) + ":" + str(port) + " &")


def udpServer(host, ip, port):
	host.cmd("python udpServer.py " + str(ip) + ":" + str(port) + " &")


def udpClient(host, ip, port):
	host.cmd("python udpClient.py " + str(ip) + ":" + str(port) + " &")


def tests(net):
	numTest = 1
	for test in listTests:
		hostDestLabel = ""
		hostSourceLabel = ""
		inicio = timeit.default_timer()
		startTcpdumAllIface(net)
		info("\nIniciando teste:\n---\n" + str(test) + "\n---\n")
		for host in listHosts:
			for iface in host.iface:
				if test.destinationIP in iface.ip:
					hostDestLabel = net.getNodeByName(host.label)
				if test.sourceIP in iface.ip:
					hostSourceLabel = net.getNodeByName(host.label)
				else:
					pass
		if(test.protocol == "tcp"):
			th1 = Thread(target=tcpServer, args=[hostDestLabel, test.destinationIP, test.destinationPort])			
			th1.start()
			time.sleep(0.5)
			if(test.sourcePort == "*"):
				th2 = Thread(target=tcpClient, args=[hostSourceLabel, test.destinationIP, test.destinationPort])
				th2.start()				
			else:
				hostSourceLabel.cmd("python tcpClient.py " + test.destinationIP + ":" + test.destinationPort + " " + test.sourcePort)
			th1.join()
			th2.join()
		if(test.protocol == "udp"):			
			th1 = Thread(target=udpServer, args=[hostDestLabel, test.destinationIP, test.destinationPort])
			th1.start()
			time.sleep(0.5)
			if(test.sourcePort == "*"):				
				th2 = Thread(target=udpClient, args=[hostSourceLabel, test.destinationIP, test.destinationPort])
				th2.start()
			else:
				hostSourceLabel.cmd("python udpClient.py " + test.destinationIP + ":" + test.destinationPort + " " + test.sourcePort)
			th1.join()
			th2.join()
		if(test.protocol == "icmp"):
			hostSourceLabel.cmd("ping -n -c 1 " + test.destinationIP)
		
		path = []
		hostNet = net.getNodeByName('h1')
		time.sleep(1)		
		hostNet.cmd("killall -1 tcpdump")
		time.sleep(1)		
		hostNet.cmd("mkdir teste" + str(numTest))
		for host in listHosts:
			for iface in host.iface:
				command = Command(iface)
				hostNET = net.getNodeByName(host.label)
				hostNET.cmd(command.convertLogTcpdump())
				time.sleep(0.2)				
				analysisLog(iface.name, test, path)		
		path.sort()
		info(path)
		result(test)
		fim = timeit.default_timer()
		hostNet.cmd("mv *.txt /home/mininet/mininet/tcc/tool4analysisfwrules/src/teste" + str(numTest))
		time.sleep(0.2)
		hostNet.cmd("sudo rm *.log")
		hostNet.cmd("sudo rm *.txt")
		info("\nteste realizado em: " + str(fim -inicio) + '\n')
		numTest = numTest + 1

def analysisLog(iface, test, path):
	f = open(iface + ".txt", 'r')
	lines = f.readlines()
	for line in lines:
		#info(line + "\n")
		processedLine = processTcpdumpLine(line)
		if(test.sourceIP == processedLine[1]):
			pass	
			#info([processedLine[0], iface])		
			path.append([processedLine[0], iface])


	f.close()


def processTcpdumpLine(lineLog):
	if("Flags" in lineLog): #protocolo tcp
		lineLog = lineLog.split(" ")

		time = lineLog[0]

		de = lineLog[2].split('.')
		de = de[0] + "." + de[1] + "." + de[2] + "." + de[3]

		para = lineLog[4].replace(":","").split('.')
		para = para[0] + "." + para[1] + "." + para[2] + "." + para[3]

		flag = lineLog[6].replace(",","")

		return time, de, para, flag

	elif("ICMP" in lineLog):
		return ["","","",""]

	else:
		lineLog = lineLog.split(" ")

		time = lineLog[0]

		de = lineLog[2].split('.')
		de = de[0] + "." + de[1] + "." + de[2] + "." + de[3]

		para = lineLog[4].replace(":","").split('.')
		para = para[0] + "." + para[1] + "." + para[2] + "." + para[3]

		return time, de, para



def result(test):
	handshake = 0
	datagram = False
	aux = 0
	destHost = getHostDest(test)
	f = open(destHost.name + ".txt")
	lines = f.readlines()
	
	for line in lines:
		if("Flags" in line):

			processedLine = processTcpdumpLine(line)
			if(aux ==  0 and test.sourceIP == processedLine[1] and test.destinationIP == processedLine[2]):
				if(processedLine[3] == "[S]"):				
					handshake += 1
				
			if(aux == 1 and test.destinationIP == processedLine[1] and test.sourceIP == processedLine[2]):
				if(processedLine[3] == "[S.]"):
					handshake += 1
			
			if(aux == 2 and test.sourceIP == processedLine[1] and test.destinationIP == processedLine[2]):
				if(processedLine[3] == "[.]"):
					handshake += 1

			if(handshake == 3):
				handshake = True
				break	

			aux += 1
		elif("ICMP" in line):
			pass
		else:
			processedLine = processTcpdumpLine(line)
			if(test.sourceIP == processedLine[1]):
				datagram = True
				break

	if(test.protocol == "tcp"):
		if(test.expected == "accept"):
			if(handshake == True):
				info("\nTeste APROVADO - os pacotes chegaram ao destino")
			else:
				info("\nTeste REPROVADO - os pacotes não chegaram ao destino")

		if(test.expected == "deny"):
			if(handshake == True):
				info("\nTeste REPROVADO - os pacotes chegaram ao destino")			
			else:
				info("\nTeste APROVADO - os pacotes não chegaram ao destino")
		handshake = 0
					
	elif(test.protocol == "ICMP"):
		pass
	else:
		if(test.expected == "accept"):
			if(datagram == True):
				info("\nTeste APROVADO - os pacotes chegaram ao destino")
			else:
				info("\nTeste REPROVADO - os pacotes não chegaram ao destino")

		if(test.expected == "deny"):
			if(datagram == True):
				info("\nTeste REPROVADO - os pacotes chegaram ao destino")			
			else:
				info("\nTeste APROVADO - os pacotes não chegaram ao destino")


	f.close()
		
		

def getHostDest(test):
	for host in listHosts:
		for interface in host.iface:
			if(interface.ip == test.destinationIP):
				return(interface)

def emptyNet():
	net = Mininet(controller=Controller, switch=OVSSwitch)
	ctrl = net.addController('c1')
	ctrl.start()

	info('*** Adding hosts ***\n')
	for host in listHosts:
		net.addHost(host.label)


	for switch in listSwitch:
		sw = net.addSwitch(str(switch.label))
		swAux.append(sw)
		

	info('*** Creating links ***\n')
	for link in listLink:
		hostFrom = link.source
		hostTo = link.dest
		net.addLink(str(hostFrom), str(hostTo))

	info('*** Configuring hosts ***\n')
	for host in listHosts:
		hostNET = net.getNodeByName(host.label)
		list_fw_cmd = host.fwCommand
		list_iface_hosts = host.iface

		for iface in list_iface_hosts:
			cmd = Command(iface)
			hostNET.cmd(cmd.configIface())
			hostNET.cmd(cmd.configMask())
			hostNET.cmd(cmd.addGateway())

			hostNET.config()

		for fwCmd in list_fw_cmd:
			hostNET.cmd(fwCmd)

		if host.type == 'router':
			hostNET.cmd(cmd.configRouter())

		

		for switch in swAux:
			switch.start([ctrl])

	info('*** Init tests ***\n')
	tests(net)

	#info('*** Starting CLI ***\n')
	CLI(net)

	#info('*** Stopping newtwork ***\n')
	net.stop()
	exit()


data = readJsonFile()
createObjects(data["scene"])
createTests(data["test"])

setLogLevel('info')
emptyNet()


## Não estamos pensando em executar serviços de rede, tal como ftp
