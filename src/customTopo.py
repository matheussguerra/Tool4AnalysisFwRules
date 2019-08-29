#!/usr/bin/python
# -*- coding: utf-8 -*-

from mininet.net import Mininet
from mininet.node import Controller
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.node import OVSSwitch, Controller, RemoteController
import time
import os
import json


listHosts = []		# Lista de hosts (node)
listLink = []		# Lista de arestas (link entre hosts)
listTests = [] 		# Lista de testes a ser realizado



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
		return "sudo tcpdump -i " + self.name + " -w " + self.name + ".log not arp &"

	def stop_tcpdump(self):
		return "killall -1 tcpdump"

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
		return "Source IP: " + self.sourceIP + "\nDestination IP: " + self.destinationIP + "\nProtocol: " + self.protocol + "\nSource port: " + self.sourceIP + "\nDestination Port: " + self.destinationPort + "\nWhat i want?: " + self.expected





def readJsonFile():
	with open('jsonTest.json') as f:
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
	
	

def createLinks(data):
	for i in range(0, len(data)):
		label = data[i]["label"]
		source = data[i]["to"]
		dest = data[i]["from"]
		listLink.append(Link(label, source, dest))


def createObjects(data):
	createHosts(data["hosts"])
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



def tests(net):
	for host in listHosts:
		for iface in host.iface:
			command = Command(iface)
			hostNET = net.getNodeByName(host.label)
			hostNET.cmd(command.start_tcpdump())
			time.sleep(1)

	for test in listTests:
		for host in listHosts:
			#dar um jeito de iterar em todas as interfaces (estático no momento)
			if test.destinationIP in host.iface[0].ip:
				hostDestLabel = net.getNodeByName(host.label)
			if test.sourceIP in host.iface[0].ip:
				hostSourceLabel = net.getNodeByName(host.label)
			else:
				pass
		if(test.protocol == "tcp"):
			#start server
			info("*** subindo servidor *** \n")
			hostDestLabel.cmd("echo python pktCreate.py --es --" + test.protocol + " " + test.destinationIP + " --sport " + test.sourcePort)
			#start client
			info("*** conectando cliente *** \n")
			info("python pktCreate.py --ec --" + test.protocol + " " + test.sourceIP + " --dport " + test.sourcePort)
			info('*** Testing...***\n')
			time.sleep(10)
			pass
		if(test.protocol == "udp"):
			pass
		if(test.protocol == "icmp"):
			pass

	aux = listHosts[0].label
	hostNet = net.getNodeByName(aux)
	hostNet.cmd(command.stop_tcpdump())

	for host in listHosts:
		for iface in host.iface:
			command = Command(iface)
			hostNET = net.getNodeByName(host.label)
			#hostNET.cmd(command.convertLogTcpdump())
			#time.sleep(3)
			#hostNET.cmd("rm " + iface.name + ".log")




def emptyNet():
	net = Mininet(controller=Controller)

	info('*** Adding hosts ***\n')
	for host in listHosts:
		net.addHost(host.label)

	info('*** Creating links ***\n')
	for link in listLink:
		hostFrom = link.source
		hostTo = link.dest
		net.addLink(hostFrom, hostTo)

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

	info('*** Init tests ***\n')
	tests(net)

	info('*** Starting CLI ***\n')
	CLI(net)

	info('*** Stopping newtwork ***\n')
	net.stop()
	exit()


data = readJsonFile()
createObjects(data["scene"])
createTests(data["test"])

setLogLevel('info')
emptyNet()


## Não estamos pensando em executar serviços de rede, tal como ftp
