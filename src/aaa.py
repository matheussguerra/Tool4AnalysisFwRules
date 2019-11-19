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
import time
import timeit

def emptyNet():
	net = Mininet(controller=Controller)

	info('*** Adding hosts ***\n')
        net.addHost('h1')
        net.addHost('h2')

        net.addSwitch('s1')

        net.addHost('r1')

        net.addSwitch('s2')

        net.addHost('h3')
        net.addHost('h4')


	info('*** Creating links ***\n')
        net.addLink('h1','s1')
        net.addLink('h2','s1')

        net.addLink('s1', 'r1')        
        net.addLink('r1', 's2')

        net.addLink('h3','s2')
        net.addLink('h4','s2')


	info('*** Configuring hosts ***\n')


	info('*** Init tests ***\n')
	tests(net)

	info('*** Starting CLI ***\n')
	CLI(net)

	info('*** Stopping newtwork ***\n')
	net.stop()
	exit()




setLogLevel('info')
emptyNet()


## Não estamos pensando em executar serviços de rede, tal como ftp
