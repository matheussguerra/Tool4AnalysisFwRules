#!/usr/bin/python
# -*- coding: utf-8 -*-

def analysisLog():
	f = open("h1-eth0.txt", 'r')
	for line in f:
		line = line.split(' ')
		#time = line[0]
		#ip_field = line[1]
		ip_source = line[2]
		#dest_symbol = line[3]
		ip_dest = line[4]
		protocol = line[5]

        ip_source = ip_source.split('.')
        port_source = ip_source[4].split(' ')[0]
        ip_source = ip_source[0] + "." + ip_source[1] + "." + ip_source[2] + "." + ip_source[3]

        ip_dest = ip_dest.split('.')
        port_dest = ip_dest[4].split(':')[0]
        ip_dest = ip_dest[0] + "." + ip_dest[1] + "." + ip_dest[2] + "." + ip_dest[3]

        print("de: " + ip_source + ":" + port_source + "para: " + ip_dest + ":" + port_dest)


f = open("h1-eth0.txt", 'r')
for line in f:
    line = line.split(' ')
    ip_source = line[2].split('.')
    
    print(ip_source)
