#!/usr/bin/python
# -*- coding: utf-8 -*-

tTime = []

i =0

f = open("r1-eth0.txt", 'r')
for line in f:
    line = line.split(' ')
    if("ICMP" in line):
        pass
    else:
        source = line[2].split('.')
        if(len(source) > 4):
            port_source = source[4]
            ip_source = source[0] + "." + source[1] + "." + source[2] + "." + source[3]
        
        dest = line[4].split('.')
        if(len(dest) > 4):
            port_dest = dest[4].replace(":","")
            ip_dest = dest[0] + "." + dest[1] + "." + dest[2] + "." + dest[3]

        print("de: " + ip_source + ":" + port_source + " para: " + ip_dest + ":" + port_dest)

    
    tTime.append([line[0], i])
    i = i+1

tTime.sort()
print(tTime)
