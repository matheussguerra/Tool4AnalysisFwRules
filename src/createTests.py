#!/usr/bin/python
# -*- coding: utf-8
import json
import random


def typeSelector():
    t = random.randint(0, 1)
    if (t == 0):
        t = "router"
    else:
        t = "host"
    return t


def generateIP():
    first = random.randint(0, 255)
    second = random.randint(0, 255)
    third = random.randint(0, 255)
    fourth = random.randint(0, 255)

    ip = str(first) + "." + str(second) + "." + str(third) + "." + str(fourth)

    return ip


def generateIface(numIface):
    ifaces = []

    for x in range(0,numIface):
        iface = {
            "ip":None,
            "mask":None,
            "gw":None
        }
        ip = generateIP()
        mask = generateIP()
        gw = generateIP()

        iface["ip"] = ip
        iface["mask"] = mask
        iface["gw"] = gw
        ifaces.append(iface)
    return ifaces


def generateHost(times):
    countHost = 0
    countRouter = 0
    hosts = []

    for x in range(0, times):
        host = {
            "type": None,
            "label": None,
            "dns": None,
            "iface": None,
            "fwCommand": None
        }
        typeNode = typeSelector()

        if typeNode == "router":
            countRouter = countRouter +1
            name = "r" + str(countRouter)
        else:
            countHost = countHost + 1
            name = "h" + str(countHost)

        dns = generateIP()

        fwRules = ""

        numIface = random.randint(1, 4)
        print (numIface)
        iface = generateIface(numIface)

        host["type"] = typeNode
        host["label"] = name
        host["dns"] = dns
        host["iface"] = iface
        host["fwCommand"] = fwRules

        hosts.append(host)

    return hosts


def main():
    qtdHosts = 10
    x = {
        "scene": {
            "hosts": None,
            "link": None
        },
        "test": None
    }

    x["scene"]["hosts"] = generateHost(qtdHosts)
    x["scene"]["link"] = []
    x["test"] = []


    with open('teste.json', 'w') as outfile:
        json.dump(x, outfile)

if __name__ == "__main__":
    main()