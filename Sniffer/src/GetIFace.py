# coding=utf-8
from platform import system


def GetIface():
    if system() == 'Windows':
        from wmi import WMI
        tmplist = []
        c = WMI()
        for interface in c.Win32_NetworkAdapterConfiguration(IPEnabled=1):
            tmpdict = {"Description": interface.Description, "IPAddress": interface.IPAddress[0],
                       "IPSubnet": interface.IPSubnet[0], "MAC": interface.MACAddress}
            tmplist.append(tmpdict['Description'])
        return tmplist
    elif system() == 'Darwin':
        from netifaces import gateways
        tmplist = []
        c = gateways()
        del c['default']
        for interface in c.values():
            for i in interface:
                if i[2]:
                    tmplist.append(i[1])
        return tmplist
