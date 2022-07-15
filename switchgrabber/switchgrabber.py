import asyncio, telnetlib3
import pandas as pd
from time import sleep
import re
from scapy.all import srp, Ether, ARP

HOST = "YOUR IP HERE"
SUBNET = "YOUR SUBNET HERE"

ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=SUBNET),timeout=10)

ip_mac_dict = dict()
for packet in ans:
    srcMAC = packet.answer.hwsrc
    srcMAC = str(srcMAC).replace(":","-").upper()
    srcIP = packet.answer.psrc
    ip_mac_dict[srcMAC] = srcIP

print(ip_mac_dict)


@asyncio.coroutine
def shell(reader, writer):

    while True:
        outp = yield from reader.read(4096)
        if not outp:
            break
        elif 'UserName:' in outp:
            writer.write('YOUR TELNET USERNAME HERE\r')
        elif 'PassWord:' in outp:
            writer.write('YOUR TELNET PASSWORD HERE\r')
            sleep(2)
            writer.write('debug info\r')
        elif 'MAC table' in outp:
            writer.write('a')
        elif 'Total Entries:' in outp:
                break
        with open('test.txt', 'a') as f:
            f.write(outp)
        
        print(outp, flush=True)
    
    saved_lines = [] 
    file = open('test.txt')
    content = file.readlines()
    for line in content:
        if line.startswith('1       '):
            line = re.sub("\s+", ",", line.strip())
            saved_lines.append(line)
    
    df = pd.DataFrame([sub.split(",") for sub in saved_lines])
    df.columns =['Vlan', 'MacAddress', 'Type', 'Ports']
    ips = []
    for row in df.itertuples():
        if row.MacAddress in ip_mac_dict:
            ips.append(ip_mac_dict[row.MacAddress])
        else:
            ips.append("")
    df['IPAddress'] = ips
    df.to_csv('output.csv')



    print()

loop = asyncio.get_event_loop()
coro = telnetlib3.open_connection(HOST, 23, shell=shell)
reader, writer = loop.run_until_complete(coro)
loop.run_until_complete(writer.protocol.waiter_closed)

