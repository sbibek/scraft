from scapy.all import *
import time

seq = 1111

dst = '134.197.42.83'
src = '134.197.86.190'

# randomly select source port
sport = random.randint(1024,65535)
dport = 3333

ip = IP(src=src, dst=dst)
# craft the syn packet
SYN = TCP(sport=sport, dport=dport,flags='S', seq = seq)

SA = sr1(ip/SYN)

SA.show()