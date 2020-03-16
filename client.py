from scapy.all import *
import time

seq = 1000

dst = '134.197.42.83'
src = '134.197.86.190'

# randomly select source port
sport = random.randint(1024,65535)
dport = 3333

ip = IP(src=src, dst=dst)
# craft the syn packet
SYN = TCP(sport=sport, dport=dport,flags='S', seq = seq)
SA = sr1(ip/SYN)

# now we send ACK packet
ACK = TCP(sport=sport, dport=dport, flags='A', seq = SA[0].ack, ack=SA[0].seq + 1 )

SA.show()