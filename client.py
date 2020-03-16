from scapy.all import *
import time

seq = 1000

dst = '134.197.42.83'
src = '134.197.86.190'

# randomly select source port
sport = random.randint(1024, 65535)
dport = 3333

ip = IP(src=src, dst=dst)
# craft the syn packet
SYN = TCP(sport=sport, dport=dport, flags='S', seq=seq)
SA = sr1(ip/SYN)

# now we send ACK packet
ACK = TCP(sport=sport, dport=dport, flags='A',
          seq=SA[0].ack, ack=SA[0].seq + 1)
send(ip/ACK)

PA = sniff(
    count=1, filter="tcp and port 3333")
# we have to acknowledge PA packet
print(PA[0].load)
pack = TCP(sport=sport, dport=dport, flags='A', seq = PA[0].ack, ack=PA[0].seq+len(PA[0].load))
send(ip/pack)

# now we expect FIN
FA = sniff(count=1, filter="tcp and port 3333" )
# we will send ACK and then FA
#send(ip/TCP(sport=sport, dport=dport, flags='FA', seq = FA[0].ack, ack=FA[0].seq+1))
lastAck = sr1(ip/TCP(sport=sport, dport=dport,flags='FA', seq=FA[0].ack, ack=FA[0].seq+1))
lastAck.show()

# PA = ACK
# for i in range(3):

# PA.show()
