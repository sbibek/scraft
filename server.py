from scapy.all import *


def log(_from, _to, msg, seq, ack) :
    print("{} {} {} {} {}".format(_from, _to, msg, seq, ack))

# first sniff for the syn request
SYN_REQ = sniff(
    count=1, filter="tcp and port 3333")

clientPort = SYN_REQ[0].sport
serverPort = SYN_REQ[0].dport
clientIp = SYN_REQ[0][IP].src
serverIp = SYN_REQ[0][IP].dst

log(clientIp, serverIp, SYN_REQ[0].flags, SYN_REQ[0].seq, SYN_REQ[0].ack)

ip = IP(src=serverIp, dst=clientIp)

# we will reply with synack, seq = syn.seq, ack = syn.seq +1, options (mss,1460)
SYNACK = TCP(sport=serverPort, dport=clientPort, flags="SA",
             seq=SYN_REQ[0].seq, ack=SYN_REQ[0].seq + 1, options=[('MSS', 1460)])
ack_response = sr1(ip/SYNACK)

ack_response.show()

