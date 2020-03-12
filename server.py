from scapy.all import *

# first sniff for the syn request
SYN_REQ = sniff(
    count=1, filter="tcp and port 3333 and tcp.flags.syn==1 and tcp.flags.ack==0")

clientPort = SYN_REQ[0].sport
serverPort = SYN_REQ[0].dport
clientIp = SYN_REQ[0][IP].src
serverIp = SYN_REQ[0][IP].dst

ip = IP(src=serverIp, dst=clientIp)

# we will reply with synack, seq = syn.seq, ack = syn.seq +1, options (mss,1460)
SYNACK = TCP(sport=serverPort, dport=clientPort, flags="SA",
             seq=SYN_REQ[0].seq, ack=a[0].seq + 1, options=[('MSS', 1460)])

ack_response = sr1(ip/TCP_SYNACK)

ack.respose.show()

