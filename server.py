from scapy.all import *


def log(_from, _to, msg, seq, ack) :
    print("# {}->{} flag: {} seq: {} ack: {}".format(_from, _to, msg, seq, ack))

# first sniff for the syn request
SYN_REQ = sniff(
    count=1, filter="tcp and port 3333")

clientPort = SYN_REQ[0].sport
serverPort = SYN_REQ[0].dport
clientIp = SYN_REQ[0][IP].src
serverIp = SYN_REQ[0][IP].dst

# log this response
log(clientIp, serverIp, SYN_REQ[0][TCP].flags, SYN_REQ[0].seq, SYN_REQ[0].ack)

ip = IP(src=serverIp, dst=clientIp)

# log this packet 
log(serverIp, clientIp, "SA", SYN_REQ[0].seq, SYN_REQ[0].seq+1) 
# we will reply with synack, seq = syn.seq, ack = syn.seq +1, options (mss,1460)
SYNACK = TCP(sport=serverPort, dport=clientPort, flags="SA",
             seq=SYN_REQ[0].seq, ack=SYN_REQ[0].seq + 1, options=[('MSS', 1460)])
ack_response = sr1(ip/SYNACK)

# log this response
log(clientIp, serverIp, ack_response[0][TCP].flags, ack_response[0].seq, ack_response[0].ack)





## now lets close the connection
fin_seq = ack_response[0].ack
fin_ack = ack_response[0].seq + 1


FIN=TCP(sport=serverPort, dport=clientPort, flags="FA", seq=fin_seq, ack=fin_ack)
FINACK=sr1(ip/FIN)
LASTACK=TCP(sport=serverPort, dport=clientPort, flags="A", seq=FINACK.ack, ack=FINACK.seq + 1)
send(ip/LASTACK)
