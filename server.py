from scapy.all import *


def log(_from, _to, msg, seq, ack) :
    print("# {}->{} flag: {} seq: {} ack: {}".format(_from, _to, msg, seq, ack))


# setup initial sequence and acknowledgements
# let inital sequence be 1000 
seq = 1000
ack = 0

# we will use another variables for seq and ack received from client
r_seq = 0
r_ack = 0

def update(pkt, i = 0):
    r_seq = pkt[i].seq
    r_ack = pkt[i].ack

# first sniff for the syn request
SYN_REQ = sniff(
    count=1, filter="tcp and port 3333")

# update the received seq and acks
update(SYN_REQ)


clientPort = SYN_REQ[0].sport
serverPort = SYN_REQ[0].dport
clientIp = SYN_REQ[0][IP].src
serverIp = SYN_REQ[0][IP].dst



# log this response
log(clientIp, serverIp, SYN_REQ[0][TCP].flags, SYN_REQ[0].seq, SYN_REQ[0].ack)

# lets calculate our seq and ack after we get syn request
# seq remains unchanged
# ack is set to sequence of the syn increased by 1
# this is because we will send a syn-ack packet
ack = r_seq + 1


ip = IP(src=serverIp, dst=clientIp)

# log this packet 
log(serverIp, clientIp, "SA", SYN_REQ[0].seq, SYN_REQ[0].seq+1) 
# we will reply with synack, seq = syn.seq, ack = syn.seq +1, options (mss,1460)
SYNACK = TCP(sport=serverPort, dport=clientPort, flags="SA",
             seq=seq, ack=ack, options=[('MSS', 1460)])
ack_response = sr1(ip/SYNACK)

# update received params
update(ack_response)

# log this response
log(clientIp, serverIp, ack_response[0][TCP].flags, ack_response[0].seq, ack_response[0].ack)





## now lets close the connection
fin_seq =  r_ack
fin_ack =  r_seq


FIN=TCP(sport=serverPort, dport=clientPort, flags="FA", seq=fin_seq, ack=fin_ack,options=[('MSS', 1460)] )
FINACK=sr1(ip/FIN)
LASTACK=TCP(sport=serverPort, dport=clientPort, flags="A", seq=FINACK.ack, ack=FINACK.seq + 1, options=[('MSS', 1460)])
send(ip/LASTACK)
