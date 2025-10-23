from scapy.all import *
from scapy.layers.inet import *
import sys
msgid = 0

def isapacket(packet):
    global msgid
    if ICMP in packet:
        if packet[ICMP].id == msgid:
            if Raw in packet:
                print(f'recieved number {msgid}: {packet[Raw].load}')
                msgid +=1
                return True
        else:
            print(f'msgid desync on {msgid}')
    return False


def send_packet(destination,data):
    global msgid
    if isinstance(data,str):
	    data = data.encode()
    send(IP(dst=destination) / ICMP(id=msgid) / Raw(data))
    print(f'sent packet number {msgid}: {data}')
    msgid += 1


def main(client_ip):
    print('starting server...')
    fpathpkt = None
    while True:
        pkt = sniff(filter="icmp", lfilter=isapacket, count=1)
        if pkt:
            fpathpkt = pkt[0]
            if fpathpkt[Raw].load != b"ACK":
                break
    fname = fpathpkt[Raw].load.decode()
    try:
        with open(f"{fname}",'wb') as f:
            print('no file errors detected')
    except PermissionError:
        send_packet(client_ip, 'ERROR#deny')
        quit()
    except (NotADirectoryError,FileNotFoundError, OSError):
        send_packet(client_ip, 'ERROR#path')
        quit()
    send_packet(client_ip,'ACK')
    done = False
    print(f"directing to {fname}")
    with open(f'{fname}', 'wb') as f:
        while not done:
            pkt = sniff(filter="icmp", lfilter=isapacket, count=1)[0]
            if pkt:
                if pkt[Raw].load != b'ACK':
                    data = pkt[Raw].load
                    if data == b'#BYE':
                        print('file downloaded successfuly')
                        print(msgid)
                        done = True
                    else:
                        f.write(data)
                        send_packet(client_ip, 'ACK')



if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print("USAGE: python ftping_server.py [source ip]")
    else:
        main(sys.argv[1])
