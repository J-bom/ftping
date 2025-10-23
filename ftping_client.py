from scapy.all import *
from scapy.layers.inet import *
import os
import random
import sys

msgid = 0
def ispacket(packet):
    global msgid
    if ICMP in packet:
        if packet[ICMP].id == msgid + 1:
            if Raw in packet:
                if packet[Raw].load == b'ACK' or packet[Raw].load.decode().split('#')[0] == 'ERROR':
                    print(f"recived packet {msgid}: {packet[Raw].load}")
                    msgid += 2

                    return True
        else:
            print(f"msgid desync on {msgid}")
    return False

def send_packet(destination,data):
    global msgid
    if isinstance(data,str):
        data = data.encode()
    send(IP(dst=destination) / ICMP(id=msgid) / Raw(data))
    print(f"sent packet number {msgid}: {data}")
    #msgid += 1

def ftping(dst_ip, fname, fdst, chunk=1024):
    global msgid
    destination_confirmed = False
    send_packet(dst_ip,fdst)
    while not destination_confirmed:
        replypkt = sniff(lfilter=ispacket, count=1, timeout=5)
        if not replypkt:
            print("no response :(")
            send_packet(dst_ip, fdst)

        else:
            response = replypkt[0][Raw].load.decode()
            print(f"got {response}")
            if response != "ACK":
                response = response.split('#')
                code = response[0]
                fields = response[1:]
                if code == "ERROR":
                    if fields[0] == "deny":
                        print("Access to directory denied. try a different directory")
                        quit()
                    elif fields[0] == "path":
                        print("Path Inacessable. Please try a different directory.")
                        quit()
            else:
                destination_confirmed = True

    if os.path.isfile(fname):
        with open(f"{fname}", "rb") as f:
            chunkid = 1
            data = f.read(chunk)
            while data:
                send_packet(dst_ip, data)
                while True:
                    ackpkt = sniff(lfilter=ispacket, count=1, timeout=5)
                    if not ackpkt:
                        print("no response :(")
                        send_packet(dst_ip, data)
                        chunkid += 1
                    else:
                        break
                chunkid += 1
                data = f.read(chunk)
        send_packet(dst_ip, '#BYE')
        print('file sent succsessfuly!')
        print(msgid)
    else:
        print('file no found')
        return


def main(server_ip,file_path,dst_dir):
    ftping(server_ip, file_path, dst_dir)


if __name__ == "__main__":
    if len(sys.argv) >= 4:
        main(sys.argv[1],sys.argv[2],sys.argv[3])
    else:
        print("USAGE: python ftping_client [SERVER IP] [LOCAL FILE PATH] [DESTINATION PATH ON THE SERVER]")
