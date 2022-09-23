import dpkt
import socket

def analysis(pcapfile):
    f = open (pcapfile, 'rb')
    pcap = dpkt.pcap.Reader(f)
    count = 0
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.arp.ARP): #check if packet contains an ip else skip it
            continue
        ip = eth.data
        if ip.sha == b'\xaa\xbb\xcc\xdd\xee\xff':
            continue
        if count == 0: # the request
            print("Request:")
            nextpacket = ip.sha
            count += 1
            print("Hardware type:", ip.hrd)
            print("Protocol type:", hex(ip.pro))
            print("Hardware size:", ip.hln)
            print("Protocol size:", ip.pln)
            print("Sender MAC address:" ,ip.sha.hex(":"))
            print("Sender IP address:" ,socket.inet_ntoa(ip.spa))
            print("Target MAC address:" ,ip.tha.hex(":"))
            print("Target IP address:" ,socket.inet_ntoa(ip.tpa))
            continue
        if count  == 1: #the response
            if nextpacket == ip.tha:
                print("")
                print ("Response:")
                print("Hardware type:", ip.hrd)
                print("Protocol type:", hex(ip.pro))
                print("Hardware size:", ip.hln)
                print("Protocol size:", ip.pln)
                print("Sender MAC address:" ,ip.sha.hex(":"))
                print("Sender IP address:" ,socket.inet_ntoa(ip.spa))
                print("Target MAC address:" ,ip.tha.hex(":"))
                print("Target IP address:" ,socket.inet_ntoa(ip.tpa))
                return # return when done to not waste processing power/time
        
def main():
   domain = input("Enter pcap file name: ")
   print("")
   analysis(domain)

if __name__ == "__main__":
    main()
