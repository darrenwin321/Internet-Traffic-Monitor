import dpkt
import socket

def analysis(pcapfile):
    num_of_flows = 0
    f = open (pcapfile, 'rb')
    pcap = dpkt.pcap.Reader(f)
    flows = {} # a dictionary of flows and num that describes thier status. in form [sport. sip, dport, dip] as key and a sum as value. 
    #if value is over a certain threshold, then we know it is a valid flow. add to threshold in 2^n order.
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP: #check if packet contains an ip else skip it
            continue
        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_TCP: # check if it is TCP else skip
            continue
        tcp = ip.data
        if tcp.flags & dpkt.tcp.TH_SYN:
            if tcp.flags & dpkt.tcp.TH_ACK:
                if (tcp.dport, ip.dst, tcp.sport , ip.src) in flows.keys(): # lsyn ack comes from server so it has stuff reveresed
                    if flows[(tcp.dport, ip.dst, tcp.sport , ip.src)] == 0: # checks just in case a syn ack has dropped previously and had to be re sent
                        flows[(tcp.dport, ip.dst, tcp.sport , ip.src)] = 1 # when it hits syn ack add 1 to the total.
            else:
                flows[(tcp.sport , ip.src, tcp.dport, ip.dst)] = 0 #initiallize the value to 0
                dport = tcp.dport
            continue
        if (tcp.flags & dpkt.tcp.TH_FIN) and tcp.dport == dport:
            flows[(tcp.sport , ip.src, tcp.dport, ip.dst)] = 3
            continue
    
    for v in flows.values():
        if v == 3:
            num_of_flows += 1
    print ("The number of flows:", num_of_flows,"\n")
    #print(num_of_flows)
    for index, tuple in enumerate(flows.keys()):
        if flows.get(tuple) != 3:
            flows.pop(tuple, 1)
    count = 1
    f.close()
    keys = flows.keys()
    for index, tuple in enumerate(keys):
        throughput = 0
        f = open (pcapfile, 'rb')
        pcap = dpkt.pcap.Reader(f)
        print ("Flow Number", count)
        print ("Source Port:", tuple[0])
        print ("Source IP:", socket.inet_ntoa(tuple[1]))
        print ("Destination Port:", tuple[2])
        print ("Destination IP:", socket.inet_ntoa(tuple[3]))
        print('\n')
        count += 1
        ack = 1 #ignore the first ack so since that is just used to establish a conneciton
        counter = 1 # tracking only 2 transmissions
        add = False
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP: #check if packet contains an ip else skip it
                continue
            ip = eth.data
            if ip.p != dpkt.ip.IP_PROTO_TCP: # check if it is TCP else skip
                continue
            tcp = ip.data
            if tcp.flags & dpkt.tcp.TH_FIN and (tcp.sport == tuple[0] or tcp.dport == tuple[0]):
                break#break at fin flag
            final_time = ts
            if tcp.sport == tuple[0] or tcp.dport == tuple[0]:
                if (tcp.flags &  dpkt.tcp.TH_ACK) and not (tcp.flags & dpkt.tcp.TH_SYN) and not (tcp.flags & dpkt.tcp.TH_FIN) and counter <= 2:
                    if ack == 1:
                        ack -= 1# skips over first ack after 2 way handshake
                    elif ack == 0:
                        add = True
                        print ("Transmisison #", counter)
                        print ("Sequence Number:", tcp.seq)
                        print ("Ack Number:", tcp.ack)
                        print ("Win Number:", tcp.win)
                        print('\n')
                        if counter == 1:
                            initial_time = ts
                        counter += 1
            if tcp.sport == tuple[0] and add:#being adding after 3 way handshake
                throughput += len(tcp)
        print("Bytes Sent :", throughput)
        total_time = final_time - initial_time
        print ("duration:", total_time, "seconds")
        print ("Throughput:", throughput / total_time, "bytes/second")
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++")
        print ('\n')  
        f.close()
        
        #Part b: calculating congestion window.
    f = open (pcapfile, 'rb')
    pcap = dpkt.pcap.Reader(f)# calculate the RTT
    port = 0
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP: #check if packet contains an ip else skip it
            continue
        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_TCP: # check if it is TCP else skip
            continue
        tcp = ip.data
        if tcp.flags & dpkt.tcp.TH_SYN and tcp.flags & dpkt.tcp.TH_ACK and tcp.dport == port:
            final_time = ts
            break
        if tcp.flags & dpkt.tcp.TH_SYN:   
            port = tcp.sport
            initial_time = ts
    RTT = final_time - initial_time
    RTT = RTT * .95 #give leeway as RTT isnt alwyas exacatly 1 number
    current = 1
    f.close()
    congestion_window = ()
    empty = ()
    for index, tuple in enumerate(keys):
        count = 1
        f = open (pcapfile, 'rb')
        pcap = dpkt.pcap.Reader(f)
        congestion_window = empty
        counter = 0
        print ("Flow", current)
        current += 1
        current_time = 0
        prev_time = 0
        run = True
        prev_ack = 0
        triple_ack_counter = 0
        trip_ack_err = 0
        seq = ()
        retrans = ()
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP: #check if packet contains an ip else skip it
                continue
            ip = eth.data
            if ip.p != dpkt.ip.IP_PROTO_TCP: # check if it is TCP else skip
                continue
            tcp = ip.data
            if tcp.flags & dpkt.tcp.TH_FIN and (tcp.sport == tuple[0] or tcp.dport == tuple[0]):# when a packet includes fin we break
                break #break at fin flag
            if tuple[0] == tcp.sport and not tcp.flags & dpkt.tcp.TH_SYN:# when the packet is just an ack and of the source port we 
                current_time = ts                          # add to the counter of packets in a window
                if tcp.seq in seq:
                    if tcp.seq in retrans:
                        pass
                    else:
                        retrans = retrans + (tcp.seq,)
                if count > 3:
                    pass
                elif (current_time - prev_time < RTT) or run:
                    counter += 1
                    run = False
                else:
                    count += 1
                    congestion_window = congestion_window + (counter,)
                    counter = 1
                prev_time = ts
                seq = seq + (tcp.seq,)
            if tuple[0] == tcp.dport and tcp.flags & dpkt.tcp.TH_ACK:
                current_ack = tcp.ack
                if current_ack == prev_ack:
                    triple_ack_counter += 1
                else:
                    triple_ack_counter = 1
                if triple_ack_counter == 4 and not tcp.ack in retrans:# triple ack occurs when more than 3 acks happen in a row increments counter
                    trip_ack_err += 1
                prev_ack = tcp.ack
            
        print("Congestion window:" ,congestion_window)
        print ("Retransmissions due to triple duplicate acks:", trip_ack_err)
        print ("Retransmissions due to timeout:", len(retrans) - trip_ack_err)
        f.close()

def main():
   domain = input("Enter pcap file name: ")
   analysis(domain)

if __name__ == "__main__":
    main()