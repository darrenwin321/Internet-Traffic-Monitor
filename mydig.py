import dns.query
import dns.message
import time
from datetime import datetime
import dns.rdtypes.IN.A
import dns.rdtypes.ANY.CNAME


def mydig(domain): #hard coding the root servers for the function.
    root_servers = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4',
        '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']
    runtime = True
    counter = 0; #in case we need to ask multiple root servers
    answer = None
    
    while runtime:# checking servers until we find an anwer.
            if counter == 13:
                raise Exception("Something is wrong, please try again later") # after all root servers are checked, we throw an exception
            question = dns.message.make_query(domain, dns.rdatatype.A)
            answer = dns.query.udp(question, root_servers[counter], 5) #we root server for the address of the domain.
            counter += 1 # increment to next root server in case of an error.
            # in case of an error, continue and try another root server. but if it doesnt exist, throw an exception.
            if answer.rcode() == dns.rcode.NXDOMAIN:
                raise Exception("Domain does not exist, try again.")
            elif answer.rcode() != dns.rcode.NOERROR: 
                continue
            else:#if we avoided all erros, we continue
                print ("Question Section:")
                print (question.question[0])
                print("Answer Section:")
                while runtime:
                    counter = 0
                    if len(answer.answer) > 0:
                        try:
                            if isinstance(answer.answer[0][0], dns.rdtypes.ANY.CNAME.CNAME): # if the answer section contains cname, recursively solve
                                return mydig(answer.answer[0][0].to_text())
                            else:
                                return answer.answer[0] # return the whole line including the ip for the answer.
                        except:
                            print("Something is wrong with the query try again")# in the case of error or parsing answer section
                    while not isinstance(answer.additional[counter][0], dns.rdtypes.IN.A.A):# if not ipv4, skip it
                        counter += 1  
                    else:
                        try:
                            question = dns.message.make_query(domain, dns.rdatatype.A)
                            answer = dns.query.udp(question, answer.additional[counter][0].to_text() , 5)#query until we find the IP
                        except:
                            continue
    return 0 
    
def main():
    domain = input("Enter domain name: ")
    start = time.time() # time we start seaching for the IP
    print(mydig(domain))
    print("Query Time:", (time.time()-start) * 1000, "ms")
    print("When:" ,datetime.now()) 
    
if __name__ == "__main__":
    main()