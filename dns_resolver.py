import time
import json
import socket
import pathlib
import threading

from dns_utils import *
from random import randint
from queue import PriorityQueue
   
  
def send_message(sock, dest, msg_bytes):
    """ 
        Function to send an entire message to the supplied socket. 
        Breaks the message into multiple packets if it cannot be sent in one piece.
    """ 
    msg_len = len(msg_bytes)
    num_bytes_to_send = msg_len
    while num_bytes_to_send > 0:
        num_bytes_to_send -= sock.sendto(msg_bytes[msg_len-num_bytes_to_send:], dest)
        

class DNSServer:
    """ Handles incoming user requests, consults the DNS Resolver and responds to the user. """

    def __init__(self, host, json_file):
        self.socket_dest = (host, 53)
        self.resolver = DNSResolver(json_file)

    def listen(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(self.socket_dest) # Bind to the socket

            while True:
                try:
                    data, addr = sock.recvfrom(512) # DNS UDP messages are limited to 512 bytes
                    threading.Thread(target=self.handle_request, args=(sock, data, addr)).start()
                except ConnectionResetError as e:
                    print("Reseting connection:", e) 

    def handle_request(self, sock, req_data, addr):
        req_message = Message.from_bytes(req_data) # Parse the request

        # If the message is flagged as a response, no need to answer
        if req_message.flags.qr:
            return

        print("Incoming request:", req_message.queries[0].type_str, req_message.queries[0].name)

        response = self.resolver.get_response(req_message)
        if response:
            send_message(sock, addr, response.to_bytes())



class DNSResolver:
    def __init__(self, json_filename):
        self.data_lock = threading.Lock()
        self.json_file_path = pathlib.Path(__file__).parent / json_filename
        with open(self.json_file_path, 'r') as f:
            self.data = json.loads(f.read())
        
        self.cur_transaction_id = randint(0, 2**16)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('', 0))

        threading.Thread(target=self.__listen).start()
        threading.Thread(target=self.__cache_purging, args=(60.0,)).start()

        self.msgs = {}
        self.recursion_depth = 0
        
    def __del__(self):
        self.sock.close()
        self.store_data()

    def __listen(self):
        while True:
            data, addr = self.sock.recvfrom(512)
            recv_time = time.time()
            msg = Message.from_bytes(data)
            if msg.transaction_id in self.msgs:
                evt = self.msgs[msg.transaction_id]
                self.msgs[msg.transaction_id] = (msg, recv_time)
                evt.set()

    def __cache_purging(self, timeout = 60.0):
        """ Periodically checks the cache for expired entries and deletes them. ``timeout`` specifies the number of seconds between purges. """
        while True:
            starttime = time.time()
            num_deleted = 0
            with self.data_lock:
                for cls in self.data['cache']:
                    for type in self.data['cache'][cls]:
                        for dname in list(self.data['cache'][cls][type].keys()):
                            self.data['cache'][cls][type][dname][:] = [entry for entry in self.data['cache'][cls][type][dname] if entry['expires'] > starttime]
                            if not self.data['cache'][cls][type][dname]:
                                num_deleted += 1
                                del self.data['cache'][cls][type][dname]

            print("Deleted", num_deleted, "cache entries in", round((time.time() - starttime) * 1000000), "µs")
            self.store_data()
            time.sleep(timeout - ((time.time() - starttime) % timeout))


    def store_data(self):
        print("Storing data to", self.json_file_path)
        with open(self.json_file_path, 'w') as f:
            with self.data_lock:
                json.dump(self.data, f, indent=4)
            
    def add_to_cache(self, rr: ResourceRecord):
        if rr.ttl <= 0:
            return

        new_entry = {key: val if isinstance(val, (int, str)) else str(val) for key,val in rr.data.items()}

        with self.data_lock:
            try:
                if str(rr.domain_name) in self.data['cache'][rr.cls_str][rr.type_str]:
                    for entry in self.data['cache'][rr.cls_str][rr.type_str][str(rr.domain_name)]:
                        if new_entry.items() <= entry.items():
                            entry['expires'] = int(time.time()) + rr.ttl
                            break
                    else:
                        new_entry['expires'] = int(time.time()) + rr.ttl
                        self.data['cache'][rr.cls_str][rr.type_str][str(rr.domain_name)].append(new_entry)
                else:
                    new_entry['expires'] = int(time.time()) + rr.ttl
                    self.data['cache'][rr.cls_str][rr.type_str][str(rr.domain_name)] = [new_entry]
            except KeyError as e:
                if rr.cls_str not in self.data['cache']:
                    self.data['cache'][rr.cls_str] = {}
                elif rr.type_str not in self.data['cache'][rr.cls_str]:
                    self.data['cache'][rr.cls_str][rr.type_str] = {}
                else:
                    raise e
                self.add_to_cache(rr)

    def cache_message(self, msg: Message):
        if msg.flags.opcode == 1 or b'*' in msg.queries[0].name.labels:
            # Don't cache results of inverse queries or ones with wildcard labels
            return
        for rr in msg.all_rrs():
            self.add_to_cache(rr)

    def get_response(self, req_msg: Message) -> Message:
        # In practice there will always only be one query in a Message (cf. https://stackoverflow.com/q/4082081/13197300)
        query = req_msg.queries[0]
        resp_flags = Flags(qr=1, rd=req_msg.flags.rd, ra=1)
        try:
            if str(query.name) in self.data['cache'][query.cls_str][query.type_str]:
                answer_rrs = [
                    ResourceRecord.from_cache(entry, query.name, query.type, query.cls)
                    for entry in self.data['cache'][query.cls_str][query.type_str][str(query.name)]
                    if entry['expires'] > time.time()
                ]
                if answer_rrs:
                    return Message(req_msg.transaction_id, resp_flags, req_msg.queries, answer_rrs)
        except KeyError as e:
            with self.data_lock:
                if query.cls_str not in self.data['cache']:
                    self.data['cache'][query.cls_str] = {}
                elif query.type_str not in self.data['cache'][query.cls_str]:
                    self.data['cache'][query.cls_str][query.type_str] = {}
                else:
                    raise e


        if str(query.name) in self.data['cache'][query.cls_str]['cname']:
            cname_rr = ResourceRecord.from_cache(self.data['cache'][query.cls_str]['cname'][str(query.name)][0], query.name, 5, 1)
            res = self.get_cname_response(cname_rr, req_msg.queries)
        else:
            res = self.recursive_lookup(req_msg)

        res.transaction_id = req_msg.transaction_id
        res.flags.ra = 1
        res.flags.aa = 0
        return res

    def get_cname_response(self, cname_rr: ResourceRecord, orig_queries):
        # print("CNAME for", cname_rr.domain_name, "->", cname_rr.data['cname'])
        cname_req = Message(0, Flags(rd=1), queries=[Query(cname_rr.data['cname'], orig_queries[0].type, orig_queries[0].cls)])
        cname_resp = self.get_response(cname_req)
        cname_resp.queries = orig_queries
        cname_resp.answer_rrs.insert(0, cname_rr)
        cname_resp.authority_rrs = []
        return cname_resp

    def is_answer(self, msg: Message, query: Query):
        for an_rr in msg.answer_rrs:
            if query.cls == an_rr.cls and query.type == an_rr.type and query.name == an_rr.domain_name:
                return True
        return False

    def recursive_lookup(self, request: Message) -> Message:

        if self.recursion_depth >= 50:
            raise Exception("Maximum recursion depth reached")

        query = request.queries[0]
        req_flags = Flags(rd = 1)
        recursive_msg = Message(self.cur_transaction_id, req_flags, queries = request.queries)
        self.cur_transaction_id = (self.cur_transaction_id + 1) % 0x10000

        slist = SList(query.name, self.data['cache'][query.cls_str])

        num_timeouts = 0

        while slist.tries < 20 and num_timeouts < 5:
            cur_address = slist.get_next(self)
            # print("Now querying", cur_address.dname_str, "at", cur_address.address)
            recursive_msg.transaction_id = self.cur_transaction_id
            self.cur_transaction_id = (self.cur_transaction_id + 1) % 0x10000

            send_time = time.time()
            send_message(self.sock, (cur_address.address, 53), recursive_msg.to_bytes())
            msg_event = threading.Event()
            self.msgs[recursive_msg.transaction_id] = msg_event
            if not msg_event.wait(min(5, cur_address.rtt_avg + 2)):
                cur_address.update_batting(0)
                with self.data_lock:
                    cur_address.cache_info(self.data['cache'][query.cls_str])
                num_timeouts += 1
                continue
            
            resp_msg, recv_time = self.msgs[recursive_msg.transaction_id]
            del self.msgs[recursive_msg.transaction_id]

            cur_rtt = round((recv_time - send_time) * 1000)
            cur_address.update_rtt(cur_rtt)
            cur_address.update_batting(1)
            with self.data_lock:
                cur_address.cache_info(self.data['cache'][query.cls_str])
            
            # Name Error -> done
            if resp_msg.flags.rcode == 3:
                # Remove any potential soas
                resp_msg.authority_rrs = []
                return resp_msg

            # Server error
            if resp_msg.flags.rcode != 0:
                continue

            # Response answers the query -> done
            if self.is_answer(resp_msg, query):
                self.cache_message(resp_msg)
                return resp_msg

            # Response contains a CNAME (which is not the answer)
            for an_rr in resp_msg.answer_rrs:
                if an_rr.type == 5:
                    cname = an_rr.data['cname']
                    self.add_to_cache(an_rr)
                    for other_rr in resp_msg.all_rrs():
                        if other_rr.type == 1 and other_rr.domain_name == cname:
                            # If there is another resource record supplying the ip address for the cname, this Message is all we need
                            return resp_msg
                    # Otherwise go back to step 1
                    return self.get_cname_response(an_rr, request.queries)

            # If  there are no RRs or only an SOA RR this is the response
            all_rrs = resp_msg.all_rrs()
            if not len(all_rrs) or (len(all_rrs) == 1 and all_rrs[0].type == 6):
                resp_msg.authority_rrs = []
                return resp_msg
                
            # Response contains delegation information to a better server
            for ns_rr in resp_msg.authority_rrs:
                if ns_rr.type != 2:     # NS
                    continue
                slist.add_server(ns_rr, self.data['cache'][query.cls_str])
            for ad_rr in resp_msg.additional_rrs:
                if ad_rr.type == 1 or ad_rr.type == 28:
                    slist.add_address(ad_rr)
            self.cache_message(resp_msg)


        print("Cancelling lookup after", slist.tries, "tries")
        return Message(request.transaction_id, Flags(qr=1, ra=1, rcode=2), queries=request.queries)



class ForeignServerAddress:
    """ Holds and keeps address and rtt/batting information of a Foreign Name Server. """
    DAMPING_FACTOR = 0.5

    def __init__(self, server_name, address, rtt_avg = 5000, batting_avg = 1.0):
        self.dname_str = server_name
        self.address = address
        self.rtt_avg = rtt_avg
        self.batt_avg = batting_avg

    def __lt__(self, other):
        return self.get_priority() < other.get_priority()

    def update_rtt(self, new_rtt):
        self.rtt_avg = (1 - ForeignServerAddress.DAMPING_FACTOR) * self.rtt_avg + ForeignServerAddress.DAMPING_FACTOR * new_rtt

    def update_batting(self, arrived):
        self.batt_avg = (1 - ForeignServerAddress.DAMPING_FACTOR) * self.batt_avg + ForeignServerAddress.DAMPING_FACTOR * arrived
        
    def cache_info(self, cache):
        try:
            for entry in cache['a'][self.dname_str]:
                if entry['address'] == self.address:
                    entry['info'] = {'rtt' : self.rtt_avg, 'batting' : self.batt_avg}
        except KeyError:
            cache['a'][self.dname_str] = [{'address' : self.address, 'expires' : time.time() + 3600}]

    def get_priority(self):
        return self.rtt_avg / self.batt_avg

class SList:
    """ A structure which describes the name servers and the zone which the resolver is currently trying to query.\n
        Uses Priority Queues based on RTT/batting averages to choose the next server to query. """

    # Root servers a and b
    SBELT = [ForeignServerAddress("a.root-servers.net", "198.41.0.4"), ForeignServerAddress("b.root-servers.net", "199.9.14.201")]
    
    def __init__(self, sname: DomainName, cache):
        self.sname = sname
        self.server_info = [{'domains' : set(), 'addresses' : PriorityQueue()} for _ in range(len(sname.labels) + 1)]
        self.tries = 0

        for sname_dist in range(len(sname.labels) + 1):
            cur_zone = str(sname.parent_domain(sname_dist))
            if cur_zone in cache['ns']:
                for k in range(len(cache['ns'][cur_zone])):
                    if cache['ns'][cur_zone][k]['expires'] < time.time():
                        continue
                    cur_nsdname = cache['ns'][cur_zone][k]['nsdname']
                    self.server_info[sname_dist]['domains'].add(cur_nsdname)

                    self.check_cache_for_addresses(cache, cur_nsdname, sname_dist)

                # To avoid infinite recursion:
                # If the current sname is one of the name servers for one of its own parent domains
                # and there are no addresses for any of these name servers in the cache,
                # clear the domains for this level as it would lead to an infite loop otherwise
                if self.server_info[sname_dist]['addresses'].empty() and str(self.sname) in self.server_info[sname_dist]['domains']:
                    self.server_info[sname_dist]['domains'].clear()



    def check_cache_for_addresses(self, cache, nsdname, sname_dist):
        if nsdname in cache['a']:
            for l in range(len(cache['a'][nsdname])):
                if cache['a'][nsdname][l]['expires'] < time.time():
                    continue                                
                fsa = ForeignServerAddress(nsdname, cache['a'][nsdname][l]['address'])
                if 'info' in cache['a'][nsdname][l]:
                    fsa.rtt_avg = cache['a'][nsdname][l]['info']['rtt']
                    fsa.batt_avg = cache['a'][nsdname][l]['info']['batting']
                self.server_info[sname_dist]['addresses'].put(fsa)

    def get_next(self, local_server: DNSResolver):
        self.tries += 1
        for sname_dist in range(len(self.server_info)):
            lvl = self.server_info[sname_dist]
            if not lvl['addresses'].empty():
                return lvl['addresses'].get()
            if lvl['domains']:
                for dom_str in lvl['domains']:
                    dom = DomainName.from_string(dom_str)
                    ns_req = Message(0, Flags(), queries=[Query(dom)]) 
                    local_server.recursion_depth += 1
                    resp = local_server.recursive_lookup(ns_req)
                    local_server.recursion_depth -= 1
                    for an_rr in resp.all_rrs():
                        if an_rr.type == 1 and an_rr.domain_name == dom:
                            self.add_address(an_rr)
                    if not lvl['addresses'].empty():
                        return lvl['addresses'].get()

        # If there is nothing else, return one of the root servers at random
        return SList.SBELT[(time.time() % 1) > 0.5]


    def add_server(self, ns_rr: ResourceRecord, cache):
        if ns_rr.type != 2 or not ns_rr.domain_name.is_parent(self.sname) or ns_rr.data['nsdname'] == self.sname:
            return

        sname_dist = len(self.sname.labels) - len(ns_rr.domain_name.labels)
        nsdname = str(ns_rr.data['nsdname'])
        self.server_info[sname_dist]['domains'].add(nsdname)
        self.check_cache_for_addresses(cache, nsdname, sname_dist)

    def add_address(self, rr: ResourceRecord):
        if rr.type != 1:
            return

        for lvl in self.server_info:
            if str(rr.domain_name) in lvl['domains']:
                fsa = ForeignServerAddress(str(rr.domain_name), rr.data['address'])
                lvl['addresses'].put(fsa)
                return        



if __name__ == '__main__':
    DNSServer('127.0.0.1', 'dns_cashe.json').listen()
