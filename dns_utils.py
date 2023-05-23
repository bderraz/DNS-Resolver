import time
from ipaddress import IPv6Address, IPv4Address


TYPES = {
    1 : 'a',
    2 : 'ns',
    3 : 'md',
    4 : 'mf',
    5 : 'cname',
    6 : 'soa',
    7 : 'mb',
    8 : 'mg',
    9 : 'mr',
    10 : 'null',
    11 : 'wks',
    12 : 'ptr',
    13 : 'hinfo',
    14 : 'minfo',
    15 : 'mx',
    16 : 'txt',
    28 : 'aaaa',
    65 : 'https',
    255 : '*'
}

CLASSES = {
    1 : 'in',
    2 : 'cs',
    3 : 'ch',
    4 : 'hs',
    255 : '*'
}    

class DomainName:
    """ Domain name class for easier translation between the different representations:
        - common format, e.g. "example.com."
        - a list of labels
        - a byte-sequence of labels as used in the DNS protocol
    """
    def __init__(self, labels):
        self.labels = labels

    @classmethod
    def from_data(cls, data, idx):
        """ Constructs a DomainName object from raw message bytes accounting for message compression.\n
            Returns a tuple containing the DomainName object and the index of the first data byte after the domain name. """
        labels = []
        compression_encountered = False
        next_label_len = data[idx]
        idx += 1
        while next_label_len != 0:
            # If the first two bits of the next_label_len byte are ones this is a pointer
            if next_label_len >= 0xc0:
                if not compression_encountered:
                    compression_encountered = True
                    end_of_dn_idx = idx + 1

                idx = (next_label_len - 0xc0) * 0x100 + data[idx]
                next_label_len = data[idx]
                idx += 1
            else:
                labels.append(data[idx:idx + next_label_len])
                idx += next_label_len + 1
                next_label_len = data[idx - 1]

        return (cls(labels), end_of_dn_idx if compression_encountered else idx)

    @classmethod
    def from_string(cls, dn_str):
        return cls(dn_str.encode('utf-8').split(b'.'))

    def __str__(self):
        return b'.'.join(self.labels).decode('utf-8') if self.labels else '.'

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return self.labels == other.labels
    
    def __hash__(self) -> int:
        return hash(str(self))

    def to_bytes(self, encoded_dnames = None, cur_idx = 0):
        """Returns the Domain Name as a bytes object using the encoding specified in RFC1035"""
        byte_encoding = b''
        if encoded_dnames == None:
            for lbl in self.labels:
                byte_encoding += len(lbl).to_bytes(1, 'big')
                byte_encoding += lbl
            return byte_encoding

        for i in range(len(self.labels)):
            cur_parent = self.parent_domain(i)
            if cur_parent in encoded_dnames:
                byte_encoding += (encoded_dnames[cur_parent] + 0xc000).to_bytes(2, 'big')
                return byte_encoding
            encoded_dnames[cur_parent] = cur_idx
            byte_encoding += len(self.labels[i]).to_bytes(1, 'big')
            byte_encoding += self.labels[i]
            cur_idx += len(self.labels[i]) + 1
        byte_encoding += b'\x00'
        return byte_encoding

    def parent_domain(self, levels_above = 1):
        return DomainName(self.labels[levels_above:])

    def is_parent(self, of):
        return self.labels == of.labels[len(of.labels) - len(self.labels):]


class Query:
    """ Query class representing a single DNS query. """

    @staticmethod
    def deserialise_queries(qdcount, qdata):
        queries = []

        cur_idx = 0
        while cur_idx < len(qdata) and len(queries) < qdcount:
            dname, cur_idx = DomainName.from_data(qdata, cur_idx)
            qtype = int.from_bytes(qdata[cur_idx:cur_idx+2], byteorder='big') 
            qclass = int.from_bytes(qdata[cur_idx+2:cur_idx+4], byteorder='big') 
            cur_idx += 4
            queries.append(Query(dname, qtype, qclass))
        
        return queries

    def __init__(self, qname: DomainName, qtype = 1, qclass = 1):
        self.name = qname
        self.type = qtype
        try:
            self.type_str = TYPES[qtype]
        except KeyError:
            self.type_str = 'undefined'
        self.cls = qclass
        try:
            self.cls_str = CLASSES[qclass]
        except KeyError:
            # Default to the internet
            self.cls_str = 'in'

    def to_bytes(self, encoded_dnames = None, cur_idx = 0):
        return self.name.to_bytes(encoded_dnames, cur_idx) + self.type.to_bytes(2, 'big') + self.cls.to_bytes(2, 'big')


class ResourceRecord:
    """ Resource Record (RR) class that is used for responses in the answer, authority, and additional sections. """

    def __init__(self, domain_name : DomainName, rr_type, rr_class, ttl, rdlength, rdata):
        self.domain_name = domain_name
        self.type = rr_type
        try:
            self.type_str = TYPES[rr_type]
        except KeyError:
            self.type_str = 'undefined'
        self.cls = rr_class
        try:
            self.cls_str = CLASSES[rr_class]
        except KeyError:
            # Default to the internet
            self.cls_str = 'in'
        self.ttl = ttl
        self.data_length = rdlength
        self.raw_data = rdata
        self.data = {}

    @classmethod 
    def from_data(cls, data, cur_idx):
        dname, cur_idx = DomainName.from_data(data, cur_idx)
        rr_type = int.from_bytes(data[cur_idx : cur_idx+2], byteorder='big') 
        cur_idx += 2
        rr_class = int.from_bytes(data[cur_idx : cur_idx+2], byteorder='big') 
        cur_idx += 2
        ttl = int.from_bytes(data[cur_idx : cur_idx+4], byteorder='big') 
        cur_idx += 4
        rdlength = int.from_bytes(data[cur_idx : cur_idx+2], byteorder='big') 
        cur_idx += 2
        rdata = data[cur_idx : cur_idx + rdlength]

        rr = cls(dname, rr_type, rr_class, ttl, rdlength, rdata)

        # RR types that should be supported: A (1), AAAA (28), NS (2), CNAME (5), SOA (6), PTR (12), MX (15), TXT? (16)
        match rr_type:
            case 1:     # A
                rr.data = {'address' : IPv4Address(rdata).compressed}
            case 2:     # NS
                rr.data = {'nsdname' : DomainName.from_data(data, cur_idx)[0]}
            case 5:     # CNAME
                rr.data = {'cname' : DomainName.from_data(data, cur_idx)[0]}
            case 6:     # SOA
                mname, cur_idx = DomainName.from_data(data, cur_idx)
                rname, cur_idx = DomainName.from_data(data, cur_idx)
                rr.data = {
                    'mname'     : mname,
                    'rname'     : rname,
                    'serial'    : int.from_bytes(data[cur_idx      : cur_idx + 4], 'big'),
                    'refresh'   : int.from_bytes(data[cur_idx + 4  : cur_idx + 8], 'big'),
                    'retry'     : int.from_bytes(data[cur_idx + 8  : cur_idx + 12], 'big'),
                    'expire'    : int.from_bytes(data[cur_idx + 12 : cur_idx + 16], 'big'),
                    'minimum'   : int.from_bytes(data[cur_idx + 16 : cur_idx + 20], 'big')
                }
            case 15:    # MX
                rr.data = {
                    'preference' : int.from_bytes(data[cur_idx : cur_idx + 2], 'big'),
                    'exchange' : DomainName.from_data(data, cur_idx + 2)[0]
                }
            case 28:    # AAAA
                rr.data = {'address' : IPv6Address(rdata).compressed}

        return (rr, cur_idx + rdlength)

    @classmethod
    def from_cache(cls, cache_entry, domain_name : DomainName, rr_type, rr_class):
        data = cache_entry.copy()
        data.pop('expires', None)
        data.pop('info', None)

        match rr_type:
            case 1:     # A
                raw_data = IPv4Address(data['address']).packed
            case 2:     # NS
                data['nsdname'] = DomainName.from_string(data['nsdname'])
                raw_data = data['nsdname'].to_bytes()
            case 5:     # CNAME
                data['cname'] = DomainName.from_string(data['cname'])
                raw_data = data['cname'].to_bytes()
            case 15:    # MX
                data['exchange'] = DomainName.from_string(data['exchange'])
                raw_data = data['preference'].to_bytes(2, 'big') + data['exchange'].to_bytes()
            case 28:    # AAAA
                raw_data = IPv6Address(data['address']).packed
            case _:
                raw_data = b''

        rr = cls(domain_name, rr_type, rr_class, cache_entry['expires'] - int(time.time()), len(raw_data), raw_data)
        rr.data = data
        return rr

    def to_bytes(self, encoded_dnames = None, cur_idx = 0):
        if encoded_dnames == None:
            return self.domain_name.to_bytes() + self.type.to_bytes(2, 'big') + self.cls.to_bytes(2, 'big') + max(0,self.ttl).to_bytes(4, 'big') + self.data_length.to_bytes(2, 'big') + self.raw_data

        rr_bytes = self.domain_name.to_bytes(encoded_dnames, cur_idx)
        rr_bytes += self.type.to_bytes(2, 'big') + self.cls.to_bytes(2, 'big') + max(0,self.ttl).to_bytes(4, 'big')
        cur_idx += len(rr_bytes) + 2

        match self.type:
            case 2:
                data = self.data['nsdname'].to_bytes(encoded_dnames, cur_idx)
            case 5:
                data = self.data['cname'].to_bytes(encoded_dnames, cur_idx)
            case 15:
                data = self.data['preference'].to_bytes(2, 'big') + self.data['exchange'].to_bytes(encoded_dnames, cur_idx)
            case _:
                data = self.raw_data

        rr_bytes += len(data).to_bytes(2, 'big') + data
        return rr_bytes

class Flags:
    def __init__(self, qr = 0, opcode = 0, aa = 0, tc = 0, rd = 0, ra = 0, rcode = 0):
        self.qr = qr
        self.opcode = opcode
        self.aa = aa
        self.tc = tc
        self.rd = rd
        self.ra = ra
        self.rcode = rcode

    @classmethod
    def from_bytes(cls, flag_bytes):
        return cls(
                (flag_bytes[0] & 0x80) >> 7,        # QUERY (0) or RESPONSE (1)
                (flag_bytes[0] & 0x78) >> 3,        # OPCODE
                (flag_bytes[0] & 0x04) >> 2,        # AUTHORITATIVE ANSWER
                (flag_bytes[0] & 0x02) >> 1,        # TRUNCATED
                (flag_bytes[0] & 0x01)     ,        # RECURSION DESIRED
                (flag_bytes[1] & 0x80) >> 2,        # RECURSION AVAILABLE
                (flag_bytes[1] & 0x0f)              # RESPONSE CODE
            )

    def to_bytes(self):
        return int((self.qr << 15) + (self.opcode << 11) + (self.aa << 10) + (self.tc << 9) + (self.rd << 8) + (self.ra << 7) + self.rcode).to_bytes(2, 'big')



        
class Message:
    """ Message class as specified in RFC1035 section 4 """

    @staticmethod
    def __extract_queries(data, cur_idx, qcount):
        queries = []
        while cur_idx < len(data) and len(queries) < qcount:
            dname, cur_idx = DomainName.from_data(data, cur_idx)
            qtype = int.from_bytes(data[cur_idx:cur_idx+2], byteorder='big') 
            qclass = int.from_bytes(data[cur_idx+2:cur_idx+4], byteorder='big') 
            cur_idx += 4
            queries.append(Query(dname, qtype, qclass))
        return (queries, cur_idx)

    @staticmethod
    def __extract_rrs(data, cur_idx, rrcount):
        rrs = []
        while cur_idx < len(data) and len(rrs) < rrcount:
            rr, cur_idx = ResourceRecord.from_data(data, cur_idx)
            rrs.append(rr)
        return (rrs, cur_idx)


    def __init__(self, transaction_id, flags, queries = [], answer_rrs = [], authority_rrs = [], additional_rrs = []):
        self.transaction_id = transaction_id
        self.flags = flags
        self.qdcount = len(queries)
        self.ancount = len(answer_rrs)
        self.nscount = len(authority_rrs)
        self.arcount = len(additional_rrs)

        self.queries = queries
        self.answer_rrs = answer_rrs
        self.authority_rrs = authority_rrs
        self.additional_rrs = additional_rrs
            
    @classmethod
    def from_bytes(cls, data):
        transaction_id = int.from_bytes(data[:2], 'big')
        flags = Flags.from_bytes(data[2:4])
        qdcount = int.from_bytes(data[4:6], 'big')
        ancount = int.from_bytes(data[6:8], 'big')
        nscount = int.from_bytes(data[8:10], 'big')
        arcount = int.from_bytes(data[10:12], 'big')

        cur_idx = 12
        queries, cur_idx = Message.__extract_queries(data, cur_idx, qdcount)
        answer_rrs, cur_idx = Message.__extract_rrs(data, cur_idx, ancount)
        authority_rrs, cur_idx = Message.__extract_rrs(data, cur_idx, nscount)
        additional_rrs, cur_idx = Message.__extract_rrs(data, cur_idx, arcount)

        msg = Message(transaction_id, flags, queries, answer_rrs, authority_rrs, additional_rrs)

        return msg

    def to_bytes(self):
        self.ancount = len(self.answer_rrs)
        self.nscount = len(self.authority_rrs)
        self.arcount = len(self.additional_rrs)
        msg_bytes = (self.transaction_id.to_bytes(2, 'big') + 
                     self.flags.to_bytes() +
                     self.qdcount.to_bytes(2, 'big') +
                     self.ancount.to_bytes(2, 'big') +
                     self.nscount.to_bytes(2, 'big') +
                     self.arcount.to_bytes(2, 'big'))

        encoded_dnames = {}

        for entry in self.queries + self.all_rrs():
            cur_idx = len(msg_bytes)
            msg_bytes += entry.to_bytes(encoded_dnames, cur_idx)

        if len(msg_bytes) > 512:
            self.flags.tc = 1
            msg_bytes[2:4] = self.flags.to_bytes()

        return msg_bytes

    def all_rrs(self):
        return self.answer_rrs + self.authority_rrs + self.additional_rrs
