# DNS-Resolver
Implementation of a recusive DNS resolver in Python.

Lightweight DNS resolver implementation written in Python. It allows you to resolve various types of DNS records, including A, AAAA, CNAME, MX, NS, PTR, SOA, and TXT records. Additionally, it provides functionality to perform DNS lookups similar to tools like dig or nslookup. It can be used as the systems main DNS resolver.

# Installation

clone the repository and run the following command in the root directory:

```bash sudo python3 dns.py ```

this will start up the dns resolver on port 53.

# Usage

The DNS resolver can be used to resolve DNS records and perform DNS lookups. The DNS resolver can be used as a standalone application. The DNS resolver can also be used as the systems main DNS resolver. As a standalone application the DNS resolver can be querried using dig or nslookup. As the systems main DNS resolver the DNS resolver can be querried using any web browser that uses the systems DNS resolver.

Using dig or nslookup to perform DNS lookups using the DNS resolver:

```bash dig @localhost -p 53 google.com A ```

```bash nslookup -port=53 google.com localhost```

After each querry the result will be saved in the dns_cache.json file. The cache can be cleared by deleting the dns_cache.json file.
