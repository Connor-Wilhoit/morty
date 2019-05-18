#!/usr/bin/env python3
import re
import sys
import socket
import dns.query
import dns.message
import dns.resolver
import dns.reversename
from dns.dnssec import algorithm_to_text
from dns.zone import *
from time import sleep
from time import time
import argparse
import urllib

DNS_PORT_NUMBER = 53
DNS_QUERY_TIMEOUT = 4.0

class DnsHelper:
    def __init__(self, domain, ns_server=None, request_timeout=3.0, proto="tcp"):
        self._domain = domain
        self._proto = proto
        if ns_server:
            self._res = dns.resolver.Resolver(configure=False)
            self._res.nameservers = [ns_server]
        else:
            self._res = dns.resolver.Resolver(configure=True)
        # Set timing
        self._res.timeout = request_timeout
        self._res.lifetime = request_timeout

    def check_tcp_dns(self, address):
        """
        Function to check if a server is listening at port 53 TCP. This will aid
        in IDS/IPS detection since a AXFR will not be tried if port 53 is found to
        be closed.
        """
        s = socket.socket()

        s.settimeout(DNS_QUERY_TIMEOUT)
        try:
            s.connect((address, DNS_PORT_NUMBER))
        except Exception:
            return False
        else:
            return True

    def resolve(self, target, type, ns=None):
        """
        Function for performing general resolution types returning the RDATA
        """
        if ns:
            res = dns.resolver.Resolver(configure=False, )
            res.nameservers = [ns]
        else:
            res = dns.resolver.Resolver(configure=True)

        tcp = True if self._proto == "tcp" else False
        answers = res.query(target, type, tcp=tcp)
        return answers

    def query(self, q, where, timeout=None, port=53, af=None, source=None, source_port=0, one_rr_per_rrset=False):
        if self._proto == "tcp":
            return dns.query.tcp(q, where, timeout, port, af, source, source_port, one_rr_per_rrset)
        else:
            return dns.query.udp(q, where, timeout, port, af, source, source_port, False, one_rr_per_rrset)

    def get_a(self, host_trg):
        """
        Function for resolving the A Record for a given host. Returns an Array of
        the IP Address it resolves to. It will also return CNAME data.
        """
        address = []
        tcp = True if self._proto == "tcp" else False
        try:
            ipv4_answers = self._res.query(host_trg, 'A', tcp=tcp)
            for ardata in ipv4_answers.response.answer:
                for rdata in ardata:
                    if rdata.rdtype == 5:
                        if rdata.target.to_text().endswith('.'):
                            address.append(["CNAME", host_trg, rdata.target.to_text()[:-1]])
                            host_trg = rdata.target.to_text()[:-1]
                        else:
                            address.append(["CNAME", host_trg, rdata.target.to_text()])
                            host_trg = rdata.target.to_text()
                    else:
                        address.append(["A", host_trg, rdata.address])
        except:
            return address
        return address

    def morty_c137(self, host):
        """
		Your standard A-Record DNS lookup ;)

        Function for resolving the A Record for a given host. Returns an Array of
        the IP Address it resolves to. It will also return CNAME data.
        """
        address = []
        tcp = True if self._proto == "tcp" else False
        try:
            ipv4_answers = self._res.query(host, 'A', tcp=tcp)
            for ardata in ipv4_answers.response.answer:
                for rdata in ardata:
                    if rdata.rdtype == 5:
                        if rdata.target.to_text().endswith('.'):
                            address.append(["CNAME", host, rdata.target.to_text()[:-1]])
                            host = rdata.target.to_text()[:-1]
                        else:
                            address.append(["CNAME", host, rdata.target.to_text()])
                            host = rdata.target.to_text()
                    else:
                        address.append(["A", host, rdata.address])
        except:
            return address
        return address

    def get_aaaa(self, host_trg):
        """
        Function for resolving the AAAA Record for a given host. Returns an Array of
        the IP Address it resolves to. It will also return CNAME data.
        """
        address = []
        tcp = True if self._proto == "tcp" else False
        try:
            ipv6_answers = self._res.query(host_trg, 'AAAA', tcp=tcp)
            for ardata in ipv6_answers.response.answer:
                for rdata in ardata:
                    if rdata.rdtype == 5:
                        if rdata.target.to_text().endswith('.'):
                            address.append(["CNAME", host_trg, rdata.target.to_text()[:-1]])
                            host_trg = rdata.target.to_text()[:-1]
                        else:
                            address.append(["CNAME", host_trg, rdata.target.to_text()])
                            host_trg = rdata.target.to_text()
                    else:
                        address.append(["AAAA", host_trg, rdata.address])
        except:
            return address
        return address

    def get_ip(self, hostname):
        """
        Function resolves a host name to its given A and/or AAAA record. Returns Array
        of found hosts and IPv4 or IPv6 Address.
        """
        found_ip_add = []
        found_ip_add.extend(self.get_a(hostname))
        found_ip_add.extend(self.get_aaaa(hostname))

        return found_ip_add

    def get_mx(self):
        """
        Function for MX Record resolving. Returns all MX records. Returns also the IP
        address of the host both in IPv4 and IPv6. Returns an Array
        """
        mx_records = []
        tcp = True if self._proto == "tcp" else False
        answers = self._res.query(self._domain, 'MX', tcp=tcp)
        for rdata in answers:
            try:
                name = rdata.exchange.to_text()
                ipv4_answers = self._res.query(name, 'A', tcp=tcp)
                for ardata in ipv4_answers:
                    if name.endswith('.'):
                        mx_records.append(['MX', name[:-1], ardata.address,
                                          rdata.preference])
                    else:
                        mx_records.append(['MX', name, ardata.address,
                                          rdata.preference])
            except:
                pass
        try:
            for rdata in answers:
                name = rdata.exchange.to_text()
                ipv6_answers = self._res.query(name, 'AAAA', tcp=tcp)
                for ardata in ipv6_answers:
                    if name.endswith('.'):
                        mx_records.append(['MX', name[:-1], ardata.address,
                                          rdata.preference])
                    else:
                        mx_records.append(['MX', name, ardata.address,
                                          rdata.preference])
            return mx_records
        except:
            return mx_records

    def get_ns(self):
        """
        Function for NS Record resolving. Returns all NS records. Returns also the IP
        address of the host both in IPv4 and IPv6. Returns an Array.
        """
        name_servers = []
        tcp = True if self._proto == "tcp" else False
        answer = self._res.query(self._domain, 'NS', tcp=tcp)
        if answer is not None:
            for aa in answer:
                name = aa.target.to_text()[:-1]
                ip_addrs = self.get_ip(name)
                for addresses in ip_addrs:
                    if re.search(r'^A', addresses[0]):
                        name_servers.append(['NS', name, addresses[2]])
        return name_servers

    def get_soa(self):
        """
        Function for SOA Record resolving. Returns all SOA records. Returns also the IP
        address of the host both in IPv4 and IPv6. Returns an Array.
        """
        soa_records = []
        tcp = True if self._proto == "tcp" else False
        querymsg = dns.message.make_query(self._domain, dns.rdatatype.SOA)
        
        try:
            if tcp:
                response = dns.query.tcp(querymsg, self._res.nameservers[0], self._res.timeout)
            else:
                response = dns.query.udp(querymsg, self._res.nameservers[0], self._res.timeout)
                
            if len(response.answer) > 0:
                answers = response.answer
            elif len(response.authority) > 0:
                answers = response.authority
            for rdata in answers:
                # A zone only has one SOA record so we select the first.
                name = rdata[0].mname.to_text()
                ipv4_answers = self._res.query(name, 'A', tcp=tcp)
                for ardata in ipv4_answers:
                    if name.endswith('.'):
                        soa_records.append(['SOA', name[:-1], ardata.address])
                    else:
                        soa_records.append(['SOA', name, ardata.address])
        except (dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoAnswer, socket.error, dns.query.BadResponse):
            print('Error while resolving SOA record.')
            return soa_records

        try:
            for rdata in answers:
                name = rdata.mname.to_text()
                ipv4_answers = self._res.query(name, 'AAAA', tcp=tcp)
                for ardata in ipv4_answers:
                    if name.endswith('.'):
                        soa_records.append(['SOA', name[:-1], ardata.address])
                    else:
                        soa_records.append(['SOA', name, ardata.address])

            return soa_records
        except:
            return soa_records

    def get_spf(self):
        """
        Function for SPF Record resolving returns the string with the SPF definition.
        Prints the string for the SPF Record and Returns the string
        """
        spf_record = []
        tcp = True if self._proto == "tcp" else False
        try:
            answers = self._res.query(self._domain, 'SPF', tcp=tcp)
            for rdata in answers:
                name = ''.join(rdata.strings)
                spf_record.append(['SPF', name])
        except:
            return None

        return spf_record

    def get_txt(self, target=None):
        """
        Function for TXT Record resolving returns the string.
        """
        txt_record = []
        tcp = True if self._proto == "tcp" else False
        if target is None:
            target = self._domain
        try:
            answers = self._res.query(target, 'TXT', tcp=tcp)
            for rdata in answers:
                string = "".join(rdata.strings)
                txt_record.append(['TXT', target, string])
        except:
            return []

        return txt_record

    def get_ptr(self, ipaddress):
        """
        Function for resolving PTR Record given it's IPv4 or IPv6 Address.
        """
        found_ptr = []
        tcp = True if self._proto == "tcp" else False
        n = dns.reversename.from_address(ipaddress)
        try:
            answers = self._res.query(n, 'PTR', tcp=tcp)
            for a in answers:
                if a.target.to_text().endswith('.'):
                    found_ptr.append(['PTR', a.target.to_text()[:-1], ipaddress])
                else:
                    found_ptr.append(['PTR', a.target.to_text(), ipaddress])
            return found_ptr
        except:
            return None

    def get_srv(self, host):
        """
        Function for resolving SRV Records.
        """
        record = []
        tcp = True if self._proto == "tcp" else False
        try:
            answers = self._res.query(host, 'SRV', tcp=tcp)
            for a in answers:
                if a.target.to_text().endswith('.'):
                    target = a.target.to_text()[:-1]
                else:
                    target = a.target.to_text()

                ips = self.get_ip(target)

                if ips:
                    for ip in ips:
                        if re.search('(^A|AAAA)', ip[0]):
                            record.append(['SRV', host, target, ip[2],
                                          str(a.port), str(a.weight)])

                else:
                    record.append(['SRV', host, target, "no_ip",
                                  str(a.port), str(a.weight)])
        except:
            return record
        return record

    def get_nsec(self, host):
        """
        Function for querying for a NSEC record and retrieving the rdata object.
        This function is used mostly for performing a Zone Walk against a zone.
        """
        tcp = True if self._proto == "tcp" else False
        answer = self._res.query(host, 'NSEC', tcp=tcp)
        return answer

    def from_wire(self, xfr, zone_factory=Zone, relativize=True):
        """
        Method for turning returned data from a DNS AXFR in to RRSET, this method will not perform a
        check origin on the zone data as the method included with dnspython
        """
        z = None
        for r in xfr:
            if z is None:
                if relativize:
                    origin = r.origin
                else:
                    origin = r.answer[0].name
                rdclass = r.answer[0].rdclass
                z = zone_factory(origin, rdclass, relativize=relativize)
            for rrset in r.answer:
                znode = z.nodes.get(rrset.name)
                if not znode:
                    znode = z.node_factory()
                    z.nodes[rrset.name] = znode
                zrds = znode.find_rdataset(rrset.rdclass, rrset.rdtype,
                                           rrset.covers, True)
                zrds.update_ttl(rrset.ttl)
                for rd in rrset:
                    rd.choose_relativity(z.origin, relativize)
                    zrds.add(rd)

        return z

    def init_morty(self, domain):
        print("\n\033[91m##########################################################")
        print("#                                                        #")
        print("#                                                        #")
        print("#\033[94m                  Wubbalubbadubdub!                     \033[91m#")
        print("#                                                        #")
        print("#                                                        #")
        print("########################################################## \n \033[0m")
        print("""Options:\n1) A\n2) NS\n3) MX\n4) SOA\n5) SPF\n6) PTR\n7) TXT\n""")
        options = int(input("Select what information you're looking for: "))

        if options not in range(1,8):
            print("Nice choice, Commander-in-Queef\n")
            return
		
        if options == 1:
            try:
                A = resolver.morty_c137(domain)
                ip = A[0][2]
                print("IPv4 Address of {} --> {}".format(domain, ip))
            except:
                print("I'm Mr. Meeseeks!  Look at me!")
                print("Look @me! - no A record Jerry....\n")

        elif options == 2:
            NS = resolver.get_ns()
            print(NS)

        elif options == 3:
            try:
                MX = resolver.get_mx()
                print(MX)
            except:
                print("\nAww Geez Maaannn....\n")
                print("MX records cost 25 schmeckles, and you have insufficient funds\n")

        elif options == 4:
            try:
                SOA = resolver.get_soa()
                print(SOA)
            except:
                print("\nAww Geez Maaannn....\n")
                print("Looks like you are SOL on finding that SOA record\n")

        elif options == 5:
            try:
                SPF = resolver.get_spf()
                if SPF is not None:
                    print(SPF)
                else:
                    print("\nAww Geez Maaannn....\n")
                    print("\nYour SPF record is empty....\n")
            except:
                print("Aww Geez Maaannn....\n")
                print("Rick c137 must have placed your SPF record in another dimension....\n")

        elif options == 6:
            try:
                PTR = resolver.get_ptr()
                if PTR is not None:
                    print(PTR)
                else:
                    print("\nAww Geez Maaannn....\n")
                    print("\nThat's not an Amphetatron-Friendly place...\n")
                    print("\nYour PTR record is empty....\n")
            except:
                print("\nAww Geez Maaannn....\n")
                print("\nNo PTR record must mean that that's not an Amphetatron-Friendly place...\n")

        elif options == 7:
            try:
                TXT = resolver.get_txt()
                if TXT is not None:
                    print("Heeerreeee ya go w/that TXT record:\n")
                    print(TXT)
                else:
                    print("\nAww Geez Maann....\n")
                    print("\nYour TXT record is not found....\n")
            except:
                print("\nAwww Geeeez Maaan....\n")
                print("TXT record must be in another time-space....\n")


def usage():
    print("Usage: $ ./morty.py [domain]\n")
    print("Example: $ ./morty.py waynesplanet.com\n")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        usage()
        sys.exit(11)
    else:
        args = sys.argv[1:]
        domain = args[0]
        resolver = DnsHelper(domain)
        resolver.init_morty(domain)
