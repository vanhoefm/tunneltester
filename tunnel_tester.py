#!/usr/bin/env python3
# vim: set ts=4 sw=4 sts=4 expandtab:
from scapy.all import *
import sys, argparse, functools
import ipaddress

def test_vulnerable(testname, p, filter, validate):
    global vulnerable
    vulnerable = False

    # Add tag to uniquely detect the response and thereby avoid false positives.
    # To detect TTL Expired in IPv4, encode the tags in the IP and ICMP header, because
    # there is no guarantee the full packet will be included in the ICMP error message.
    tag1, tag2 = random.randint(0, 2**16 - 1), random.randint(0, 2**16 - 1)
    tag_pad = b"AAAA" + struct.pack(">II", tag1, tag2)
    if IP in p.payload:
        p.payload[IP].id = tag1
        p.payload[IP][ICMP].id = tag2

    s = conf.L2socket(conf.iface, filter=filter)
    send(p/Raw(tag_pad), verbose=False)

    print(f"Testing {testname}:", end=" ")
    sniff(prn=functools.partial(validate, tag1=tag1, tag2=tag2), timeout=args.timeout, opened_socket=s)
    print("VULNERABLE" if vulnerable else "SAFE")
    s.close()


def validate_ipv4(p, tag1, tag2):
    global vulnerable
    tag_pad = b"AAAA" + struct.pack(">II", tag1, tag2)
    # Note that the src address is already checked by the BFP filter on the socket
    if IP in p and p[IP].payload.name == "ICMP" and p[ICMP].type == 0 and p[ICMP].code == 0 and tag_pad in raw(p):
        vulnerable = True

def validate_ttl_ipv4(p, tag1, tag2, inner_us_priv, inner_ttl):
    global vulnerable
    # For IPv4, any NAT in between might rewrite addresses in the ICMP error messages as well.
    # It's hard to predict the exact NAT behaviour. So we detect replies purely based on the tags.
    if (IP in p and p[IP].payload.name == "ICMP" and p[ICMP].type == 11 and p[ICMP].code == 0
            and p[IP][ICMP][IPerror].id == tag1 and p[IP][ICMP][IPerror][ICMPerror].id == tag2):
        vulnerable = True


def validate_ipv6(p, tag1, tag2):
    global vulnerable
    tag_pad = b"AAAA" + struct.pack(">II", tag1, tag2)
    # Note that the src address is already checked by the BFP filter on the socket
    if IPv6 in p and p[IPv6].payload.name == "ICMPv6 Echo Reply" and tag_pad in raw(p):
        vulnerable = True

def validate_ttl_ipv6(p, tag1, tag2, inner_us_priv, inner_ttl):
    global vulnerable
    if IPv6 in p and p[IPv6].payload.name == "ICMPv6 Time Exceeded" and IPerror6 in p:
        # Need to use ipaddress.ip_address() because function arguments may use 'exploded' from
        # of the IPv6 address while src and dst may use the shorthand with '::' notation.
        src = ipaddress.ip_address(p[IPerror6].src)
        dst = ipaddress.ip_address(p[IPerror6].dst)
        # Tag is not checked because there is no guarantee that it is included
        if src == ipaddress.ip_address(inner_us_priv) and dst == ipaddress.ip_address(inner_ttl):
            vulnerable = True


def gen_probe_ipip(src_outer, dst_outer, src_inner, dst_inner, ping_request=False, ttl_test=False):
    return (IP(src=src_outer, dst=dst_outer) /
            IP(src=src_inner, dst=dst_inner, ttl=1 if ttl_test else 64)/ICMP(type=8 if ping_request else 0, code=0))

def gen_probe_gre(src_outer, dst_outer, src_inner, dst_inner, ping_request=False, ttl_test=False):
    return (IP(src=src_outer, dst=dst_outer) /
            GRE() /
            IP(src=src_inner, dst=dst_inner, ttl=1 if ttl_test else 64)/ICMP(type=8 if ping_request else 0, code=0))

def gen_probe_ip6ip6(src_outer, dst_outer, src_inner, dst_inner, ping_request=False, ttl_test=False):
    return (IPv6(src=src_outer, dst=dst_outer)/
            IPv6(src=src_inner, dst=dst_inner, hlim=0 if ttl_test else 64)/(ICMPv6EchoRequest() if ping_request else ICMPv6EchoReply()))

def gen_probe_gre6(src_outer, dst_outer, src_inner, dst_inner, ping_request=False, ttl_test=False):
    return (IPv6(src=src_outer, dst=dst_outer)/
            GRE()/
            IPv6(src=src_inner, dst=dst_inner, hlim=0 if ttl_test else 64)/(ICMPv6EchoRequest() if ping_request else ICMPv6EchoReply()))

def gen_probe_6in4(src_outer, dst_outer, src_inner, dst_inner, ping_request=False, ttl_test=False):
    return (IP(src=src_outer, dst=dst_outer)/
            IPv6(src=src_inner, dst=dst_inner, hlim=0 if ttl_test else 64)/(ICMPv6EchoRequest() if ping_request else ICMPv6EchoReply()))

def gen_probe_4in6(src_outer, dst_outer, src_inner, dst_inner, ping_request=False, ttl_test=False):
    return (IPv6(src=src_outer, dst=dst_outer)/
            IP(src=src_inner, dst=dst_inner, ttl=1 if ttl_test else 64)/ICMP(type=8 if ping_request else 0, code=0))


class ScanAddresses:
    def __init__(self, my_ip_priv, my_ip_pub, dest_ip, spoof_ip, ttl, inner_us=None, inner_host=None):
        # In in AWS server, the server is assigned a private internal IPv4 that must be used.
        # For servers that are directly assinged a public IPv4, the 'private' IPv4 in this script
        # can simply be set to the public IPv4.
        self.outer_us_priv = my_ip_priv or my_ip_pub
        self.outer_us = my_ip_pub
        self.outer_host = dest_ip

        # When testing 4in6 the inner_host is unknown, which is indicated by the value False. For 6in4 the
        # mapped address can be provided for inner_host. In all other causes, inner_host equals outer_host.
        self.inner_us = self.outer_us if inner_us == None else inner_us
        if inner_host == False:
            self.inner_host = None
        else:
            self.inner_host = self.outer_host if inner_host == None else inner_host

        self.inner_spoof_subnet = None
        self.inner_spoof = spoof_ip
        self.inner_ttl = ttl


def test_protocol(name, addr, construct_probe, validate, validate_ttl):
    # Standard scan, not possible with 6in4 where we don't know the inner IPv6 destination
    if addr.inner_host:
        p = construct_probe(addr.outer_us_priv, addr.outer_host, addr.inner_host, addr.inner_us)
        test_vulnerable(f"{name} Standard", p, "(icmp or icmp6) and src "+addr.inner_host, validate)

    # Subnet spoof scan, not possible with 6in4 where we don't know the inner IPv6 destination
    if addr.inner_spoof_subnet:
        p = construct_probe(addr.outer_us_priv, addr.outer_host, addr.inner_spoof_subnet, addr.inner_us)
        test_vulnerable(f"{name} Standard (subnet spoof)", p, "(icmp or icmp6) and src "+addr.inner_spoof_subnet, validate)

    # Spoof scan is only done when given an explicit IP address to spoof by the user
    if addr.inner_spoof:
        p = construct_probe(addr.outer_us_priv, addr.outer_host, addr.inner_spoof, addr.inner_us)
        test_vulnerable(f"{name} Standard (spoof)", p, "(icmp or icmp6) and src "+addr.inner_spoof, validate)

    if addr.inner_host:
        p = construct_probe(addr.outer_us_priv, addr.outer_host, addr.inner_us, addr.inner_host, ping_request=True)
        test_vulnerable(f"{name} Ping", p, "(icmp or icmp6) and src "+addr.inner_host, validate)

    if addr.inner_ttl:
        p = construct_probe(addr.outer_us_priv, addr.outer_host, addr.inner_us, addr.inner_ttl, ttl_test=True)
        validate_ttl_with_addr = functools.partial(validate_ttl, inner_us_priv=addr.inner_us, inner_ttl=addr.inner_ttl)
        # For 4in6 and 6in4, and TTL test in general, we can't be sure what the src address is. Instead filter on ICMP only.
        test_vulnerable(f"{name} TTL", p, "icmp or icmp6", validate_ttl_with_addr)

    print("")


def get_same_subnet_ipv4(ipaddr):
    # Flip the last bit to stay in the smallest related subnet
    parts = [int(part) for part in ipaddr.split(".")]
    parts[-1] ^= 1

    # But avoid generating possible network or broadcast address
    if parts[-1] == 0 or parts[-1] == 255:
        parts[-1] ^= 2

    return ".".join([str(part) for part in parts])


def get_same_subnet_ipv6(ipaddr):
    try:
        # Parse the address and convert it to its full (expanded) form
        full_address = ipaddress.ip_address(ipaddr).exploded
    except ValueError:
        return "Invalid IPv6 address"
    # Flip the last bit to stay in the smallest related subnet
    parts = full_address.split(":")
    parts[-1] = format(int(parts[-1], 16) ^ 1, 'x')
    return ":".join(parts)


def ipv4_to_ipv6_mapped(ipv4_address):
    octets = ipv4_address.split('.')
    hex_octets = [format(int(octet), '02x') for octet in octets]
    return '::ffff:' + ''.join(hex_octets[0:2]) + ':' + ''.join(hex_octets[2:4])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    # Main functionality
    parser.add_argument("interface", help="Interface to inject and monitor packets on")
    parser.add_argument("-t", "--target", help="Target's IPv4 address")
    parser.add_argument("-t6", "--target6", help="Target's IPv6 address")
    # Advanced functionality
    parser.add_argument("--timeout", default=2, type=float, help="Timeout to wait for replyes (default: 2)")
    parser.add_argument("-p", "--private", help="Private IPv4 address of scanner")
    parser.add_argument("-s", "--spoof", default="212.224.129.90", help="Source IPv4 address to spoof in standard scan")
    parser.add_argument("-r", "--ttl", default="212.224.129.90", help="Destination IPv4 address for TTL Scans")
    parser.add_argument("-P", "--public", help="Override Public IPv4 address of scanner")
    parser.add_argument("-s6", "--spoof6", default="2a02:2c40:0:80::80:15", help="Source IPv6 address to spoof in standard scan")
    parser.add_argument("-r6", "--ttl6", default="2a02:2c40:0:80::80:15", help="Destination IPv6 address for TTL Scans")
    parser.add_argument("-P6", "--public6", help="Override the IPv6 address of scanner")
    args = parser.parse_args()

    # Set interface and get default source IPv4/6 addresses
    conf.iface = args.interface
    if args.public == None:
        args.public = get_if_addr(conf.iface)
    if args.public6 == None:
        args.public6 = get_if_addr6(conf.iface)
    if args.target and args.public == None:
        print(f"ERROR: Cannot test IPv4 host without knowing the IPv4 address of {conf.iface}")
        quit(1)
    if args.target6 and args.public6 == None:
        print(f"ERROR: Cannot test IPv6 host without knowing the IPv6 address of {conf.iface}")
        quit(1)

    addr4 = ScanAddresses(args.private, args.public, args.target, args.spoof, args.ttl)
    addr6 = ScanAddresses(args.public6, args.public6, args.target6, args.spoof6, args.ttl6)

    # Scan an IPv4 host
    if args.target and args.public:
        addr4.inner_spoof_subnet = get_same_subnet_ipv4(addr4.outer_host)
        test_protocol("IPIP", addr4, gen_probe_ipip, validate_ipv4, validate_ttl_ipv4)
        test_protocol("GRE", addr4, gen_probe_gre, validate_ipv4, validate_ttl_ipv4)

    # Scan an IPv6 host
    if args.target6 and args.public6:
        addr6.inner_spoof_subnet = get_same_subnet_ipv6(addr6.outer_host)
        test_protocol("IP6IP6", addr6, gen_probe_ip6ip6, validate_ipv6, validate_ttl_ipv6)
        test_protocol("GRE6", addr6, gen_probe_gre6, validate_ipv6, validate_ttl_ipv6)

    # Scan an IPv4 host with 6in4
    if args.target and args.public6:
        host_6in4 = ipv4_to_ipv6_mapped(args.target)
        addr6in4 = ScanAddresses(args.private, args.public, args.target, args.spoof6, addr6.inner_ttl, inner_us=args.public6, inner_host=host_6in4)
        addr6in4.inner_spoof_subnet = get_same_subnet_ipv6(host_6in4)
        addr6in4.inner_ttl = addr6in4.inner_ttl or args.ttl6
        test_protocol("6in4", addr6in4, gen_probe_6in4, validate_ipv6, validate_ttl_ipv6)

    # Scan an IPv6 host with 4in6
    if args.target6 and args.public:
        addr4in6 = ScanAddresses(args.public6, args.public6, args.target6, args.spoof, addr4.inner_ttl, inner_us=args.public, inner_host=False)
        addr4in6.inner_ttl = addr4in6.inner_ttl or args.ttl
        test_protocol("4in6", addr4in6, gen_probe_4in6, validate_ipv4, validate_ttl_ipv4)

