import re


def is_ip(ip):
    """
    Check IP address to confirm if IPV4
    """
    ipv4 = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    return ipv4.match(ip)


is_ip("192.168.10.1")
