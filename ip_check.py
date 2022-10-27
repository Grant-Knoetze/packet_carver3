import re


def is_ip(ip):
    """
    Check IP address to confirm if IPV4
    """
    ipv4 = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    return ipv4.match(ip)

print(is_ip("192.168.2.1"))

