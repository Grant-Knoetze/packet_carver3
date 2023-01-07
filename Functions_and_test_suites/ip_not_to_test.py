#!/usr/env/bin python3

def ips_not_to_test(ip):
    """
    Function that tests to see if ip's are worth testing, ie: not loopback, internal, bogon etc
    """
    # 10.0.0.0 - 10.255.255.255
    if ip[:3] == '10.':
        return True

    # 172.16.0.0 - 172.31.255.255
    if ip[:4] == '172.' and ip[6:7] == '.' and int(ip[4:6]) in range(16, 31, 1):
        return True

    # 192.168.0.0 - 192.168.255.255
    if ip[:8] == '192.168.':
        return True

    # 255.255.255.255
    if ip == '255.255.255.255':
        return True

    # Multicast 224.0.0.0 - 239.255.255.255
    if int(ip[:3]) in range(224, 240, 1):
        return True

    # 0.0.0.0
    if ip == '0.0.0.0':
        return True

    return False


ips_not_to_test("192.168.1.1")
