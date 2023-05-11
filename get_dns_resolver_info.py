#!/usr/bin/env python

import platform
import socket
import subprocess
import requests
import dns
import time
from ipaddress import ip_address, IPv4Address

def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True


def get_unix_dns_ips():
    dns_ips = []

    with open('/etc/resolv.conf') as fp:
        for cnt, line in enumerate(fp):
            columns = line.split()
            if columns[0] == 'nameserver':
                ip = columns[1:][0]
                if is_valid_ipv4_address(ip):
                    dns_ips.append(ip)

    return dns_ips


def get_windows_dns_ips():
    output = subprocess.check_output(["ipconfig", "-all"])
    ipconfig_all_list = output.split('\n')

    dns_ips = []
    for i in range(0, len(ipconfig_all_list)):
        if "DNS Servers" in ipconfig_all_list[i]:
            # get the first dns server ip
            first_ip = ipconfig_all_list[i].split(":")[1].strip()
            if not is_valid_ipv4_address(first_ip):
                continue
            dns_ips.append(first_ip)
            # get all other dns server ips if they exist
            k = i+1
            while k < len(ipconfig_all_list) and ":" not in ipconfig_all_list[k]:
                ip = ipconfig_all_list[k].strip()
                if is_valid_ipv4_address(ip):
                    dns_ips.append(ip)
                k += 1
            # at this point we're done
            break
    return dns_ips


def validIPAddress(IP: str) -> str:
    try:
        return "v4" if type(ip_address(IP)) is IPv4Address else "v6"
    except ValueError:
        return "Invalid"

def get_frontend_resolver_ip(platform):
    dns_ips = []

    if platform == 'Windows':
        dns_ips = get_windows_dns_ips()
    elif platform == 'Darwin':
        dns_ips = get_unix_dns_ips()
    elif platform == 'Linux':
        dns_ips = get_unix_dns_ips()
    else:
        print("unsupported platform: {0}".format(platform.system()))
    return dns_ips[0]
    
def do_experiment(platform):
    client_ip = requests.get('https://api.ipify.org').content.decode('utf8')
    frontend_resolver_ip = get_frontend_resolver_ip(platform)
    version = validIPAddress(frontend_resolver_ip)
    timestamp = str(int(time.time()))
    experiment_id = "$".join([timestamp, client_ip]).replace(".", "-")
    url = "zzz".join([timestamp, frontend_resolver_ip + version, client_ip]).replace(".", "-") + ".tpr.ana-aqualab.cs.northwestern.edu"
    path = "/get-experiment-results/" + experiment_id
    request_url = "https://" + url  + path
    response = requests.get(request_url)
    if response.status_code == 200:
        # do something with experiment code
        print("Experiment ID: " + experiment_id)
    else:
        # use error as the experiment id
        reason = response.reason
        print("Experiment ID: " + reason)

def main():
    do_experiment(platform.system())

if __name__ == "__main__":
    main()