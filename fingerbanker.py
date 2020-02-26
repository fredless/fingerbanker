#!/usr/bin/env python3
"""
Small script that watches DHCP traffic and compares it to known ethers.  New ethers are
fingerprinted and logged.  Intended to assist in populating /etc/ethers files used by L2 OpenWRT APs
"""

import json

import datetime
import requests
import urllib3
from scapy.all import sniff, DHCP, Ether

CURRENT_TIME = datetime.datetime.now

INTERFACE = "eth0"
FINGERBANK_URL = 'https://api.fingerbank.org/api/v2/combinations/interrogate'
API_KEY = "<Insert your key here>"
PARAMS = {'key': API_KEY}
ETHERS_FILE = './ethers'
ETHERS_HINTS = './ethers_hints'
HEADERS = {'Content-Type': 'application/json'}

def log_fingerbank_error(error, response):
    """Log message for troubleshooting (this never seems to hit?)"""
    print(f' HTTP error: {error}')
    responses = {
        404: "No device was found the the specified combination",
        502: "No API backend was able to process the request.",
        429: "The amount of requests per minute has been exceeded.",
        403: "This request is forbidden. Your account may have been blocked.",
        401: "This request is unauthorized. Either your key is invalid or wasn't specified."
    }
    print(responses.get(response.status_code, "Fingerbank API returned some unknown error"))
    return

def get_option(dhcp_options, key):
    """return single DHCP option"""
    must_decode = ['hostname', 'domain', 'vendor_class_id']
    try:
        for i in dhcp_options:
            if i[0] == key:
                # If DHCP Server Returned multiple name servers
                # return all as comma seperated string.
                if key == 'name_server' and len(i) > 2:
                    return ",".join(i[1:])
                # domain and hostname are binary strings,
                # decode to unicode string before returning
                elif key in must_decode:
                    return i[1].decode()
                else:
                    return i[1]
    except:
        pass

def profile_device(dhcp_fingerprint, macaddr, vendor_class_id):
    """send DHCP fingerprint to fingerbank for an opinion"""
    data = {}
    try:
        data['dhcp_fingerprint'] = ','.join(map(str, dhcp_fingerprint))
    except TypeError:
        pass
    data['mac'] = macaddr
    data['vendor_class_id'] = vendor_class_id

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        response = requests.get(FINGERBANK_URL, headers=HEADERS, params=PARAMS,
                                data=json.dumps(data))
    except requests.exceptions.HTTPError as error:
        log_fingerbank_error(error, response)
        return "Fingerprint error"

    # If score is less than 40, there is very little confidence on the returned profile.
    if response.json()['score'] < 40:
        scorenote = "Low confidence fingerprint"
    else:
        scorenote = "High confidence fingerprint"

    return ' '.join([response.json()['device_name'], response.json()['version'], scorenote])

def update_hints_file(mac, hostname, ip_address, profile):
    """write a new ethers hint"""
    timestamp = str(CURRENT_TIME())
    with open(ETHERS_HINTS, 'a+') as hints_file:
        hints_file.write(' '.join([mac, hostname, ip_address, profile, timestamp])+'\n')


def handle_dhcp_packet(packet):
    """parse DHCP packet and determine whether to take action"""
    if DHCP in packet:
        mac = packet[Ether].src
        requested_addr = get_option(packet[DHCP].options, 'requested_addr')
        hostname = get_option(packet[DHCP].options, 'hostname')
        param_req_list = get_option(packet[DHCP].options, 'param_req_list')
        vendor_class_id = get_option(packet[DHCP].options, 'vendor_class_id')

        device_profile = profile_device(param_req_list, mac, vendor_class_id)

        if mac not in ethers:
            ethers.append(mac)
            update_hints_file(mac, hostname, requested_addr, device_profile)
    return

with open(ETHERS_FILE) as ethers_file:
    ethers = [line.strip().split()[0] for line in ethers_file]

sniff(iface=INTERFACE, filter='udp and (port 67 or 68)', prn=handle_dhcp_packet, store=0)
