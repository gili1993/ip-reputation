"""
Python CLI for IP reputation analysis.
Using the VirusTotal API and the Neutrino API.
"""

import random
import re
import argparse
import requests
import shutil

VT_API_KEY = 'XXXXXXXXXXXXXX'
NEUTRINO_API_KEY = 'XXXXXXXXXXXXXX'
NEUTRINO_USER_ID = 'XXXXXXXXXXXXXX'
IP_REGEX = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"

def validate_ip_address(address):
    """
    Validate an IP address
    """
    if re.match(IP_REGEX, address):
        return address
    raise argparse.ArgumentTypeError('invalid value for IP argument (src or target)')


def query_vt(ip) -> dict:
    """
    Query VirusTotal for the given IP address.
    """
    try:
        url = 'https://www.virustotal.com/api/v3/ip_addresses/' + ip
        headers = {'x-apikey': VT_API_KEY}
        response = requests.get(url, headers=headers)
        return response.json()['data']['attributes']
    except Exception as e:
        print("Error: VirusTotal Exception. Try again later "+e)


def query_neutrino(ip):
    """
    Query Neutrino for the given IP address.
    """
    url = 'https://neutrinoapi.net/ip-info'
    params = {'user-id': NEUTRINO_USER_ID, 'api-key': NEUTRINO_API_KEY, 'host': ip}
    response = requests.get(url, params=params)
    data = response.json()
    if data['api-error']:
        return None
    return data


def calc_rep_score_neutrino(neutrino_response) -> int:
    """
    calculate the reputation score for a given Neutrino response
    based on the Neutrino API documentation.
    The score is the number of DNSBL's where the IP is blacklisted up to 10. (1 - 10)
    """
    blacklist_score = neutrino_response['list-count']
    if blacklist_score > 10:
        return 10
    else:
        return blacklist_score


def calc_rep_score_vt(vt_response) -> float:
    """
    Calculate the reputation score for a given VirusTotal response.
    The score is the weighted average of the DNSBL response scores.
    Weights are 0-4 - harmless, 5-7 - suspicious, 8-10 - malicious.
    """
    score = 0
    # don't count the undetected or timeout responses
    relevant_results_amount = len(vt_response['last_analysis_results']) - \
                              vt_response['last_analysis_stats']['undetected'] - \
                              vt_response['last_analysis_stats']['timeout']
    # average the reputation scores (0-10)
    score += random.randrange(0, 5) * vt_response['last_analysis_stats']["harmless"]
    score += random.randrange(5, 8) * vt_response['last_analysis_stats']["suspicious"]
    score += random.randrange(8, 11) * vt_response['last_analysis_stats']["malicious"]
    return score / relevant_results_amount


def main():
    """
    Main function.
    """
    # Banner
    t_w = shutil.get_terminal_size().columns
    print("======================".center(t_w))
    print("IP Reputation Analyzer".center(t_w).title())
    print("======================".center(t_w))
    print('''A simple tool that displays the reputation of an IP address.
            Score:
            [0 - 4] Clean
            [5 - 7] suspicious
            [8 - 10] malicious
            ''')
    # get IP address from the user
    ip_address = str(input("Enter IP address: "))
    validate_ip_address(ip_address)
    # Query VirusTotal and Neutrino
    vt_response = query_vt(ip_address)
    neutrino_response = query_neutrino(ip_address)
    # calculate average
    acc_score = 0
    amount = 0
    if vt_response:
        acc_score += calc_rep_score_vt(vt_response)
        amount += 1
    if neutrino_response:
        acc_score += calc_rep_score_neutrino(neutrino_response)
        amount += 1
    if amount == 0:
        print(f"No reputation data available. IP: {ip_address}")
    else:
        acc_score = round(acc_score / amount)
        print(f"reputation score for {ip_address}: {acc_score}. ", end="")
    if 0 <= acc_score <= 4:
        print("The IP is clean.")
    elif 5 <= acc_score <= 7:
        print("The IP is suspicious.")
    elif 8 <= acc_score <= 10:
        print("The IP is malicious.")


if __name__ == '__main__':
    main()
