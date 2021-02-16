def retrieve_vt_analysis_stats(url):
    """
    This returns the last analysis result of the URL from Virustotal.

    :param url: String.
    :return: Dict. Results of the last url analysis.
    """
    # pip install virustotal3(Unofficial).
    import virustotal3.core
    import config

    api_key = config.VT_API_KEY

    try:
        # Data is returned as a dict. We can just iterate through to get the required information.
        # analysis_result = virustotal3.core.URL(api_key).get_network_location(url, 5000)
        analysis_result = virustotal3.core.URL(api_key).info_url(url, 2500)

        mal_result = analysis_result['data']['attributes']['last_analysis_stats']
        # print('Analysis result: {} malicious, {} harmless, {} sus, {} timeout, {} undetected'.format(x['malicious'], x['harmless'], x['suspicious'], x['timeout'], x['undetected']))
        return mal_result
    except:
        return None


def check_domain_punycode(url):
    """
    This checks if the string "xn--" inside a string which is "required" if the url/domain is in punycode.
    Alternatively, understand that unicode will need to be translated to punycode for urls.

    :param url: String.
    :return: Boolean. True if URL is in unicode(punycode-able).
    """
    # url='München.com'
    try:
        domain_idna = url.encode('idna')
        # print(domain_idna)
        if b'xn--' in domain_idna:
            # print('True')
            return True
        else:
            # print('False')
            return False
    except:
        return None


def download_blocklist():
    """
    Downloads then sorts the malware domain blocklist. This will be saved at an azure function level.

    :return: None
    """
    import requests
    import os
    # print('Starting download of malware domain list...')
    url = 'https://zonefiles.io/f/compromised/domains/full/compromised_domains_full.txt'

    try:
        r = requests.get(url)

        filename = url.split('/')[-1]  # this will take only -1 split part of the url
        domains_sorted = [domain + '\n' for domain in r.text.split('\n')[1:-2]] # Removes the 1st header line and last empty line.
        domains_sorted.sort()   # Sorts the list alphabetically(linear)

        filepath = os.path.join(os.path.dirname(__file__), filename)
        # Write to file(overwrite).
        with open(filepath, 'w') as output_file:
            output_file.writelines(domains_sorted)
    except:
        return None


def check_url_in_blocklist(url):
    """
    Checks if a url is in the blocklist specified. Blocklist must first be downloaded.

    :param url: String.
    :return: Boolean. True if url is in blocklist.
    """
    import mmap
    import os
    import re
    filepath = os.path.join(os.path.dirname(__file__), 'compromised_domains_full.txt')

    # Checks if file is in, else download blocklist first.
    if os.path.isfile(filepath) == False:
        download_blocklist()

    # Gets only the domain. Strips off "http(s)" and the trailing characters.
    domain_regex = r'^(?:http[s]?\:\/\/)?(?P<domain>[^\/\s]+)'
    domain = re.match(pattern=domain_regex, string=url).group('domain')

    try:
        with open(filepath, 'rb') as file:
            # Maps the file to memory(in theory faster execution time.
            mmap = mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ)

            # "-1" is returned when item cannot be found.
            # Therefore, return True when URL is in blocklist.
            if mmap.find(domain.encode(), 0, -1) != -1:
                # print('URL found.')
                return True
            else:
                # print('URL NOT found.')
                return False
    except:
        return None


def retrieve_whois(url, xml=None):
    """
    Checks the age of the domain(days). A low age of registration could mean a scam site.

    :param age: String.
    :return: Boolean. True if website is relatively new(<365 days).
    """
    import requests
    import lxml
    from lxml import etree, objectify
    from xml.dom import minidom
    import config

    def pretty_print(elem):
        """
        Prints the entire document tree in a nice indented manner(XML headers incl).
        """
        xml = etree.tostring(elem)
        pretty = minidom.parseString(xml).toprettyxml(indent='  ')
        print(pretty)
    
    def check_age(age):
        """
        Checks the age of the domain(days).

        :param age: String.
        :return: Boolean. True if website is relatively new(<365 days).
        """
        try:
            age = int(age)
            if age < 365:
                return True
            else:
                return False
        except:
            print('Error converting age of domain.')

    # Returns as a XML text.
    whois_server_url = 'https://www.whoisxmlapi.com/whoisserver/WhoisService'
    api_key = config.WHOIS_API_KEY
    data = {
        'apiKey': api_key,
        'domainName': url
    }
    
    try:
        xml = requests.post(whois_server_url, data).text
        root = lxml.objectify.fromstring(xml.encode("utf-8"))

        return check_age(root.estimatedDomainAge.text)
    except:
        return None


def req_vt_whois_maldom_puny(url):
    """
    Calls all the corresponding functions to return a dictionary of the detections.
    - Virustotal
    - Whois
    - Malicious site blocklist
    - Punycode

    :param url: String.
    :return: Dict. Dictionary of all results returned. 
    """
    results = {}
    try:
        # MalDomain.py
        results['maldomain_result'] = check_url_in_blocklist(url)
        # WHOIS.py
        results['whois_result'] = retrieve_whois(url)
        # VT.py
        # vt_results = VT.view_vt(url)
        # if int(vt_results['malicious']) > 5:
        #     results['vt_result'] = True
        # else:
        #     results['vt_result'] = False
        results['vt_result'] = retrieve_vt_analysis_stats(url)
        # PunycodeDet.py
        results['puny_result'] = check_domain_punycode(url)

        # Returns dictionary of all results.
        return results
    except:
        return None