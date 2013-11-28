########################
#bywaf utility methods, to be loaded on init
########################

import urllib2

def has_ssl(addr):
    
    if('https://' not in addr):
        addr = 'https://'+addr

    try:
        urllib2.urlopen(addr)
        return True
    except urllib2.URLError:
        return False
