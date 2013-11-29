# A plugind for Bywaf
# This plugin gets all allow methods from a web server

import httplib

print('loaded http_methods')

#dictionary

options = {

    # <name>   <value>    <default value>    <required>    <description>
    'TARGET_HOST': ('', '', 'Yes', 'Target host on which to get allowed methods'),
    # bywaf options
    'USE_HOSTDB': ('', 'yes', 'yes', 'Use the HostDB to store information about hosts'),
}

""" setting TARGET_HOST """


def set_TARGET_HOST(new_value):
    print('TARGET_HOST= "{}"'.format(new_value))
    # retrieve the option (it's a tuple)
    _value, _defaultvalue, _required, _descr = options['TARGET_HOST']
    options['TARGET_HOST'] = new_value, _defaultvalue, _required, _descr


def do_methods(line):
    """get allowed methods"""
    Aurl = line
    if not line:
        Aurl = options['TARGET_HOST']

    conn = httplib.HTTPConnection(Aurl)
    conn.request('OPTIONS', '/')
    response = conn.getresponse()
    print response.getheader('allow')
