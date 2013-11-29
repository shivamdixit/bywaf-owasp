# A plugind for Bywaf
# This plugin gets all allow methods from a web server

import httplib

print('loaded http_methods')

#dictionary

options = {

    # <name>   <value>    <default value>    <required>    <description>
    'TARGET_HOST': ('', '', 'yes', 'Target host on which to get allowed methods'),
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
    if line is None:
        if options['TARGET_HOST'][0]:
            Aurl = str (options['TARGET_HOST'][0])
        else:
            Aurl = str (options['TARGET_HOST'][1])

    if not Aurl:
        print("methods: must specify a domain on the command line or in 'TARGET_HOST' option")
        return

    conn = httplib.HTTPConnection(Aurl)
    conn.request('OPTIONS', '/')
    response = conn.getresponse()
    print response.getheader('allow')
