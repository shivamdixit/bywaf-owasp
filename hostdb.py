#!/usr/bin/env python2

# standard Python library imports

# secondary Python library imports
# (should be in your distribution's repository)
import sqlite3



# ----------------------------------------------------
#     Exception classes
# ----------------------------------------------------

class InvalidAddressError(Exception):
    """invalid TCP string specified"""
    def __init__(self, ipaddr):
        self.hostip = ipaddr

        
class InvalidProtocolError(Exception):
    """Invalid TCP/UDP protocol specified"""
    def __init__(self, protocol):
        self.protocol = protocol

        
class InvalidStateError(Exception):
    """Invalid state specified"""
    def __init__(self, state):
        self.state = state
        

# ----------------------------------------------------
#     Data containers (returned from HostDB's query methods)
# ----------------------------------------------------        
        
# holder class for data coming out of the database
class PortInfo:
    def __init__(self, portnum, protocol, service_name, state):
        self.portnum = portnum
        self.protocol = protocol
        self.service_name = service_name
        self.state = state

        
# holder class for data coming out of the database        
class HostInfo:
    def __init__(self, hostip, hostname, ports=[]):
        self.ports = ports  # collection of PortInfo objects
        self.hostip = hostip
        self.hostname = hostname


        
# ----------------------------------------------------
#     Internal (private) module functions
# ----------------------------------------------------                   
   
# loads /etc/services and returns dictionary of "ip/port":servicename
def load_service_defs(fname):
    services = parse_service_defs(open(fname).readlines())
    return services

# feed it lines of services definition (like from /etc/services) and it will return a
# dictionary of "ip/port":servicename
def parse_service_defs(lines):
    services = {}
    for _line in lines:
       line = _line.strip()
       if line == '': continue
       if line[0]=='#': continue
       portAndType = line.split()[1]
       serviceName = line.split()[0]
       services[portAndType] = serviceName

    return services

# ----------- API and Utility Methods ----------------------------------------------
#
# These methods are exposed to the plugins and may be overriden by them.
#
#-----------------------------------------------------------------------------------
   
def is_tcpip_addr(tcpip_addr):
       """Utility API:  Return True if the string specified is a valid TCPv4 address and False otherwise"""
       # TODO:  Extend this to IPv6
       
       # filter out non-IP strings
       octets = tcpip_addr.strip().split('.')
       valid_octets = sum(oct.isdigit() and 0 <= int(oct) <= 256 for oct in octets)
       return valid_octets == 4

        
# ----------------------------------------------------
#     HostDB Implementation
# ----------------------------------------------------                

# Implements a database of host and port information, with API calls for plugins
class HostDatabase:
    
   def __init__(self):
       self.db = self._create_database()

   def _create_database(self):
       """Private method: create an empty database"""
       
       self.db = sqlite3.connect(':memory:')
       self.cursor = self.db.cursor()
       self.cursor.executescript("""

           CREATE TABLE Hosts(
               id        INTEGER PRIMARY KEY,
               hostip    VARCHAR(15) UNIQUE,
               hostname  VARCHAR(50)
               );
        
           CREATE TABLE Ports(
               id        INTEGER PRIMARY KEY,
               portnum   INTEGER CHECK (portnum>0 and portnum<=65535),
               protocol  VARCHAR(5),
               svcname   VARCHAR(20),
               state     VARCHAR(10),
               hostip    VARCHAR(15),
               foreignid INTEGER,
               
               FOREIGN KEY (foreignid) REFERENCES Hosts(id)
               );

           """)
           


   def add_host(self, hostip, host_name):
       """Database API:  Add a host to the database, where:
           - hostip: a string containing the host's Internet Protocol (IP) number
           - host_name: the name associated with this host"""

       # note: FIXME - make the queries below more efficient, probably condense into one query
       
       try:
           # skip if this is already in the database
           self.get_hostid(hostip)
           
       except Exception:
           # add host if it is unique
           self.cursor.execute("INSERT INTO Hosts(hostip, hostname) VALUES (?, ?);", (hostip, host_name))
       

   def get_hostip_list(self):
       """Database API:  Return a list of HostInfo objects describing the hosts in the database"""

       # make a generator of host info
       results = self.cursor.execute("SELECT h.hostip, h.hostname from Hosts AS h")
       
       # establish a list of proper HostInfo objects for the caller
       result = [HostInfo(hostip=h_ip,hostname=h_n) for (h_ip,h_n) in results]
       
       return result
       
       
   def get_hostid(self, hostip):
       """Database API:  Return ForeignID (integer) of a host given its IP address as a string"""
       
       # filter input IP string
       hostip = hostip.strip()
       if not is_tcpip_addr(hostip): raise InvalidAddressError(hostip)

       # perform the query
       results = self.cursor.execute("SELECT id from Hosts WHERE hostip=?",[hostip])
       
       # first element of the result contains the host id
       hostid = results.fetchone()[0] 
       
       return hostid

  
   def add_port(self, portnum, port_protocol, service_name, state, hostip):
       """Database API:  Add port information for a given host to the database, where:
           - hostip:  a string containing the host's Internet Protocol (IP) number
           - portnum:  a string containing the port number
           - protocol: one of "tcp", "udp"
           - service_name: name of the service or program responding to queries on this port
           - status: can be "Open", "Closed", or "Filered". """

       # normalize input
       port_protocol = port_protocol.strip().lower()
       state = state.strip().lower()
       service_name = service_name.strip().lower()
       
       # filter out bogus input
       if port_protocol not in ('tcp', 'udp'): raise InvalidProtocolError(port_protocol)
       
       # put statement here to make sure service_name is kosher
       if state not in ('closed', 'open', 'filtered'):  raise InvalidStateError(state)

       # get existing host's ID from its IP address
       foreignid = self.get_hostid(hostip)
       
       # add port information to the database
       self.cursor.execute("INSERT INTO Ports(portnum, protocol, svcname, state, hostip, foreignid) VALUES (?, ?, ?, ?, ?, ?);", (portnum, port_protocol, service_name, state, hostip, foreignid))

   
   def get_host_portlist(self, hostip):
       """Database API:  Return all port information for the specified host as a list of PortInfo objects, where:
           - hostip: a string containing the host's Internet Protocol (IPv4) address"""

       # filter out non-IP strings   
       hostip = hostip.strip()
       if not is_tcpip_addr(hostip): raise InvalidAddressError(hostip)
       
       # gather query results
       results = self.cursor.execute("SELECT portnum,protocol,svcname,state From Ports  WHERE Ports.hostip=?", [hostip])
       
       # establish a list of proper HostInfo objects for the caller
       result = [PortInfo(portnum=pn,protocol=pr,service_name=sv,state=st) for (pn,pr,sv,st) in results]
       return result
   
   
   def list_matching_ports(self, portnum, protocol="tcp", state="open"):
       # TODO:  Add option to specify port ranges or list of ports (or both)
       """Database API:  Return list of all hosts that have this port open, where:
           - portnum:  a string containing the port number
           - protocol: one of "tcp", "udp"
           - service_name: name of the service or program responding to queries on this port
           - status: optional.  Can be "open", "closed", or "filtered". """
           
       # filter bogus input
       protocol = protocol.strip().lower()
       if protocol not in ['tcp', 'udp']: 
           raise InvalidProtocolError(protocol)

       state = state.strip().lower()       
       if state not in ['open','closed','filtered']:
           raise InvalidStateError(state)
       
       # perform database query joiningg on host ID as a foreign key in Ports table
       results = self.cursor.execute("SELECT p.hostip, h.hostname FROM Ports AS p JOIN Hosts AS h ON p.foreignid=h.id  WHERE protocol=? AND portnum=? AND state=?;", [protocol, portnum, state])
       
       # establish a list of proper HostInfo objects for the caller
       result = [HostInfo(hostip=h_ip,hostname=h_n) for (h_ip,h_n) in results]
       
       return result
           
 

# These test routines execute when this module is executed by itself
if __name__=='__main__':
    
    db = HostDatabase()
    servicedefs = load_service_defs('/etc/services')
    
    port_protocol = "TCP"    

    # create some example hosts and ports
    IP='1.1.1.1'
    HOSTNAME='www.test123.com'
    db.add_host(hostip=IP, host_name=HOSTNAME)
    for portnum in range(20, 100):
       try:
           # note: FIXME - skip if this is already in the database
           service_name = servicedefs[portnum]
       except Exception:
           service_name  = "????"
       db.add_port(portnum=str(portnum), port_protocol="TCP", service_name=service_name, state="open", hostip=IP)       

    # create another example host with its own port list
    IP='2.2.2.2'
    HOSTNAME='www.testABC.com'
    db.add_host(hostip=IP, host_name=HOSTNAME)    
    for portnum in range(10, 30):
       try:
           # note: FIXME - skip if this is already in the database
           service_name = servicedefs[portnum]
       except Exception:
           service_name  = "????"
       db.add_port(portnum=str(portnum), port_protocol="TCP", service_name=service_name, state="open", hostip=IP)

        
    # show all hosts with open port 25/TCP
    hosts = db.list_matching_ports("10", protocol="tcp", state="open")
    print('ports with open port 10 include: ' + ','.join(p.hostip for p in hosts))
    
    # show a list of hosts inside the DB    
    print('hosts in the database: ' + ','.join([h.hostip for h in db.get_hostip_list()]))
    
    # show ports of a particular host
    print('ports for 1.1.1.1:')
    print(', '.join('{}/{} ({})'.format(p.portnum, p.protocol, p.state)  for p in db.get_host_portlist('1.1.1.1')))


