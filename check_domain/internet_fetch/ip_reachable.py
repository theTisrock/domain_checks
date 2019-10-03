import socket as s
import subprocess as sp
from subprocess import PIPE
import json
from ..formatted_response import DNSHostMappingFormattedResponse, HostFormattedResponse


class Reacher(object):
    """Connects to or pings hosts via IP Address and does not perform any
    dns resolving. For dns resolving, see dns_resolvers.py in the Resolver class.
    The two utility methods are ping() and port_test().
    The workhorse method of this class is the reach() method. All other reachability checks derive from this one.
    reach_mail(), reach_web(), and reach_ns() are simple short cuts to not have to remember common ports for those
    services.
    Inherits from: object.
    Parent to: None.
    Sibling to: Resolver, DmarcianClient"""

    def reach_dns_hosts(self, dns_answer: DNSHostMappingFormattedResponse, port_list: list = None, ping_it: bool = True, jsonic=False):
        """This represents the testing of reachability on a group of hosts of the same dns_host_type: mx, ns, web.
        It encapsulates multiple units of work: one unit of work for each host.
        dns_answer: dict - a formatted answer from a dns resolver. see Resolver class and/or formatted_response.py.
        port_list: list - default None; Additional ports to be queried.
        ping_it: bool - default True; set False disable ping.
        Extracts dns answer information (host names, ip addresses, domain name, rr_types) to check
        reachable property of all hosts associated with this domain via the ipv4 'a record' or ipv6 'aaaa record' found
        in the formatted response.
        Returns a dict of results for each host as a HostFormattedResponse."""

        if not isinstance(dns_answer, DNSHostMappingFormattedResponse):  # protection
            raise TypeError(f"The dns_answer must be of type: DNSHostMappingFormattedResponse. Not {type(dns_answer)}")

        dns_answer = dns_answer.get_response()  # unpack output from get_ipv[#]_mapping() method

        formatted_answer = {  # to be returned
            'domain': dns_answer['domain'],
            'rr_types': dns_answer['rr_types'],
            'hosts': {}
        }

	# analyze dns_answer data in preparation for reach testing

        ip_v = None  # determine ip version from dns answer
        if dns_answer['rr_types'][1] == "aaaa":
            ip_v = 6
        elif dns_answer['rr_types'][1] == "a":
            ip_v = 4

        dns_host_type = dns_answer['rr_types'][0]  # get dns host type

        if dns_answer['answer'] is None or len(dns_answer['answer']) == 0:  # check for no hosts
            formatted_answer['hosts'] = None  # the request hosts types (ns, mx servers) do not exist
	
	# perform reach testing according to dns_host_type
        else:
            host_names = list(dns_answer['answer'].keys())  # get host name keys

            for key in host_names:
                ip = dns_answer['answer'][key]
                if dns_host_type == "ns":
                    h = self.reach_ns(ip, ip_v, key, dns_answer['domain'], port_list, ping_it).get_response()
                elif dns_host_type == "mx":
                    h = self.reach_mail(ip, ip_v, key, dns_answer['domain'], port_list, ping_it).get_response()
                else:
                    h = self.reach(ip, ip_v, key, dns_host_type, dns_answer['domain'], port_list, ping_it).get_response()

	# copy test results
                formatted_answer['hosts'][key] = {}
                formatted_answer['hosts'][key]['pingable'] = h['pingable']
                formatted_answer['hosts'][key]['ip'] = h['ip']
                formatted_answer['hosts'][key]['ports_succeeded'] = h['ports_succeeded']
                formatted_answer['hosts'][key]['can_connect'] = h['can_connect']

        if jsonic:
            formatted_answer = json.dumps(formatted_answer)
	
	# return test results
        return HostFormattedResponse(formatted_answer)

    def reach(self, address: str, ip_version: int, host_name: str = None, host_type: str = None,
              common_domain: str = None, port_list: list = None, ping_it: bool = True, as_json=False):
        """This represents the testing of reachability on a singular host, a single unit of work.
        The optional context parameters are intended to be obtained from a previous query to DNS in a
        DNSHostMappingFormattedResponse, but this method can also be used in isolation. 'host_name', 'host_type',
        'common_domain', 'port_list' are all optional. Set 'ping_it=False' to disable ping.
        :return: 'as_json=True' to enables returning a json response. Otherwise, a HostFormattedResponse is returned."""
        formatted_answer = {
            'host_name': host_name, 'host_type': host_type, 'domain': common_domain,
            'pingable': None, 'ip_v': ip_version, 'ip': address, 'ports_succeeded': None, 'can_connect': None
        }

        if address is not None:
            if ping_it == True:
                packets_sent_received = ping(address, ip_version)  # test for ping
                if packets_sent_received[1] >= 1:  # packets received
                    formatted_answer['pingable'] = True
                else:
                    formatted_answer['pingable'] = False

            if port_list is not None and len(port_list) > 0:
                ports_successful = None  # test ports
                formatted_answer['can_connect'] = False
                if ip_version == 4:
                    ports_successful = port_test(address, port_list, s.AF_INET, s.SOCK_STREAM)
                elif ip_version == 6:
                    ports_successful = port_test(address, port_list, s.AF_INET6, s.SOCK_STREAM)
                formatted_answer['ports_succeeded'] = ports_successful
                if ports_successful is not None and len(ports_successful) > 0:
                    formatted_answer['can_connect'] = True
        else:  # ip is None; do not ping or connect
            formatted_answer['pingable'] = False
            formatted_answer['can_connect'] = False

        if as_json:
            formatted_answer = json.dumps(formatted_answer)
        return HostFormattedResponse(formatted_answer)

    def reach_mail(self, address: str, ip_version: int, host_name: str = None, common_domain: str = None,
                   additional_ports: list = None, ping_it: bool = True, jsonic=False):
        """Requires same input as reach() method: ip & ip_version. Additional ports may be passed in explicitly so they
        can be checked. Duplicate ports are removed and are only checked one time. Contains a list of common mail ports
        in order to remove the chore of remembering port numbers."""
        common_ports = [587, 465, 25]
        if additional_ports is not None:
            for port in additional_ports:
                common_ports.append(port)
        common_ports = list(set(common_ports))  # get list of unique ports
        formatted_answer = self.reach(address, ip_version, host_name, "mx", common_domain, common_ports, ping_it,
                                      as_json=jsonic).get_response()

        if jsonic:
            formatted_answer = json.dumps(formatted_answer)
        return HostFormattedResponse(formatted_answer)

    def reach_web(self, address: str, ip_version: int, host_name: str = None, common_domain: str = None,
                  additional_ports: list = None, ping_it: bool = True, jsonic=False):
        """Requires same input as reach() method: ip & ip_version. Additional ports may be passed in explicitly so they
                can be checked. Duplicate ports are removed and are only checked one time. Contains a list of common
                web ports in order to remove the chore of remembering port numbers."""
        common_ports = [80, 443]
        if additional_ports is not None:
            for port in additional_ports:
                common_ports.append(port)
        common_ports = list(set(common_ports))  # get list of unique ports
        formatted_answer = self.reach(address, ip_version, host_name, "web", common_domain, common_ports,
                                      ping_it).get_response()

        if jsonic:
            formatted_answer = json.dumps(formatted_answer)
        return HostFormattedResponse(formatted_answer)

    def reach_ns(self, address: str, ip_version: int, host_name: str = None, common_domain: str = None,
                 additional_ports: list = None, ping_it: bool = True, jsonic=False):
        """
        Requires same input as reach() method: ip & ip_version. Additional ports may be passed in explicitly so they
        can be checked. Duplicate ports are removed and are only checked one time. Contains port 53 as the default
        dns nameserver port.
        """
        common_ports = [53]
        if additional_ports is not None:
            for port in additional_ports:
                common_ports.append(port)
        common_ports = list(set(common_ports))  # get list of unique ports
        formatted_answer = self.reach(address, ip_version, host_name, "ns", common_domain, common_ports,
                                      ping_it).get_response()

        if jsonic:
            formatted_answer = json.dumps(formatted_answer)
        return HostFormattedResponse(formatted_answer)


# ping for testing for general reachable status of hosts with no regard to port specific services
def ping(address: str, ip_version: int = 4, packet_num: int = 1, maxtimeout: int = 2):
    """Sends 1 packet (default quantity) to a host. Records quantity of received packets. Returns [sent, received].
    This is done regardless of whether or not an exception is thrown. packet_num below 1 is disallowed.
    This is meant to test the basic reachability of a host. For service (web, mail, other) see port_test()."""
    if packet_num < 1:
        raise ValueError("You must send at least one packet.")
    if ip_version == 4 and (len(address) > 15 or len(address) < 7):
        raise ValueError(f"IPv4 Address has improper length {len(address)}.")

    sent = packet_num

    try:
        x = None
        if ip_version == 6:
            x = sp.run(["ping6", "-c", str(packet_num), address], timeout=maxtimeout, stdout=PIPE, stderr=PIPE, check=True)
        elif ip_version == 4:
            x = sp.run(["ping", "-c", str(packet_num), address], timeout=maxtimeout, stdout=PIPE, stderr=PIPE, check=True)

        if not isinstance(x, sp.CompletedProcess):
            raise TypeError("Ping returned NoneType. Subprocess may have failed.")

        word_elements = x.stdout.decode().split()  # commas are contained in list elements
        received_index = word_elements.index("received,")
        receive_packets = word_elements[received_index - 1]  # value of packets received is 1 before "received"
        sent_received = (sent, int(receive_packets))

    except sp.TimeoutExpired:
        print("ping subprocess timed out")
        sent_received = (sent, 0)
    except sp.CalledProcessError as cpe:
        sent_received = (sent, 0)
    except TypeError:
        print("The subprocess.run() method returned NoneType from ping command.")
        sent_received = (sent, 0)

    return sent_received  # tuple pair to compare what was sent and what was received


# tests for specific services at a host. Ex, mail [25, 487, 587], web [80, 443]
def port_test(ip_str, port_list, address_family, sock_type):  # a client socket used to test ipv6 port connection
    """
    Accepts 1 address + port_list + socket_context(AF_INET or AF_INET6 + sock_type).
    Checks each port for connectivity. Returns a list of successful ports or None.
    This test is intended to be used for the primary means of "reachability" checking. If all ports fail,
    ping can be used as a fall back.
    This is meant to test the reachability of a specific service (mail, web, other). For general, non-port specific,
    host-only reachability, see ping()."""
    if not isinstance(ip_str, str):
        raise TypeError("ip must be in string format.")
    if not isinstance(port_list, list):
        raise TypeError(f"port_list must be type:list. Not {type(port_list)}")
    if len(port_list) == 0:
        raise Exception(f"port_list {port_list} cannot be empty.")
    if not isinstance(port_list[0], int):  # test an element for proper type
        raise TypeError("elements in arg 'port_list' must be of type:int")

    ports_successful = []

    for port in port_list:
        my_s = s.socket(address_family, sock_type)
        my_s.settimeout(2)
        dest = (ip_str, port)
        try:
            my_s.connect(dest)
            # assumed connected at this line, else exception thrown
            ports_successful.append(port)
        except s.timeout:
            print(f"ip reach check for {dest} timed out.")
        except s.gaierror as gai:
            print(f"gai error: ip: {ip_str}, port: {port}")
        except ConnectionRefusedError:
            print(f"Connection refused: ip {ip_str}, port: {port}")
        except OSError:
            print(f"OSError: ip {ip_str}, port: {port}")
        finally:
            my_s.close()

    if len(ports_successful) == 0:
        ports_successful = None

    return ports_successful


# end
