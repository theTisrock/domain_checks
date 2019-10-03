import unittest

from project.tools.dns_resolvers import Resolver
from project.tools.ip_reachable import Reacher


class TestIPReachable(unittest.TestCase):

    def test_reach_single_host_ipv4_ping(self):  # ping only; no domain context
        host = Reacher()
        expected = {
            'host_name': None,
            'host_type': None,
            'domain': None,
            'pingable': True,
            'ip_v': 4,
            'ip': "52.33.238.38",
            'ports_succeeded': None,
            'can_connect': None
        }
        self.assertEqual(expected, host.reach('52.33.238.38', 4).get_response())  # ping turned on: default
        expected['pingable'] = None
        self.assertEqual(expected, host.reach("52.33.238.38", 4, ping_it=False).get_response())  # turn off ping

    def test_reach_single_host_ipv4_ping_ports(self):
        host = Reacher()
        expected = {
            'host_name': None,
            'host_type': None,
            'domain': None,
            'pingable': None,
            'ip_v': 4,
            'ip': "52.33.238.38",
            'ports_succeeded': [80, 443],
            'can_connect': True
        }
        self.assertEqual(expected, host.reach("52.33.238.38", 4, port_list=[80, 443], ping_it=False).get_response())  # good ports
        expected['pingable'] = True
        self.assertEqual(expected, host.reach("52.33.238.38", 4, port_list=[80, 443], ping_it=True).get_response())  # good ports&ping
        expected['ports_succeeded'] = None
        expected['pingable'] = None
        expected['can_connect'] = False
        self.assertEqual(expected, host.reach("52.33.238.38", 4, port_list=[99], ping_it=False).get_response())  # bad ports
        expected['pingable'] = True
        self.assertEqual(expected, host.reach("52.33.238.38", 4, port_list=[99], ping_it=True).get_response())  # bad ports&ping

    def test_reach_group_host_ipv4_ping(self):
        hosts = Reacher()
        dns = Resolver()

        expected = {
            'domain': "gvlswing.com",
            'rr_types': ["ns", "a"],
            'hosts': {
                'ns-1394.awsdns-46.org.': {
                    'pingable': None,
                    'ip': "205.251.197.114",
                    'ports_succeeded': [53],
                    'can_connect': True},
                'ns-1582.awsdns-05.co.uk.': {
                    'pingable': None,
                    'ip': "205.251.198.46",
                    'ports_succeeded': [53],
                    'can_connect': True},
                'ns-439.awsdns-54.com.': {
                    'pingable': None,
                    'ip': "205.251.193.183",
                    'ports_succeeded': [53],
                    'can_connect': True},
                'ns-812.awsdns-37.net.': {
                    'pingable': None,
                    'ip': "205.251.195.44",
                    'ports_succeeded': [53],
                    'can_connect': True}
            }
        }

        answer = dns.get_ipv4("gvlswing.com", "ns")
        self.assertEqual(expected, hosts.reach_dns_hosts(answer, ping_it=False).get_response())

# end
