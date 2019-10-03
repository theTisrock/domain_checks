import unittest
from project.tools.ip_reachable import Reacher, HostFormattedResponse
from project.tools.dns_resolvers import Resolver, DNSFormattedResponse, DNSHostMappingFormattedResponse


class TestDNSResponseFormat(unittest.TestCase):

    def test_get_a_records(self):
        dns = Resolver()
        response = dns.get_a_records("interdc.nl")
        self.assertIsInstance(response, DNSFormattedResponse)

    def test_get_aaaa_records(self):
        dns = Resolver()
        response = dns.get_aaaa_records("interdc.nl")
        self.assertIsInstance(response, DNSFormattedResponse)

    def test_get_soa(self):
        dns = Resolver()
        response = dns.get_soa("interdc.nl")
        self.assertIsInstance(response, DNSFormattedResponse)

    def test_get_ns(self):
        dns = Resolver()
        response = dns.get_ns("interdc.nl")
        self.assertIsInstance(response, DNSFormattedResponse)

    def test_get_mx(self):
        dns = Resolver()
        response = dns.get_mx("interdc.nl")
        self.assertIsInstance(response, DNSFormattedResponse)

    def test_get_all_dnssec(self):
        dns = Resolver()
        response = dns.get_dnssec_sigs("interdc.nl")
        self.assertIsInstance(response, DNSFormattedResponse)

    def test_get_dnskey(self):
        dns = Resolver()
        response = dns.get_dnskeys("interdc.nl")
        self.assertIsInstance(response, DNSFormattedResponse)

    def test_get_rrsigs(self):
        dns = Resolver()
        response = dns.get_rrsigs("interdc.nl")
        self.assertIsInstance(response, DNSFormattedResponse)

    def test_get_ds(self):
        dns = Resolver()
        response = dns.get_ds("interdc.nl")
        self.assertIsInstance(response, DNSFormattedResponse)

    def test_get_nsec(self):
        dns = Resolver()
        response = dns.get_nsec("interdc.nl")
        self.assertIsInstance(response, DNSFormattedResponse)

    def test_validate_dnsssec(self):
        dns = Resolver()
        response = dns.dnssec_validate("interdc.nl")
        self.assertIsInstance(response, DNSFormattedResponse)


class TestDNSHostMappingFormattedResponse(unittest.TestCase):

    def test_get_ipv4(self):
        dns = Resolver()
        response = dns.get_ipv4("gvlswing.com", "ns")
        self.assertIsInstance(response, DNSHostMappingFormattedResponse)

    def test_get_ipv6(self):
        dns = Resolver()
        response = dns.get_ipv6("gvlswing.com", "ns")
        self.assertIsInstance(response, DNSHostMappingFormattedResponse)


class TestHostResponseFormat(unittest.TestCase):

    def test_reach_dns_hosts(self):
        hosts = Reacher()
        dns = Resolver()
        dns_host_map_response = dns.get_ipv4("gvlswing.com", "ns")
        response = hosts.reach_dns_hosts(dns_host_map_response)
        self.assertIsInstance(response, HostFormattedResponse)

    def test_reach(self):
        hosts = Reacher()
        dns = Resolver()
        dns_formatted_response = dns.get_a_records("gvlswing.com")
        response = hosts.reach(dns_formatted_response.get_response()['answer'][0], 4)
        self.assertIsInstance(response, HostFormattedResponse)