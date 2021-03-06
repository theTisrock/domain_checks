# top level service drivers for domain checking
from .internet_fetch import *
from .domain_state import *
import json


class DomainChecker(object):
    """Pieces together bottom level services to perform customized top level tasks (domain checking)."""

    # dmarcian = DmarcianClient(BASE_URL, TOKEN)  # singletons for connecting underlying, decoupled code to top level requests
    dns = Resolver()
    hosts = Reacher()

    def __init__(self):
        pass

    # def dkim(self, domain: str, selector: str, as_json=False):
    #     response = self.dmarcian.inspect_dkim(domain=domain, selector=selector)
    #     state = DKIMState(response)
    #
    #     if as_json is True:
    #         dkim = {'dkim': response.get_response()}
    #         return json.dumps(dkim)
    #
    #     return state
    #
    # def spf(self, domain: str, as_json=False):
    #     response = self.dmarcian.inspect_spf(domain=domain)
    #     state = SPFState(response)
    #
    #     if as_json is True:
    #         spf = {'spf': response.get_response()}
    #         return json.dumps(spf)
    #
    #     return state
    #
    # def dmarc(self, domain: str, as_json=False):
    #     response = self.dmarcian.inspect_dmarc(domain=domain)
    #     state = DMARCState(response)
    #
    #     if as_json is True:
    #         dmarc = {'dmarc': response.get_response()}
    #         return json.dumps(dmarc)
    #
    #     return state

    def dnssec_signatures(self, domain: str, as_json=False):
        response = self.dns.get_dnssec_sigs(domain=domain)
        state = DNSSECSignaturesFormattedResponse(response)

        return state

    def dnssec_valid(self, domain: str, as_json=False):
        response = self.dns.dnssec_validate(domain=domain)
        state = DNSSECValidatedState(response)

        return state

    def dnssec(self, domain: str, as_json=False):
        response = self.dns.dnssec_comprehensive(domain=domain)
        state = DNSSECState(response)

        return state

    def ns_ipv6_exist(self, domain: str, as_json=False):
        response = self.dns.get_ipv6_mapping(domain=domain, associated_with="ns")
        state = IPV6ExistState(response)

        return state

    def ns_ipv6_reach(self, domain: str, as_json=False):
        dns_host_map = self.dns.get_ipv6_mapping(domain=domain, associated_with="ns")
        response = self.hosts.reach_dns_hosts(dns_host_map)
        state = IPV6ReachState(response)

        return state

    def ns_ipv4_exist(self, domain: str, as_json=False):
        return self.dns.get_ipv4_mapping(domain=domain, associated_with="ns")

    def ns_ipv4_reach(self, domain: str, as_json=False):
        dns_host_map = self.dns.get_ipv4_mapping(domain=domain, associated_with="ns")
        response = self.hosts.reach_dns_hosts(dns_host_map)
        state = IPV4ReachState(response)

        return state

    def mx_ipv6_exist(self, domain: str, as_json=False):
        response = self.dns.get_ipv6_mapping(domain=domain, associated_with="mx")
        state = IPV6ExistState(response)

        return state

    def mx_ipv6_reach(self, domain: str, as_json=False):
        dns_host_map = self.dns.get_ipv6_mapping(domain=domain, associated_with="mx")
        response = self.hosts.reach_dns_hosts(dns_host_map)
        state = IPV6ReachState(response)

        return state

    def mx_ipv4_exist(self, domain: str, as_json=False):
        return self.dns.get_ipv4_mapping(domain=domain, associated_with="mx")

    def mx_ipv4_reach(self, domain: str, as_json=False):
        dns_host_map = self.dns.get_ipv4_mapping(domain=domain, associated_with="mx")
        response = self.hosts.reach_dns_hosts(dns_host_map)
        state = IPV4ReachState(response)

        return state

# end

