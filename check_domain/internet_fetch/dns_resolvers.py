# resolve dns records

import json
import unbound as ub
from ..internet_fetch import ip_helper
from ...domain_checks.config import Config
from ..formatted_response import DNSFormattedResponse, DNSHostMappingFormattedResponse
from ..formatted_response import DNSSECSignaturesFormattedResponse, DNSSECValidatedFormattedResponse, DNSSECFormattedResponse


class Resolver(object):
    """
    Responsible for querying dns records and returning results of the query in a formatted response.
    The general format is: {'domain', 'rr_types', 'answer'}.
    This class does not attempt to reach any hosts. See 'Reacher" class for host connecting & reachability.
    This class does not attempt to obtain DMARC, SPF, or DKIM records from DNS. For this, see DmarcianClient class.
    This class borrows functionality from the 'ip_helper.py' module to assist in constructing proper IPv6 addresses.
    This class has sibling FormattedResponse classes that wrap dictionaries that contain the response data.
    Inherits from: object.
    Parent to: None.
    Sibling to: Reacher, DmarcianClient
    """

    ctx = ub.ub_ctx()  # non dnssec context
    ctx.resolvconf(Config.RESOLV_CONF_LOCATION)

    ctx_dnssec = ub.ub_ctx()
    ctx_dnssec.resolvconf(Config.RESOLV_CONF_LOCATION)
    ctx_dnssec.add_ta_file(Config.ROOT_TRUST_ANCHOR)

    def __init__(self):
        pass

    def get_a_records(self, domain: str, as_json: bool = False):
        """
        Accepts domain: str. Returns a formatted answer including dictionary of A records in the format:
        {'domain': 'example.com', 'rr_types':['a'], 'answer': ['1.1.1.1', '2.2.2.2', '3.3.3.3' ... etc]}.
        If no record is found, returns None in the answer section.
        Set 'as_json' to True to return a pure json response instead of the wrapped formatted response.
        """

        formatted_answer = {'domain': domain, 'rr_types': ["a"], 'answer': None}

        status, results = Resolver.ctx.resolve(domain, rrtype=ub.RR_TYPE_A, rrclass=ub.RR_CLASS_IN)

        if status != 0:
            raise DNSResolveError(f"Error occurred while resolving IPv4 for {domain}")
        elif results.havedata == 1 and len(results.data.address_list) > 0:
            ipv4_addr_list = results.data.address_list
            formatted_answer['answer'] = {}
            i = 0
            for ip in ipv4_addr_list:
                formatted_answer['answer'][i] = ip
                i += 1
        if as_json:
            return json.dumps(formatted_answer)
        return DNSFormattedResponse(formatted_answer)

    def get_aaaa_records(self, domain: str, as_json: bool = False):
        """
        Accepts domain: str. Returns a formatted answer including dictionary of A records in the format:
        {'domain': 'example.com', 'rr_types':['aaaa'], 'answer': ['f::0', 'f::1', 'f::2' ... etc]}.
        If no record is found, returns None in the answer section.
        Set 'as_json' to True to return a pure json response instead of the wrapped formatted response.
        """
        formatted_answer = {'domain': domain, 'rr_types': ["aaaa"], 'answer': None}

        status, results = Resolver.ctx.resolve(domain, rrtype=ub.RR_TYPE_AAAA, rrclass=ub.RR_CLASS_IN)

        if status != 0:
            raise DNSResolveError(f"Error occurred while resolving IPv4 for {domain}")
        elif results.havedata == 1 and len(results.data.address_list) > 0:
            ipv6_addr_list = results.rawdata
            formatted_answer['answer'] = {}
            i = 0
            for ip in ipv6_addr_list:
                if ip_helper.V6.is_valid(ip):
                    formatted_answer['answer'][i] = ip_helper.V6.bytes_to_hexadectet(ip)
                i += 1
        if as_json:
            return json.dumps(formatted_answer)
        return DNSFormattedResponse(formatted_answer)

    # no exposed json for this private method below

    def _get_aaaa_bytes(self, domain: str):
        """Private internal class method. Takes in a single server name.
        If ipv6 data is found, returns bytes. If not found, returns None. No formatted response has been set."""
        ipv6_bytes = None

        status, results = Resolver.ctx.resolve(domain, rrtype=ub.RR_TYPE_AAAA)

        if status != 0:
            raise DNSResolveError(f"Error resolving AAAA record for {domain}: {ub.ub_strerror(status)}")
        elif results.havedata == 1 and ip_helper.V6.is_valid(results.rawdata[0]):
            ipv6_bytes = results.rawdata[0]
            # return results

        return ipv6_bytes

    def get_soa(self, domain: str, as_json: bool = False):
        """
        Accepts domain: str. Returns a formatted answer containing 'Start Of Authority' records in the format:
        {'domain': 'example.com', 'rr_types':['soa'], 'answer': ['administrator info, other info, time info, etc]}.
        If no record is found, returns None in the answer section.
        Set 'as_json=True' to return a pure json response instead of the wrapped formatted response.
        """
        formatted_answer = {'domain': domain, 'rr_types': ["soa"], 'answer': None}

        soa_list = None
        status, result = Resolver.ctx_dnssec.resolve(domain, ub.RR_TYPE_SOA, ub.RR_CLASS_IN)
        if status == 0 and result.havedata and result.secure == 1:
            formatted_answer['answer'] = {}
            soa_list = result.data.data
            i = 0
            for record in soa_list:
                formatted_answer['answer'][i] = str(record)
                i += 1
        elif status != 0:  # throw/raise error
            print("Resolve error: ", ub.ub_strerror(status))
        elif result.havedata == 0:  # if no data in result
            print("No data.")

        if as_json:
            return json.dumps(formatted_answer)
        return DNSFormattedResponse(formatted_answer)

    def get_ns(self, domain: str, as_json: bool = False):
        """
        Accepts domain: str. Returns a formatted answer containing 'NS' records in the format:
        {'domain': 'example.com', 'rr_types':['ns'], 'answer': ['ns1.com', 'ns2.com', ... etc]}.
        If no record is found, returns None in the answer section.
        Set 'as_json=True' to return a pure json response instead of the wrapped formatted response.
        """
        formatted_answer = {'domain': domain, 'rr_types': ["ns"], 'answer': None}

        status, results = Resolver.ctx.resolve(domain, rrtype=ub.RR_TYPE_NS)

        if status != 0:
            raise DNSResolveError(f"Error occured while resolving IPv4 for {domain}")
        elif results.havedata == 1 and len(results.data.address_list) > 0:
            ns_list = list(results.data.as_domain_list())
            formatted_answer['answer'] = {}
            i = 0
            for each in ns_list:
                formatted_answer['answer'][i] = each
                i += 1
        if as_json:
            return json.dumps(formatted_answer)
        return DNSFormattedResponse(formatted_answer)

    def get_mx(self, domain: str, as_json: bool = False):
        """
        Accepts domain: str. Returns a formatted answer containing 'MX' records in the format:
        {'domain': 'example.com', 'rr_types':['mx'], 'answer': ['smtp1.com', 'smtp2.com', ... etc]}.
        If no record is found, returns None in the answer section.
        Set 'as_json=True' to return a pure json response instead of the wrapped formatted response.
        """
        formatted_answer = {'domain': domain, 'rr_types': ["mx"], 'answer': None}

        status, results = Resolver.ctx.resolve(domain, rrtype=ub.RR_TYPE_MX)

        if status != 0:
            raise DNSResolveError(f"Error while fetching Mail Exchange list for {domain}")
        elif results.havedata == 1 and len(results.data.as_mx_list()) > 0:
            mx_list = list(results.data.as_mx_list())
            formatted_answer['answer'] = {}
            i = 0
            for priority, name in mx_list:
                formatted_answer['answer'][i] = name
                i += 1
        if as_json:
            return json.dumps(formatted_answer)
        return DNSFormattedResponse(formatted_answer)

    # methods below this line use unbound indirectly. They use methods in this class as their dependencies.

    # dns host mapping for use with reachability
    def get_ipv6_mapping(self, domain: str, associated_with: str, as_json: bool = False):
        """
        Accepts a domain, a type of host to associate an ip address with, and optionally 'as_json=True' to output json.
        This builds the DNSHostMappingFormattedResponse which can then be 'unpacked' by the Reacher class method
        reach_dns_hosts() or can be passed into a IPV6ExistsState directly.
        Output is something like,
        {'domain': 'x.com', 'rr_types':['ns', 'aaaa'], 'answer': {'ns1.com':'f::1', 'ns2.com':'f::2' ... etc}
        """
        formatted_answer = {'domain': domain, 'rr_types': [], 'answer': None}

        name_list = None
        if associated_with == "ns":
            ns_list = None
            if self.get_ns(domain).get_response()['answer'] is not None:
                ns_list = list(self.get_ns(domain).get_response()['answer'].values())
            name_list = ns_list
            formatted_answer['rr_types'].append("ns")
        elif associated_with == "mx":
            mx_list = None
            if self.get_mx(domain).get_response()['answer'] is not None:
                mx_list = list(self.get_mx(domain).get_response()['answer'].values())
            name_list = mx_list
            formatted_answer['rr_types'].append("mx")

        formatted_answer['rr_types'].append("aaaa")  # [rr_type, 4a] in that order indicates 'answer' content format.

        if associated_with == "ns" and name_list is None:  # all domains have ns records, but not necessarily mx records
            raise ValueError("Value of 'name_list' is None while querying for NS records. Should be non-empty list.")

        if name_list:
            i = 0
            formatted_answer['answer'] = {}
            for name in name_list:
                ip6_dict = self.get_aaaa_records(name).get_response()  # None or valid ip6 address returned
                if ip6_dict['answer'] is not None:
                    formatted_answer['answer'][name] = ip6_dict['answer'].get(i)
                else:
                    formatted_answer['answer'][name] = ip6_dict['answer']
                i += 1
                if ip6_dict['answer'] and i + 1 > len(ip6_dict['answer']):  # i beyond the bounds of 'data' dict
                    i = 0
                    continue
        if as_json:
            return json.dumps(formatted_answer)
        return DNSHostMappingFormattedResponse(formatted_answer)

    def get_ipv4_mapping(self, domain: str, associated_with: str, as_json: bool = False):  # newly added for decoupling
        """
        Accepts a domain, a type of host to associate an ip address with, and optionally 'as_json=True' to output json.
        This builds the DNSHostMappingFormattedResponse which can then be 'unpacked' by the Reacher class method
        reach_dns_hosts() or can be passed into a IPV4ExistsState directly.
        Output is something like,
        {'domain': 'x.com', 'rr_types':['ns', 'a'], 'answer': {'ns1.com':'1.1.1.1', 'ns2.com':'2.2.2.2' ... etc}
        """
        formatted_answer = {'domain': domain, 'rr_types': [], 'answer': None}

        name_list = None
        if associated_with == "ns":
            ns_list = None
            if self.get_ns(domain).get_response()['answer'] is not None:
                ns_list = list(self.get_ns(domain).get_response()['answer'].values())
            name_list = ns_list
            formatted_answer['rr_types'].append("ns")
        elif associated_with == "mx":
            mx_list = None
            if self.get_mx(domain).get_response()['answer'] is not None:
                mx_list = list(self.get_mx(domain).get_response()['answer'].values())
            name_list = mx_list
            formatted_answer['rr_types'].append("mx")

        formatted_answer['rr_types'].append("a")  # [name_record, ipv6] in that order indicates 'data' response index contents.

        if associated_with == "ns" and name_list is None:  # all domains have ns records, but not necessarily mx records
            raise ValueError("Value of 'name_list' is None while querying for NS records. Should be non-empty list.")

        if name_list:
            i = 0
            formatted_answer['answer'] = {}
            for name in name_list:
                ip4_dict = self.get_a_records(name).get_response()  # None or valid ip4 address returned
                if ip4_dict['answer'] is not None:
                    formatted_answer['answer'][name] = ip4_dict['answer'].get(i)
                else:
                    formatted_answer['answer'][name] = ip4_dict['answer']
                i += 1
                if ip4_dict['answer'] and i + 1 > len(ip4_dict['answer']):  # i beyond the bounds of 'data' dict
                    i = 0
                    continue
        if as_json:
            return json.dumps(formatted_answer)
        return DNSHostMappingFormattedResponse(formatted_answer)

    # dnssec
    def dnssec_comprehensive(self, domain: str, as_json: bool = False):

        formatted_response = {
            'domain': domain,
            'rr_types': ['a', 'dnssec', 'dnskey', 'rrsig', 'nsec', 'ds', 'soa'],
            'answer': {
                'validation': {'a': None, 'dnssec': None},
                'signatures': {'rrsig': None, 'nsec': None, 'ds': None, 'soa': None}
            }
        }

        validation_response = self.dnssec_validate(domain=domain, as_json=False).get_response()
        formatted_response['answer']['validation'] = validation_response['answer']

        dnssec_sigs_response = self.get_dnssec_sigs(domain=domain, as_json=False).get_response()
        formatted_response['answer']['signatures'] = dnssec_sigs_response['answer']

        if as_json:
            return json.dumps(formatted_response)
        return DNSSECFormattedResponse(formatted_response)

    def dnssec_validate(self, domain: str, as_json: bool = False):
        """Accepts a domain: str.
        Returns a formatted answer dictionary with dnssec validation results in the 'answer.'"""
        formatted_answer = {'domain': domain, 'rr_types': ["a", "dnssec"], 'answer': None}

        status, result = Resolver.ctx_dnssec.resolve(domain, ub.RR_TYPE_A)
        if status == 0 and result.havedata:
            formatted_answer['answer'] = {}
            ip_address_list = result.data.address_list
            for ip in ip_address_list:
                if result.secure:
                    formatted_answer['answer'][ip] = "secure"
                elif result.bogus:
                    formatted_answer['answer'][ip] = "bogus"
                else:
                    formatted_answer['answer'][ip] = "insecure"
        if as_json:
            return json.dumps(formatted_answer)
        return DNSSECValidatedFormattedResponse(formatted_answer)

    def get_dnssec_sigs(self, domain: str, as_json: bool = False):
        """
        Accepts a domain name and acquires all DNSSEC records according to RFC4034 and RFC4035: DNSKEY, RRSIG, NSEC, DS.
        Additionally, it also gets the SOA record. This method does not validate DNSSEC. It only checks for proper
        signatures.
        """

        # fetch
        formatted_answer = {'domain': domain, 'rr_types': ['dnskey', 'rrsig', 'nsec', 'ds', 'soa'], 'answer': None}
        dnskey_fa = self.get_dnskeys(domain, as_json=False).get_response()
        rrsig_fa = self.get_rrsigs(domain, as_json=False).get_response()
        nsec_fa = self.get_nsec(domain, as_json=False).get_response()
        ds_fa = self.get_ds(domain, as_json=False).get_response()
        soa_fa = self.get_soa(domain, as_json=False).get_response()

        # construct multi-resource record answer
        formatted_answer['answer'] = {}

        if soa_fa['answer'] is not None and len(soa_fa['answer']) > 0:
            keys = list(soa_fa['answer'].keys())
            for key in keys:
                formatted_answer['answer']['soa'] = []
                formatted_answer['answer']['soa'].append(soa_fa['answer'][key])
        else:
            formatted_answer['answer']['soa'] = None

        if dnskey_fa['answer'] is not None and len(dnskey_fa['answer']) > 0:
            keys = list(dnskey_fa['answer'].keys())
            for key in keys:
                formatted_answer['answer']['dnskey'] = []
                formatted_answer['answer']['dnskey'].append(dnskey_fa['answer'][key])
        else:
            formatted_answer['answer']['dnskey'] = None

        if rrsig_fa['answer'] is not None and len(rrsig_fa['answer']) > 0:
            keys = list(rrsig_fa['answer'].keys())
            for key in keys:
                formatted_answer['answer']['rrsig'] = []
                formatted_answer['answer']['rrsig'].append(rrsig_fa['answer'][key])
        else:
            formatted_answer['answer']['rrsig'] = None

        if nsec_fa['answer'] is not None and len(nsec_fa['answer']) > 0:
            keys = list(nsec_fa['answer'].keys())
            for key in keys:
                formatted_answer['answer']['nsec'] = []
                formatted_answer['answer']['nsec'].append(nsec_fa['answer'][key])
        else:
            formatted_answer['answer']['nsec'] = None

        if ds_fa['answer'] is not None and len(ds_fa['answer']) > 0:
            keys = list(ds_fa['answer'].keys())
            for key in keys:
                formatted_answer['answer']['ds'] = []
                formatted_answer['answer']['ds'].append(ds_fa['answer'][key])
        else:
            formatted_answer['answer']['ds'] = None

        if as_json:
            return json.dumps(formatted_answer)
        return DNSSECSignaturesFormattedResponse(formatted_answer)

    def get_dnskeys(self, domain: str, as_json: bool = False):
        """Accepts a domain: str. Returns a formatted answer dictionary, including dnskey records in the 'answer'."""
        formatted_answer = {'domain': domain, 'rr_types': ["dnskey"], 'answer': None}

        status, result = Resolver.ctx_dnssec.resolve(domain, rrtype=ub.RR_TYPE_DNSKEY)

        if status == 0 and result.havedata == 1:
            print("returned dnskeys.")
            formatted_answer['answer'] = {}
            dns_keys_list = result.data.data  # list of dnskeys. *should* return None or non-empty list
            i = 0
            for key in dns_keys_list:  # place into dict
                if as_json:
                    formatted_answer['answer'][i] = str(key)
                else:
                    formatted_answer['answer'][i] = key
                i += 1
        elif status != 0:  # throw/raise error
            print("Resolve error: ", ub.ub_strerror(status))
        elif result.havedata == 0:  # if no data in result
            print("No data.")

        if as_json:
            return json.dumps(formatted_answer)
        return DNSFormattedResponse(formatted_answer)

    def get_rrsigs(self, domain: str, as_json: bool = False):
        """Accepts a domain: str. Returns a formatted answer dictionary, with rrsig records in the 'answer'."""
        formatted_answer = {'domain': domain, 'rr_types': ["rrsig"], 'answer': None}

        status, result = Resolver.ctx_dnssec.resolve(domain, rrtype=ub.RR_TYPE_RRSIG)
        if status == 0 and result.havedata:
            print("rrsigs returned.")
            rrsig_list = result.data.data
            formatted_answer['answer'] = {}
            i = 0
            for sig in rrsig_list:
                if as_json:
                    formatted_answer['answer'][i] = str(sig)
                else:
                    formatted_answer['answer'][i] = sig
                i += 1
        elif status != 0:  # throw/raise error
            print("Resolve error: ", ub.ub_strerror(status))
        elif result.havedata == 0:  # if no data in result
            print("No data.")
            print(result.rcode_str)
        elif result.rcode != 0:
            print(result.rcode_str)

        if as_json:
            return json.dumps(formatted_answer)
        return DNSFormattedResponse(formatted_answer)

    def get_ds(self, domain: str, as_json: bool = False):
        """Accepts a domain. Returns a formatted answer dictionary with ds records in the 'answer'."""
        formatted_answer = {'domain': domain, 'rr_types': ["ds"], 'answer': None}

        status, result = Resolver.ctx_dnssec.resolve(domain, rrtype=ub.RR_TYPE_DS)

        if status == 0 and result.havedata:
            print("ds record returned.")
            formatted_answer['answer'] = {}
            ds_records_list = result.data.data
            i = 0
            for ds in ds_records_list:
                if as_json:
                    formatted_answer['answer'][i] = str(ds)
                else:
                    formatted_answer['answer'][i] = ds
                i += 0
        elif status != 0:  # throw/raise error
            print("Resolve error: ", ub.ub_strerror(status))
        elif result.havedata == 0:  # if no data in result
            print("No data.")
        if as_json:
            return json.dumps(formatted_answer)
        return DNSFormattedResponse(formatted_answer)

    def get_nsec(self, domain: str, as_json: bool = False):
        """Accepts a domain: str. Returns a formatted answer dictionary with the nsec records inside the 'answer'."""
        formatted_answer = {'domain': domain, 'rr_types': ["nsec"], 'answer': None}

        status, result = Resolver.ctx_dnssec.resolve(domain, rrtype=ub.RR_TYPE_NSEC)
        if status == 0 and result.havedata:
            nsec_list = result.data.data
            formatted_answer['answer'] = {}
            i = 0
            for nsec in nsec_list:
                if as_json:
                    formatted_answer['answer'][i] = str(nsec)
                else:
                    formatted_answer['answer'][i] = nsec
                i += 1
        elif status != 0:  # throw/raise error
            print("Resolve error: ", ub.ub_strerror(status), result.rcode_str)
        elif result.havedata == 0:  # if no data in result
            print("No data", result.rcode_str)

        if as_json:
            return json.dumps(formatted_answer)
        return DNSFormattedResponse(formatted_answer)


# errors
class Error(Exception):
    pass


class DNSResolveError(Error):
    pass

# end

