# domain_state contains classes that store information about a particular domain and/or it's related hosts.
# For example, ipv6 existence state, ipv6 reachability state, dnssec signatures state, dnssec validity state, etc.
# These are the models that represent the 'states' of various capabilities and attributes of a domain and are returned for analysis to the programmer.

from datetime import datetime
from .formatted_response import *


class BaseState(object):
    """Parent to all state objects. Contains core data structures and variables common to all states,
    like time stamping, the original response, and the domain that was queried. In summary, it provides the context for
    any query on/to a domain, host, or Dmarcian API. All states inherit this state."""

    def __init__(self, formatted_answer):
        self.formatted_answer = formatted_answer
        self.domain = self.formatted_answer.get('domain')
        self.state_timestamp = datetime.utcnow()


class DomainAuthenticityState(BaseState):
    """Accepts any of the MailAntiphishingFormattedResponse type responses: DMARCInspectorFormattedResponse,
    SPFInspectorFormattedResponse, DKIMInspectorFormattedResponse. Any other object passed in will raise a
    TypeError exception.
    Inherits from: Base State
    Parent to: SPFState, DKIMState, & DMARCState.
    Sibling to: DNSHostGroupState, DNSSECSignaturesState, DNSSECValidatedState"""

    def __init__(self, formatted_answer: DomainAuthenticityFormattedResponse or DmarcianFormattedResponse):
        if not isinstance(formatted_answer, DomainAuthenticityFormattedResponse) \
                and not isinstance(formatted_answer, DmarcianFormattedResponse):
            raise TypeError("A DomainAuthenticityState only accepts a DomainAuthenticityResponse or a "
                            f"DmarcianFormattedResponse. Found {type(formatted_answer)}")
        BaseState.__init__(self, formatted_answer)
        self.records = self.formatted_answer.get('records')
        if self.records is None:
            self.records_count = 0
        else:
            self.records_count = len(self.formatted_answer.get('records'))
        self.valid = self.formatted_answer.get('valid')
        self.errors = self.formatted_answer.get('errors')


class DNSHostGroupState(BaseState):
    """Accepts DNSHostMappingFormattedResponse or HostFormattedResponse from get_ipv#_mapping() in Resolver class
    or reach_dns_hosts() in Reacher class, respectively. Throws a TypeError exception otherwise.
    Acts as the parent class of IPV#ExistState & IPV#ReachState sibling classes. Provides a common field to both:
    host_type ('ns', 'mx', etc).
    Inherit from: BaseState
    Parent to: IPV6ExistState, IPV6ReachState, IPV4ExistState, IPV4ReachState.
    Sibling to: DomainAuthenticityState, DNSSECSignaturesState, DNSSECValidatedState"""

    def __init__(self, formatted_answer):
        # if not isinstance(formatted_answer, DNSHostMappingFormattedResponse) and not \
        #         isinstance(formatted_answer, HostFormattedResponse):
        #     raise TypeError("DNSHostMappingFormattedResponse or HostFormattedResponse are required."
        #                     f" Found {type(formatted_answer)}")
        BaseState.__init__(self, formatted_answer)
        self.host_type = self.formatted_answer['rr_types'][0]
        self.report = None


class IPV6ExistState(DNSHostGroupState):
    """Accepts a DNSHostMappingFormattedResponse and throws a TypeError exception otherwise. If the formatted response
    does not indicate an 'aaaa' record, a ValueError exception is thrown. An IPV6ExistState class shows the
    IP Addresses listed for a particular host_type ('ns', 'mx' ... etc) or None if no IP address is found.
    Inherits from: DNSHostGroupState -> BaseState.
    Parent to: None.
    Sibling to: IPV4ExistState, IPV4ReachState, IPV6ReachState"""

    def __init__(self, dns_formatted_answer: DNSHostMappingFormattedResponse):
        if not isinstance(dns_formatted_answer, DNSHostMappingFormattedResponse):
            raise TypeError("IPV6ExistState requires DNSHostMappingFormattedResponse "
                            "from reach_dns_hosts() method in Resolver class.")
        DNSHostGroupState.__init__(self, dns_formatted_answer)
        if dns_formatted_answer.get_response()['rr_types'][1] != "aaaa":
            raise ValueError(f"dns answer does not indicate ipv6 ('aaaa') according to the given rr_types: "
                             f"{dns_formatted_answer.get_response()['rr_types']}")
        self.elements_present = self._load_elements_present()
        self.elements_missing = self._load_elements_missing()

    def __repr__(self):
        return f"<IPV6ExistsState: {self.domain}, {self.formatted_answer['rr_types']}>"

    def with_ipv6(self):
        return self.elements_present

    def without_ipv6(self):
        return self.elements_missing

    def all_elements(self):
        return self.formatted_answer['answer']

    def _load_elements_present(self):
        passed_dict = {}
        keys = list(self.formatted_answer['answer'].keys())

        for key in keys:
            if self.formatted_answer['answer'][key] is not None:
                passed_dict[key] = self.formatted_answer['answer'][key]

        if len(passed_dict) == 0:
            return None

        return passed_dict

    def _load_elements_missing(self):
        failed_dict = {}
        keys = list(self.formatted_answer['answer'].keys())

        for key in keys:
            if self.formatted_answer['answer'][key] is None:
                failed_dict[key] = self.formatted_answer['answer'][key]

        if len(failed_dict) == 0:
            return None

        return failed_dict


class IPV4ExistState(DNSHostGroupState):
    """Accepts a DNSHostMappingFormattedResponse from get_ipv4_mapping in Resolver class &
    throws a TypeError exception otherwise. If the formatted response does not indicate an 'a' record, a ValueError
    exception is thrown.
    An IPV4ExistState class shows the IP Addresses listed for a particular host_type ('ns', 'mx' ... etc) or None,
    if no IP address is found. Ex, 'ns1.com' : "1.2.3.4", 'ns2.com': None
    Inherits from: DNSHostGroupState -> BaseState.
    Parent to: None.
    Sibling to: IPV6ExistState, IPV4ReachState, IPV6ReachState"""

    def __init__(self, formatted_answer):
        # if not isinstance(formatted_answer, DNSHostMappingFormattedResponse):
        #     raise TypeError("IPV4ExistState requires DNSHostMappingFormattedResponse "
        #                     "from get_ipv4_mapping() method in Resolver class.")
        DNSHostGroupState.__init__(self, formatted_answer)
        if formatted_answer['rr_types'][1] != "a":
            raise ValueError(f"dns answer does not indicate ipv4 ('a') according to the given rr_types: "
                             f"{formatted_answer['rr_types']}")
        self.elements_present = self._load_elements_present()
        self.elements_missing = self._load_elements_missing()

    def __repr__(self):
        return f"<IPV4ExistsState: {self.domain}, {self.formatted_answer['rr_types']}>"

    def with_ipv4(self):
        return self.elements_present

    def without_ipv4(self):
        return self.elements_missing

    def all_elements(self):
        return self.formatted_answer['answer']

    def _load_elements_present(self):
        passed_dict = {}
        if self.formatted_answer['answer'] is None:
            return None
        keys = list(self.formatted_answer['answer'].keys())

        for key in keys:
            if self.formatted_answer['answer'][key] is not None:
                passed_dict[key] = self.formatted_answer['answer'][key]

        if len(passed_dict) == 0:
            return None

        return passed_dict

    def _load_elements_missing(self):
        failed_dict = {}
        if self.formatted_answer['answer'] is None:
            return None

        keys = list(self.formatted_answer['answer'].keys())

        for key in keys:
            if self.formatted_answer['answer'][key] is None:
                failed_dict[key] = self.formatted_answer['answer'][key]

        if len(failed_dict) == 0:
            return None

        return failed_dict


class IPV6ReachState(DNSHostGroupState):
    """Accepts a HostFormattedResponse from reach_dns_hosts() in Reacher class & throws a TypeError exception otherwise.
    If the formatted response does not include an 'aaaa' record type in the rr_types list,
    a ValueError exception is thrown.
    This object shows the results of an attempt to reach a list of dns hosts ('mx', 'ns', ... etc).
    Inherits from: DNSHostGroupState -> BaseState.
    Parent to: None.
    Sibling to: IPV6ExistState, IPV4ExistState, IPV4ReachState"""

    def __init__(self, dnshosts_formatted_response: HostFormattedResponse):
        if not isinstance(dnshosts_formatted_response, HostFormattedResponse):
            raise TypeError("IPV6ReachState requires HostFormattedResponse "
                            "from reach_dns_hosts() method in Reacher class.")
        DNSHostGroupState.__init__(self, dnshosts_formatted_response)
        if dnshosts_formatted_response.get_response()['rr_types'][1] != "aaaa":
            raise ValueError(f"dns answer does not indicate ipv6 ('aaaa') according to the given rr_types: "
                             f"{dnshosts_formatted_response.get_response()['rr_types']}")

    def __repr__(self):
        return f"<IPV6ReachState: {self.domain}, {self.formatted_answer['rr_types']}>"

    def reach_test(self, require_connect=False):
        hosts_keys = list(self.formatted_answer['hosts'].keys())
        reached = {}
        unreached = {}

        for host in hosts_keys:
            pingable = self.formatted_answer['hosts'][host]['pingable']
            can_connect = self.formatted_answer['hosts'][host]['can_connect']

            if require_connect:
                if can_connect:
                    reached[host] = self.formatted_answer['hosts'][host]
                else:
                    unreached[host] = self.formatted_answer['hosts'][host]
            else:
                if can_connect or pingable:
                    reached[host] = self.formatted_answer['hosts'][host]
                else:
                    unreached[host] = self.formatted_answer['hosts'][host]

        return {'reached': reached, 'unreached': unreached}


class IPV4ReachState(DNSHostGroupState):
    """Accepts a HostFormattedResponse from reach_dns_hosts() in Reacher class & throws a TypeError exception otherwise.
        If the formatted response does not include an 'a' record type in the rr_types list,
        a ValueError exception is thrown.
        This object shows the results of an attempt to reach a list of dns hosts ('mx', 'ns', ... etc).
        Inherits from: DNSHostGroupState -> BaseState.
        Parent to: None.
        Sibling to: IPV6ExistState, IPV4ExistState, IPV6ReachState"""

    def __init__(self, dnshosts_formatted_response: HostFormattedResponse):
        if not isinstance(dnshosts_formatted_response, HostFormattedResponse):
            raise TypeError("IPV4ReachState requires HostFormattedResponse "
                            "from reach_dns_hosts() method in Reacher class.")
        DNSHostGroupState.__init__(self, dnshosts_formatted_response)
        if dnshosts_formatted_response.get_response()['rr_types'][1] != "a":
            raise ValueError(f"dns answer does not indicate ipv4 ('a') according to the given rr_types: "
                             f"{dnshosts_formatted_response.get_response()['rr_types']}")

    def __repr__(self):
        return f"<IPV4ReachState: {self.domain}, {self.formatted_answer['rr_types']}>"

    def reach_test(self, require_connect=False):
        hosts_keys = list(self.formatted_answer['hosts'].keys())
        reached = {}
        unreached = {}

        for host in hosts_keys:
            pingable = self.formatted_answer['hosts'][host]['pingable']
            can_connect = self.formatted_answer['hosts'][host]['can_connect']

            if require_connect:
                if can_connect:
                    reached[host] = self.formatted_answer['hosts'][host]
                else:
                    unreached[host] = self.formatted_answer['hosts'][host]
            else:
                if can_connect or pingable:
                    reached[host] = self.formatted_answer['hosts'][host]
                else:
                    unreached[host] = self.formatted_answer['hosts'][host]

        return {'reached': reached, 'unreached': unreached}


class DNSSECState(DomainAuthenticityState):

    def __init__(self, formatted_response: DNSSECFormattedResponse):
        if not isinstance(formatted_response, DNSSECFormattedResponse):
            raise TypeError("DNSSECState requires a DNSSECFormattedResponse from dnssec_comprehensive() in Resolver "
                            "class.")
        super(DNSSECState, self).__init__(formatted_response)
        self.valid = False

        ips = list(formatted_response.get_response()['answer']['validation'].keys())

        for ip in ips:
            if formatted_response.get_response()['answer']['validation'][ip] != "secure":
                self.valid = False
                break
            self.valid = True


class DNSSECSignaturesState(DomainAuthenticityState):
    """Accepts a DNSSECSignaturesFormattedResponse from get_all_dnssec() in Resolver class & throws a TypeError
    exception otherwise. Contains all dns records for DNSSEC specified by RFC4035 & RFC4034 plus the SOA record
    specified by internet.nl.
    Inherits from: BaseState.
    Parent to: None.
    Sibling to: DNSSECValidatedState"""

    def __init__(self, dnssec_resolver_answer: DNSSECSignaturesFormattedResponse):
        if not isinstance(dnssec_resolver_answer, DNSSECSignaturesFormattedResponse):
            raise TypeError("DNSSECSignaturesState requires DNSSECSignaturesFormattedResponse "
                            "from get_all_dnssec() method in Resolver class.")
        BaseState.__init__(self, dnssec_resolver_answer)
        self.soa = self._load_soa()
        self.dnskey = self._load_dnskey()
        self.rrsig = self._load_rrsig()
        self.nsec = self._load_nsec()
        self.ds = self._load_ds()

    def _load_soa(self):
        return self.formatted_answer['answer'].get('soa')

    def _load_dnskey(self):
        return self.formatted_answer['answer']['dnskey']

    def _load_rrsig(self):
        return self.formatted_answer['answer']['rrsig']

    def _load_nsec(self):
        return self.formatted_answer['answer']['nsec']

    def _load_ds(self):
        return self.formatted_answer['answer']['ds']


class DNSSECValidatedState(DomainAuthenticityState):
    """Accepts a DNSSECValidatedFormattedResponse from validate_dnssec() in Resolver class & throws a TypeError
        exception otherwise. Contains the IPV4 address and a corresponding determination of 'secure', 'bogus', or
        'insecure'.
        note: a 'bogus' result seems to be a result in which DNSSEC is configured with a chain of trust except that the
        chain of trust is broken. For example, this can happen if the root trust anchor is not properly configured.
        Inherits from: BaseState.
        Parent to: None.
        Sibling to: DNSSECSignaturesState."""

    def __init__(self, dnssec_resolver_answer: DNSSECValidatedFormattedResponse):

        """[BLANK]State requires [BLANK]FormattedResponse from [BLANK]() method in [BLANK] class.."""
        if not isinstance(dnssec_resolver_answer, DNSSECValidatedFormattedResponse):
            raise TypeError("DNSSECValidatedState requires DNSSECValidatedFormattedResponse "
                            "from validate_dnssec() method in Resolver class.")
        super(DNSSECValidatedState, self).__init__(dnssec_resolver_answer)
        self.secure = self._load_secure()
        self.chain_of_trust_unbroken = self._load_chain_of_trust_unbroken()
        self.details = self.formatted_answer['answer']

    def _load_chain_of_trust_unbroken(self):
        ip_keys = list(self.formatted_answer['answer'].keys())

        for key in ip_keys:
            if self.formatted_answer['answer'][key] == "bogus":
                return False
            elif self.formatted_answer['answer'][key] == "secure":
                return True

        return None

    def _load_secure(self):
        ip_keys = list(self.formatted_answer['answer'].keys())

        for key in ip_keys:
            if self.formatted_answer['answer'][key] != "secure":
                return False
        return True

    def cot_unbroken(self):
        return self.chain_of_trust_unbroken

    def is_secure(self):
        return self.secure

    def get_details(self):
        return self.details


class DMARCState(DomainAuthenticityState):
    """Accepts a DMARCInspectorFormattedResponse obtained from inspect_dmarc() in DmarcianClient class & throws a
    TypeError exception otherwise.
    Inherits from: DomainAuthenticityState -> BaseState.
    Parent to: None.
    Sibling to: DKIMState, SPFState"""

    def __init__(self, formatted_answer: DMARCInspectorFormattedResponse):
        if not isinstance(formatted_answer, DMARCInspectorFormattedResponse):
            raise TypeError("DMARCState requires DMARCInspectorFormattedResponse from inspect_dmarc() in "
                            "DmarcianClient.")
        super(DMARCState, self).__init__(formatted_answer)
        self.valid = self.formatted_answer.get('valid')
        self.dns_query = self.formatted_answer.get('dns_query')


class DKIMState(DomainAuthenticityState):
    """Accepts a DKIMInspectorFormattedResponse obtained from inspect_dkim() in DmarcianClient class & throws a
        TypeError exception otherwise.
        Inherits from: DomainAuthenticityState -> BaseState.
        Parent to: None.
        Sibling to: DMARCState, SPFState"""

    def __init__(self, formatted_answer: DKIMInspectorFormattedResponse):

        if not isinstance(formatted_answer, DKIMInspectorFormattedResponse):
            raise TypeError("DKIMState requires DKIMInspectorFormattedResponse from inspect_dkim() in DmarcianClient.")

        super(DKIMState, self).__init__(formatted_answer)
        self.selector = self.formatted_answer.get('selector')
        self.query = self.formatted_answer.get('query')
        self.valid = self.formatted_answer.get('valid')


class SPFState(DomainAuthenticityState):
    """Accepts a SPFInspectorFormattedResponse obtained from inspect_dmarc() in DmarcianClient class & throws a
        TypeError exception otherwise.
        Inherits from: DomainAuthenticityState -> BaseState.
        Parent to: None.
        Sibling to: DKIMState, DMARCState"""

    def __init__(self, formatted_answer: SPFInspectorFormattedResponse):
        if not isinstance(formatted_answer, SPFInspectorFormattedResponse):
            raise TypeError("SPFState requires SPFInspectorFormattedResponse from inspect_spf() in DmarcianClient.")
        super(SPFState, self).__init__(formatted_answer)
        self.display_domain = self.formatted_answer.get('display_domain')
        self.valid = None

# end
