# Holds the formatted responses. They use to be stored with their corresponding functionality. 
# Showing the connection to the corresponding functionality will be the goal of the documentation of all formatted responses classed here.

# Formatted responses are made for use inside a Python environment. To unpack any formatted response, simply use the
# FR.get_response() method to get the raw underlying dictionary.

# The alternative response for any method here should be JSON.


# generic
class FormattedResponse(object):

    def __init__(self, dns_response):
        self.response = dns_response

    def get_response(self):
        return self.response


# pure dns responses
class DNSFormattedResponse(FormattedResponse):
    """
    Represents a simple dns query look up, typically for a single record. For example, A records or AAAA records or NS
    Records, etc. DNSSEC records are also simple records, but are subclassed under DNSSECFormattedResponse.
    Inherits from: object.
    Parent to: DNSSECFormattedResponse, DNSSECSignaturesFormattedResponse, DNSSECValidatedFormatteResponse.
    Sibling to: None.
    """

    def __init__(self, formatted_response: dict):
        super(DNSFormattedResponse, self).__init__(formatted_response)


class DNSHostMappingFormattedResponse(DNSFormattedResponse):
    """
    A wrapper class used to contain a response that maps a host type ('ns', 'mx', etc) to an ip address.
    Inherits from: DNSFormattedResponse
    Parent to: None.
    Sibling to: DNSSECFormattedResponse
    """

    def __init__(self, dns_host_mapping_response):
        super(DNSHostMappingFormattedResponse, self).__init__(dns_host_mapping_response)


# host responses
class HostFormattedResponse(FormattedResponse):
    """Wrapper to encapsulate host response. This response comes from reach_dns_hosts() in Reacher class."""

    def __init__(self, host_formatted_response: dict):
        super(HostFormattedResponse, self).__init__(host_formatted_response)


# domain authenticity responses
class DomainAuthenticityFormattedResponse(DNSFormattedResponse):

    def __init__(self, formatted_response):
        super(DomainAuthenticityFormattedResponse, self).__init__(formatted_response)


class DmarcianFormattedResponse(FormattedResponse):

    def __init__(self, formatted_response: dict):
        super(DmarcianFormattedResponse, self).__init__(formatted_response)


class DNSSECFormattedResponse(DomainAuthenticityFormattedResponse):
    """
    Acts as an umbrella wrapper class to subsequent DNSSEC response classes.
    Inherits from: DNSFormattedResponse.
    Parent to: DNSSECSignaturesFormattedResponse, DNSSECValidatedFormattedResponse.
    Sibling to: DNSHostMappingFormattedResponse.
    """

    def __init__(self, dnssec_response):
        super(DNSSECFormattedResponse, self).__init__(dnssec_response)


class DMARCInspectorFormattedResponse(DmarcianFormattedResponse):

    def __init__(self, formatted_response: dict):
        super(DMARCInspectorFormattedResponse, self).__init__(formatted_response)


class DKIMInspectorFormattedResponse(DmarcianFormattedResponse):

    def __init__(self, formatted_response: dict):
        super(DKIMInspectorFormattedResponse, self).__init__(formatted_response)


class SPFInspectorFormattedResponse(DmarcianFormattedResponse):

    def __init__(self, formatted_response: dict):
        super(SPFInspectorFormattedResponse, self).__init__(formatted_response)


class DNSSECSignaturesFormattedResponse(DNSSECFormattedResponse):
    """
    A wrapper class for a DNSSEC Signature answers from dns. Used in get_all_dnssec() in Resolver class.
    Inherits from: DNSSECFormattedResponse -> DNSFormattedResponse
    Parent to: None.
    Sibling to: DNSSECValidatedFormattedResponse.
    """

    def __init__(self, dnssec_sigs):
        super(DNSSECSignaturesFormattedResponse, self).__init__(dnssec_sigs)


class DNSSECValidatedFormattedResponse(DNSSECFormattedResponse):
    """
    A wrapper class for a DNSSEC Validated answers from dns. Used in validate_dnssec() in Resolver class.
    Inherits from: DNSSECFormattedResponse -> DNSFormattedResponse
    Parent to: None.
    Sibling to: DNSSECSignaturesFormattedResponse.
    """

    def __init__(self, dnssec_validation):
        super(DNSSECValidatedFormattedResponse, self).__init__(dnssec_validation)
