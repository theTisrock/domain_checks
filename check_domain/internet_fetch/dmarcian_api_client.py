import requests
from ..formatted_response import DMARCInspectorFormattedResponse, DKIMInspectorFormattedResponse  # client objects produce formatted response types
from ..formatted_response import SPFInspectorFormattedResponse

TOKEN = "some_token_hash"
BASE_URL = "https://us.dmarcian.com/api/"


class RootClientBase(object):
    """
    Obtains the root endpoint for all subsequent, publicly exposed API endpoints for navigation. Contains generic methods for performing requests.
    Loads the api token, base url, constructs the base headers, and root routes/endpoints.
    """

    def __init__(self, base_url: str, token: str):
        self.base_url = base_url
        self.token = token
        self.headers = {'Authorization': f"Token {token}"}
        self.root = self._load_endpoints()

    def _load_endpoints(self):
        response = requests.get("https://us.dmarcian.com/api/", headers=self.headers)
        return response.json()

    def get_request(self, url: str):
        response = requests.get(url, headers=self.headers)
        return response.json()

    def post_request(self, url: str, post_data: dict):
        response = requests.post(url=url, headers=self.headers, json=post_data)
        return response.json()


class DmarcianClient(RootClientBase):
    """
    Inherits from RootClientBase all token, root endpoint, and basic header info needed to perform queries.
    Also contains dmarc, spf, and dkim specific api endpoints to dmarcian api.
    """

    def __init__(self, base_url: str, token: str):
        RootClientBase.__init__(self, base_url=base_url, token=token)
        self.dmarc = {'inspect': self.root['dmarc_inspector'],
                      'validate': self.root['dmarc_validator']}
        # spf and dkim endpoints not found in api endpoints documentation at root level
        self.spf = {'inspect': "https://us.dmarcian.com/api/spf/inspect/",
                    'validate': "https://us.dmarcian.com/api/spf/validate/"}
        self.dkim = {'inspect': "https://us.dmarcian.com/api/dkim/inspect/",
                     'validate': "https://us.dmarcian.com/api/dkim/validate/"}

    def inspect_dmarc(self, domain: str):
        """
        Inspects a dmarc record on a domain via dmarcian API. A DMARCInspectorFormattedResponse is returned.
        """
        request_data = {'domain': domain}
        response = self.post_request(self.dmarc['inspect'], request_data)
        return DMARCInspectorFormattedResponse(response)

    def inspect_dkim(self, domain: str, selector: str):
        """
        Inspects a dkim record on a domain using a selector via dmarcian API.
        A DKIMInspectorFormattedResponse is returned.
        """
        request_data = {'domain': domain, 'selector': selector}
        response = self.post_request(self.dkim['inspect'], request_data)
        return DKIMInspectorFormattedResponse(response)

    def inspect_spf(self, domain):
        """Inspects an spf record on a domain via dmarcian API. A SPFInspectorFormattedResponse is returned."""
        request_data = {'domain': domain}
        response = self.post_request(self.spf['inspect'], request_data)
        return SPFInspectorFormattedResponse(response)

# end

