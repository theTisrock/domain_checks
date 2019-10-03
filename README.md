# domain_checks
Uses Unbound DNS Resolver to perform DNS record checks &amp; host connectivity checks.

1) Fetching

There are 3 main classes that are responsible for fetching responses over the web: dns_resolver.py/Resolver, dmarcian_api_client.py/DmarcianClient, & ip_reachable.py/Reacher.
Note: all fetching class methods have been given a JSON response object as an option.

2) Formatted Responses

There are numerous Formatted Response classes that allow the programmer to know, especially when working in a Python shell, which 'Fetcher' the response came from and also tell which state the responses can be stored within. The FR's are made to be inserted into their corresponding 'States'. 

3) States

Numerous state classes were constructed to represent the state of a given aspect of a domain. For instance, there is an IPV6ExistenceState that shows mailservers or nameservers and their corresponding IP version 6 addresses. A state accepts a Formatted Response type and ONLY that type. For example, you cannot store anything other than an DNSHostMappingFormattedResponse in an IPV6ExistenceState; otherwise, a TypeError will occur. 

Domain Checker service - 

This acts as the top level driver class to be instantiated as a singleton. It encapsulates all of the previously mentioned decoupled components into one convenient class. When a method is called, it returns the appropriate state that is being queried. 
