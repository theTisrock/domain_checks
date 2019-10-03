from tools.domain_state import BaseState, DNSHostGroupState, IPV6ExistState, IPV4ExistState, IPV6ReachState, IPV4ReachState

from tools.tests import FunctionalTestCase

class BaseStateTestCase(FunctionalTestCase):
    """
    test the states
    """

    def test_create(self):
        answer = {'domain': 'domain.com'}
        state = BaseState(answer)
        self.assertEqual(state.domain, 'domain.com')

class DNSHostGroupState(FunctionalTestCase):
    def test_create(self):
        pass