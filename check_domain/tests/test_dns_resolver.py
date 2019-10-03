import unittest
from project.tools.dns_resolvers import Resolver, DNSFormattedResponse


class TestDNSResponseFormat(unittest.TestCase):

    def test__init__(self):
        r = Resolver()
        self.assertTrue(isinstance(r, Resolver))

    def test_get_a_records(self):
        r = Resolver()
        expected = {
            'domain': "google.com", 'rr_types': ["a"],
            'answer': {0: "74.125.196.101", 1: "74.125.196.139", 2: "74.125.196.138", 3: "74.125.196.102",
                       4: "74.125.196.100", 5: "74.125.196.113"}
        }
        self.assertEqual(expected['domain'], r.get_a_records("google.com").get_response()['domain'])
        self.assertEqual(expected['rr_types'], r.get_a_records("google.com").get_response()['rr_types'])
        expected_key = list(expected['answer'].keys())[0]
        actual_key = list(r.get_a_records("google.com").get_response()['answer'].keys())[0]
        self.assertEqual(expected_key, actual_key)  # correct key and its type.
        expected_val_type = str
        actual_val_type = type(list(r.get_a_records("google.com").get_response()['answer'].values())[0])
        self.assertEqual(expected_val_type, actual_val_type)  # correct val and type; google rotates ip addresses
        expected['domain'] = "ns-1394.awsdns-46.org."
        expected['rr_types'] = ["a"]
        expected['answer'] = {0: "205.251.197.114"}
        self.assertEqual(expected, r.get_a_records("ns-1394.awsdns-46.org.").get_response())
        expected['domain'] = "kaljfnotexists.org"
        expected['answer'] = None
        self.assertEqual(expected, r.get_a_records("kaljfnotexists.org").get_response())

    def test_get_aaaa_records(self):
        r = Resolver()
        expected = {'domain': "ns-439.awsdns-54.com.", 'rr_types': ["aaaa"],
                    'answer': {0: "2600:9000:5301:b700:0:0:0:1"}}
        actual = r.get_aaaa_records("ns-439.awsdns-54.com.").get_response()
        self.assertEqual(expected['domain'], actual['domain'])  # has ipv6
        self.assertEqual(expected['rr_types'], actual['rr_types'])
        self.assertEqual(expected['answer'], actual['answer'])
        expected = {'domain': "gvlswing.com", 'rr_types': ["aaaa"],
                    'answer': None}
        self.assertEqual(expected, r.get_aaaa_records("gvlswing.com").get_response())  # no ipv6
        expected['domain'] = "ljlkjsafdnotexistskljsdl.com"
        self.assertEqual(expected, r.get_aaaa_records("ljlkjsafdnotexistskljsdl.com").get_response())  # not exists

    # def test_get_aaaa_bytes(self, target):
    #     pass

    def test_get_soa(self):
        r = Resolver()
        expected = {'domain': "interdc.nl.", 'rr_types': ["soa"],
                    'answer':
                        {0: str(b'\x03ns1\nicehosting\x02nl\x00\nhostmaster\x07interdc\x02nl\x00xX\xbc\xba\x00\x008@'
                                b'\x00\x00\x0e\x10\x00\x12u\x00\x00\x01Q\x80')}
                    }
        self.assertEqual(expected, r.get_soa("interdc.nl.").get_response())
        expected['domain'] = "kjlasjkasdnotexistslkjalf.com"
        expected['answer'] = None
        self.assertEqual(expected, r.get_soa("kjlasjkasdnotexistslkjalf.com").get_response())

    def test_get_ns(self):
        r = Resolver()
        expected = {'domain': "gvlswing.com", 'rr_types': ["ns"],
                    'answer': {0: "ns-1394.awsdns-46.org.", 1: "ns-1582.awsdns-05.co.uk.", 2: "ns-439.awsdns-54.com.",
                               3: "ns-812.awsdns-37.net."}}
        self.assertEqual(expected, r.get_ns("gvlswing.com").get_response())

    def test_get_mx(self):
        r = Resolver()
        expected = {'domain': "gmail.com", 'rr_types': ["mx"],
                    'answer': {0: "alt1.gmail-smtp-in.l.google.com.", 1: "alt3.gmail-smtp-in.l.google.com.",
                               2: "alt2.gmail-smtp-in.l.google.com.", 3: "alt4.gmail-smtp-in.l.google.com.",
                               4: "gmail-smtp-in.l.google.com."}}
        expected_mx_set = set(expected['answer'].values())
        actual_mx_set = set(r.get_mx("gmail.com").get_response()['answer'].values())
        self.assertEqual(expected_mx_set, actual_mx_set)  # test correct mx elements
        self.assertEqual(expected['domain'], r.get_mx("gmail.com").get_response()['domain'])
        self.assertEqual(expected['rr_types'], r.get_mx("gmail.com").get_response()['rr_types'])
        expected['domain'] = "gvlswing.com"
        expected['answer'] = None
        self.assertEqual(expected, r.get_mx("gvlswing.com").get_response())  # mx not exists

    # methods below this line use unbound indirectly. They use methods in this class as their dependencies.
    def test_get_ipv6bytes_list(self):  # may deprecate
        pass

    def test_ns_list_to_ipv6str(self):  # may deprecate
        pass

    def test_get_ipv6(self):
        r = Resolver()
        expected = {'domain': "gvlswing.com", 'rr_types': ["ns", "aaaa"],
                    'answer': {'ns-812.awsdns-37.net.': "2600:9000:5303:2c00:0:0:0:1",
                               'ns-439.awsdns-54.com.': "2600:9000:5301:b700:0:0:0:1",
                               'ns-1582.awsdns-05.co.uk.': "2600:9000:5306:2e00:0:0:0:1",
                               'ns-1394.awsdns-46.org.': "2600:9000:5305:7200:0:0:0:1"}}
        self.assertEqual(expected, r.get_ipv6("gvlswing.com", "ns").get_response())

    def test_mx_list_to_ipv6bytes(self):  # may deprecate
        pass

    # dnssec records types
    def test_get_dnskeys(self):
        r = Resolver()
        expected = {'domain': "interdc.nl", 'rr_types': ["dnskey"],
                    'answer': {
                        0: b'\x01\x01\x03\x08\x03\x01\x00\x01\xc9\xeaL\x01\xc8\x16nQ\x9d\xb2\x94\xb1\xc1TH\x9cC\xf8[\xfa%^\xaen\x07C3\xb0\x8b\xd5i\\\xd4\x17\xa2\xfd\xd0\xe6d\xba\xb6\xb8P\xe9\xfe\x18\xcbm~\xa3\xd6\\\x1b\xa0HN5\xb9\x18\xf8\x1e\xdd\x08+\xe3W`P\x16B\x03\xed\xfes\xd0m\xae|\x90D0\\\x7fgU\x17B\x93\xc5\x85#\xbd\x87\x95\x1e\x96\x93\xc89\xc1\x82\xc6\x8di\x92\xd7\xd3E\x0e\xdd\x91H\x1a\xbf\x15L\xd4Wl\xed\xcb\x1e\x1a\x8c\x9a)\xec\xd5J\x8d\xc8\xcf\xcd\x8fC\x1f\xffb\xb4/\xc2Q\x9e\xaf\x1b\x0e\xc5\xf9/\x0f\xfcE\xd5\x01x\x19Q\xcd\xc2\xa2\xf4\xfd\xc8\x8b\xf9\x07\xaef=\xa5\xaeya\xf3z?c\x1fn\x8d\xa4f7\x0be\xac\x94\xee\x93\xf3\x86\xab\x93\xb5\xef\x88y{?\xfa\xe9\xf4\xb5M\xbe\xf3\x94\n\xa8\x03\x90\x1b*\xd7\x1e\xc5\x08=\x91\xe6\x13>#5\x7f\xfdY\xe0\x14\xe0\xc7\xd2\x95\x14C\xdcrv\x97M\xf8\xad\x8ef:(\xcb\x9d\xe5i}\x85\x1e\xa1\x15\x9f',
                        1: b'\x01\x00\x03\x08\x03\x01\x00\x01\xba\xfc\xb6\x00\xe9z\x83\xa7\xe0l\xd6\x06\xa5#c\xb4i\x12\n\x92\xc5\x88JD9\x89uV\xf7\xe8i\xfb\xa2V\x7f\x84N9\xf9k\x15g\xd4\xa8\xf3C\x84\x9f\xcc\xd9%8\x14\x07U\xd6\xd0\x08\xc2\xa5){>\xb7\xb5\xf4\xb8\x1f\tdE\x92U\x84h\xba\xac\xf5a\x97\xde\x0f\xa2\xccw\x1a\xf3TB;c:K\xb2b\xe2\xc0\xf3\xe3\x1d\xe6\x85T\xf6\xab\xae\xdeU\xe7\xbb\xc1\x8d\xdb?\x8aa\xb9K\xfb_\x1fgG\xed\x1e\xf7]g',}
                    }
        self.assertEqual(expected, r.get_dnskeys("interdc.nl").get_response())  # has dnskeys
        expected['domain'] = "gvlswing.com"
        expected['answer'] = None
        self.assertEqual(expected, r.get_dnskeys("gvlswing.com").get_response())  # no dnskeys

    def test_get_rrsigs(self):
        r = Resolver()
        expected = {
            'domain': "interdc.nl",
            'rr_types': ["rrsig"],
            'answer': {
                0: b'\x00\x06\x08\x02\x00\x008@]\x82%(]T\x00\xa84\xf8\x07interdc\x02nl\x001['
                       b'C\xd9_VlI\x00c\x0f\x04Mp\xdb\x06!\x96\x11bH\x1f\x88\xeb\xf2\x1c\x19_i\x85'
                       b"\xfb4,';APX\xcc\xc5\xfd.\xf1\x99/&PR\xbf,d\xbbK\xd9\xc3\xfe\xa6C\xdd6xG"
                       b'j\x83\x9ew\x87\xb0\xaeq\xa2\xb8\x8f\xae3\x07\x87\x15A\xde\xf1<\xdc\xf1\xb3S'
                       b'\xcb\x87\x99\xe7\x06\xb2\xd9_\x84\x0c\xb3c\xd3\x07\xa3\xf7eV8\xc6'
                       b'\x00\xae\x81\xd8L\x11@\xd9\xabn8\xf9\xea\xcf\x08\xde\x99\xbe\x07\xce$M',  # end

                1: b'\x00\x02\x08\x02\x00\x008@]\x82%(]T\x00\xa84\xf8\x07interdc\x02nl\x00L\xad'
                       b'\x13z\x90,\tU,\xb87\xbb]\xc5\xf5\x8e|@\x7f\xe6\xe0\x17Vl8#\x0c\xf77\xc7'
                       b'\x01\xd9\xd1\x93\xc4\xf2\xbfu\x82-s\xa87\x0e\xbdA\x8a\xe7~ \xa5\x14.,'
                       b"[\xb3K\xa7\x99-\xcd\xa9\xd1\xc2(\x91\xac\xb7m\r\xd4\xa8\x91\x0bJ\x81'4"
                       b'\xd5n:D\xe3*\x87m\xd9\xcdAGe\x80\xc6e\x89\x87\xca\xed&\x90h+s\xf6R\xa6'
                       b'\x99\x02T\x14H0Ksk\xe5\xec\xfa\xe0\xa2/\xde\x1e\xf7\xe2H5\xa9',  # end
                2: b'\x00\x01\x08\x02\x00\x008@]\x82%(]T\x00\xa84\xf8\x07interdc\x02n'
                       b'l\x00\xb0\xf7\xa9\xaeU\xe4\x04\xe5\xc2x\xa1D\xf9P\xdb\x1d\xd70y\xaaj%'
                       b'f\xea\xb4\x8bV\x90dF\xa7\x17\x05\x18\x8a\x93\x1bPo\xdb\xfd\x85\xda"\x8a\xa4'
                       b'F[\xff\xe0\x85\xb8z4\x92#)\x8dX\n@m\xee\xb8\xb1@\xb7\xc77\t9\xa0d\x0c'
                       b'8\x81I\x80t\tj}k\x93\xfd\xf2\xf0\x10\xbe\xaa0\xb2\xe0\xbelM\x90\x9f'
                       b'\x03\x17o\xc7\x02\xd0`\xeeb\x17>5\x8d]\x02\xb8\xd6\xcb\xae\xad\x1a"?\x88'
                       b'\xa9\xc7AX\x18\x15',  # end
                3: b'\x00\x0f\x08\x02\x00\x008@]\x82%(]T\x00\xa84\xf8\x07interdc\x02nl\x00d\x13'
                       b'\xf3\xdcN\xbb\xde\x87\xb3\xe8%\xf4r\x9e\x07k\x0c\x15|eDA\xdau\xc2\x80'
                       b'j\x1fF\x06{5 -\xca\x8f\x06n;\xc4sw\x9b\xf0\xd1\x02\xaeT\xef\xf3S#\x94\x93'
                       b'\x0c}$0\xca\x11MR#\xe6\x80\x87\x1a\xb0N\x96O5\x8c\xe6V\x12TA\xf4\xd5\xac\xbc'
                       b'J\xce\x19\x83\x88\xa7\xaeVEn\xfa\xfcD\n\xf1\xc3\x08\x99\x7f\x1eZ\xab\xc6,'
                       b'\xd5\xbe\xa4f9y\xf6J{\xb1\x03\xbf\x02\x98C\xed\xf6\xcd\x04\x08\xd7L',  # end
                4: b'\x00\x10\x08\x02\x00\x008@]\x82%(]T\x00\xa84\xf8\x07interdc\x02n'
                       b'l\x00\x9d\x18~\xd0\x10\xd4\xceD\x858\xa4|\xd0\x8d\x01\xe3\xa0_\xb8s\x1cc'
                       b'\n_\xa1\x9c\xe0\xfdh\x8d\xf5 l\xe5\xae2JH\xec\x0f\x8a\x03\xb7d\xc3\x04'
                       b'\xfcN\xe6@\x89}$\xa5$\xff\xf4A\xe0\xba\x02\tc\xd2;\xdf\x93sY\xc3'
                       b'\xcdW\x11\xbd\xde:\xfdmt\xa7\x98-\xd0oBt\xeb\x94\xdc`y\x0eC\xd8S)[\x04'
                       b'\x8f\x94/y\x99\xc5\x991\x99qp\xc1\xa7\x17h\xd4\xfd\x06\xbd\xbch\xec\xdd\xd8'
                       b'\xde\x9a\x91\xd4\xa2\xae',  # end
                5: b'\x00\x1c\x08\x02\x00\x008@]\x82%(]T\x00\xa84\xf8\x07interdc\x02n'
                       b'l\x00\xa8\x91\x1f\x1a\xadu] \xea\x03\xcf\x82\x13c\xa1$}0\x996\xf4\xf6'
                       b"\x16\x1b\xdb\x1eY4\xcb'\x1a\x0c\xbd\xec\x05/T\xec\xcf'\x87\x1e;\xac\xc7\xbf"
                       b'\xe0X\xfb\xac\x06\xc3Y\x0ea\xc8\xac\x95\xd8\x88\xe9\xd6\xec<\x17\xff'
                       b'\x9eN\xe3NJ\xed\x06m\x9c\xc9-G\xca\x03\xd5\xba\r\xc4\xa8\xaa\\\x84\xd48'
                       b'\x0e\xb8\rb\xecXh\x14.\xc9\x15o\xdev\xedYal\x8b\xd1#I\x01\xf4\xbb\x80?I'
                       b'F\x95>i_\x01u\xeclj',  # end
                6: b'\x00/\x08\x02\x00\x01Q\x80]\x82%(]T\x00\xa84\xf8\x07interdc\x02nl\x00/\xa9'
                       b'\x97<\xcbe\xbe8\xcc.\xca\xae \xf4\xaax\x0e+\x82\x89E\xb6V\xfb\x8bc'
                       b'z\xd1\xa2\xf0\x154\x1a\xcd\xf7\xd8\xca\x9ba\xbf\xca\xb7\xff\xe8\x98\x13'
                       b"\xbe\xc6'\r\xbe\x1d\x0ee\x8ez+\x15H\r\nog\xf7\xc6\xdd\x95\xe1(a\xc4E(\x01"
                       b'@xvF\xde\xd83p\x13\x0ei\xa1_\xbf`\xd8z\x94\xb4B\xa90Fc\x02\xe2\x05\xb5'
                       b' \xb8\xc3\xdf\x1f\x99L\xf4\xe2\x96\xec?\xac\xae\xc6\x10\xb1\xab\x1dO'
                       b'\xed\x1d&\x9c\xeb\x9f',  # end
                7: b'\x000\x08\x02\x00\x008@]\x82%(]T\x00\xa84\xf8\x07interdc\x02nl\x00F*'
                       b'6\xa1i\x02\x08%\xcb\xb6+\xf2\xf7\x08f\xd1_<\x16\xda\xadz\xc6d\x92#'
                       b'\xe9\x1b\xdc\xa6R\xdd\xd0@\x0b<\xfb/\x04\x01m\xc2\xed;\x8eB\xc7>\x15\xd3'
                       b'\xd1\xae\xc5%\x04}YH\xb6~\x0c\xa4}\\x\x9a\x89\x82\x88Gz\x1d\x83\xfc'
                       b'\x86\x92\xc7\x1d\xe6\x9a\xa5\xc8k\x92\xa1\xde\x8c\x87\xfe\xa9\x81\xfbz\xcb'
                       b'\xab\xc9\xda\xdc.)\xd1-\xb0\x8e\xc3\xa6o\xb3\x0c\x83\xe0\x02\xa9\xfa'
                       b'@\xd7}\x9d\xa5d\x81\xfeY[\x1drD[',  # end
                8: b'\x000\x08\x02\x00\x008@]\x82%(]T\x00\xa8\xb92\x07interdc\x02nl\x00\xa1\xeb'
                       b'\x10\n\xf5,\xac\x90\xb8\xbcA\x027\xdexB\x01\xc1\xf6)\xc0D}\xa5?\x16'
                       b'\xe8A\xe6\x1bs\xc6T\xae\xfb\xd9\xf0\xed\xb4\x1e~\xae\xb4\x06Ip\xc3S\x8b\xcc'
                       b'p`\x1a\x0e=\xe5\x1f\xa9\xfd\xd0B\xe7\xf5\xff\x8f\xb2\x17`-=\xe3(\xe5O'
                       b'\xb0V}\x9f\xe7\xf7\xc5jb\xa7\t\x1c\xa6\xb4\x06\xd0\xb6\xce\xb0U\xb2O\x85\xa2'
                       b'\x05\xe2\xa5\xb9N\xa2"{\xc6\xf2y\'\xa9{a\x1aS5\x0f\xce|\xf9\xd4m'
                       b'\xa0C\x93\xeeEw\x89\x051\xf9kfC\x9b\xc7\xbex\x8aB\x04\rH\xde7\xc1\xbb8\x94'
                       b'\x98vU\xe5Q\xaf*\xbcX\n\xbb\xf1\xf74\x06\xd20\xb3]\x85\x18\xda\x03\xd7'
                       b'\xa5\xb1\x18\xe1U\xac\xe9/\xf8\x06I\x92\xf2#\xd2\n\x97\xcc\x90J'
                       b'\xac\xad\x0e\x08\xbf9xEN\xa1\x94\xe2\x89\xe5D%[*\x0e\xf8P\xe1\xcb\xcc'
                       b'\xe3\xba\xa5\x1a1"\xe1\xba\xbd\x15#\xc1\xfa\x1e\x1d\xd6\xa4f\xe2\xa4'
                       b'\xc06\xc2\x7f\xbb\xaa\x16\xda\xc2\xd8\x1a\x00]\x17\x1aS\x1e\xeb'
            }
        }
        self.assertEqual(expected, r.get_rrsigs("interdc.nl").get_response())  # has rr sigs
        expected['domain'] = "gvlswing.com"
        expected['answer'] = None
        self.assertEqual(expected, r.get_rrsigs("gvlswing.com").get_response())  # no rr sigs

    def test_get_ds(self):
        r = Resolver()
        expected = {'domain': "interdc.nl", 'rr_types': ["ds"],
                    'answer': {0: b'\xb92\x08\x02\x97\x19\xc6\xfa\xae-}f\xc9\x80\x9b\\\xbdr\x9e8pm\x1f\xbd'
                                      b'\xd4\xa1\xf5\x97\xe7a\x08\xd18j\xc3\x8c'}}
        self.assertEqual(expected, r.get_ds("interdc.nl").get_response())  # has ds
        expected['domain'] = "gvlswing.com"
        expected['answer'] = None
        self.assertEqual(expected, r.get_ds("gvlswing.com").get_response())  # no ds

    def test_get_nsec(self):
        r = Resolver()
        expected = {'domain': "interdc.nl", 'rr_types': ["nsec"],
                    'answer': {0: b'\x06_dmarc\x07interdc\x02nl\x00\x00\x07b\x01\x80\x08\x00\x03\x80'}}
        self.assertEqual(expected, r.get_nsec("interdc.nl").get_response())
        expected['domain'] = "gvlswing.com"
        expected['answer'] = None
        self.assertEqual(expected, r.get_nsec("gvlswing.com").get_response())

    def test_validate_dnssec(self):
        r = Resolver()
        expected = {'domain': "interdc.nl", 'rr_types': ["a", "dnssec"], 'answer': {'195.22.100.12': "secure"}}
        self.assertEqual(expected, r.dnssec_validate("interdc.nl").get_response())
        expected['domain'] = "gvlswing.com"
        expected['answer'] = {'52.33.238.38': "insecure"}
        self.assertEqual(expected, r.dnssec_validate("gvlswing.com").get_response())
