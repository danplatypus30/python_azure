import unittest
import domaincheck.domain_checker as dc


class TestDomainCheckerPunyCode(unittest.TestCase):
    def test_puny(self):
        self.assertTrue(dc.check_domain_punycode('ünchen.com'))
    def test_puny_slash(self):
        self.assertTrue(dc.check_domain_punycode('ünchen.com/'))
    def test_puny_slash_param(self):
        self.assertTrue(dc.check_domain_punycode('ünchen.com/ünchen'))
    def test_https_puny_slash_param(self):
        self.assertTrue(dc.check_domain_punycode('https://München.com/Mün'))
    def test_https_nopuny(self):
        self.assertFalse(dc.check_domain_punycode('https://Munchen.com/Mun'))


class TestVirusTotal(unittest.TestCase):
    def test_malicious_host(self):
        self.assertTrue(dc.retrieve_vt_analysis_stats('freecontent.science')['malicious'] > 2)
    def test_harmless_host(self):
        self.assertFalse(dc.retrieve_vt_analysis_stats('google.com')['malicious'] > 2)


class TestURLInBlocklist(unittest.TestCase):
    def test_in_blocklist(self):
        self.assertTrue(dc.check_url_in_blocklist('00capital0neservice.000webhostapp.com'))
    def test_not_in_blocklist(self):
        self.assertFalse(dc.check_url_in_blocklist('www.google.com'))


class TestWHOISCreationDate(unittest.TestCase):
    def test_less_than_year_old(self):
        self.assertTrue(dc.retrieve_whois('eqq3.com'))
    def test_greater_than_year_old(self):
        self.assertFalse(dc.retrieve_whois('www.google.com'))

        
# if __name__ == '__main__':
#     unittest.main()