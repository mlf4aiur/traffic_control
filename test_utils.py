#!/usr/bin/env python
# encoding: utf-8
"""
test_utils.py

Created by 4Aiur on 2011-05-18.
"""

import unittest
import utils


class ConvertIPTests(unittest.TestCase):

    def setUp(self):
        self.convert_ip = utils.ConvertIP()

    def test_ip2hex(self):
        self.assertEqual(self.convert_ip.ip2hex('1.2.3.255'), '010203ff')
        self.assertRaises(ValueError, self.convert_ip.ip2hex, '1.2.3.255.1')

    def test_hex2ip(self):
        self.assertEqual(self.convert_ip.hex2ip('01020304'), '1.2.3.4')
        self.assertEqual(self.convert_ip.hex2ip('010203ff'), '1.2.3.255')
        self.assertEqual(self.convert_ip.hex2ip('7b7d9e70'), '123.125.158.112')
        self.assertNotEqual(self.convert_ip.hex2ip('010203ff'), '1.2.3.25')


if __name__ == '__main__':
    unittest.main()
