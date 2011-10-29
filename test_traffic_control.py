#!/usr/bin/env python
# encoding: utf-8
"""
test_traffic_control.py

Created by 4Aiur on 2011-05-31.
"""

import unittest
import traffic_control


class test_traffic_control(unittest.TestCase):

    def setUp(self):
        self.tc = traffic_control.TrafficControl()

    def test_get_class_id(self):
        self.assertEqual(self.tc.get_class_id(u"1Mbit"), u"10")
        self.assertEqual(self.tc.get_class_id(u"2Mbit"), u"15")
        self.assertEqual(self.tc.get_class_id(u"3Mbit"), u"20")
        self.assertEqual(self.tc.get_class_id(u"4Mbit"), u"25")
        self.assertNotEqual(self.tc.get_class_id(u"4Mbit"), u"10")
        self.assertNotEqual(self.tc.get_class_id(u"5Mbit"), u"10")

    def test_add_filter(self):
        self.assertEqual(self.tc.add_filter( "1.2.3.4", "eth0", "1Mbit"), None)
        self.assertEqual(self.tc.add_filter( "1.2.3.7", "eth0", "10Mbit"), None)
        self.assertEqual(self.tc.add_filter( "1.2.3.8", "eth0", "10Mbit"), None)
        return

    def test_show_filter(self):
        self.assertEqual(self.tc.show_filter("1.2.3.4"), None)
        self.assertRaises(ValueError, self.tc.show_filter, 'foo')

    def test_delete_filter(self):
        self.assertEqual(self.tc.delete_filter("1.2.3.4"), None)
        self.assertEqual(self.tc.delete_filter("1.2.3.9"), None)


if __name__ == '__main__':
    unittest.main()
