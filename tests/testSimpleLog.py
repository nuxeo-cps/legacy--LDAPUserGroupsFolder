#!/usr/bin/env python
#####################################################################
#
# testSimpleLog     Tests for the simple log mechanism
#
# This software is governed by a license. See
# LICENSE.txt for the terms of this license.
#
#####################################################################
__version__='$Revision$'[11:-2]

# General Python imports
import unittest

# LDAPUserFolder package imports
from SimpleLog import SimpleLog


class TestSimpleLog(unittest.TestCase):

    def setUp(self):
        self.log = SimpleLog()

    def testInstantiation(self):
        self.assertEqual(len(self.log.getLog()), 0)

    def testClearing(self):
        self.log.clear()
        self.assertEqual(len(self.log.getLog()), 1)

    def testLogging(self):
        self.log.log(1, 'Test Message')
        self.assertEqual(len(self.log.getLog()), 1)

    def testLogSizelimit(self):
        for i in range(0, 500):
            self.log.log(1, 'Message %i' % i)
        cur_log = self.log.getLog()
        self.assertEqual(len(cur_log), 500)
        self.assert_(cur_log[0].find('Message 0') != -1)
        self.assert_(cur_log[-1].find('Message 499') != -1)
        self.log.log(1, 'Message 500')
        cur_log = self.log.getLog()
        self.assertEqual(len(cur_log), 500)
        self.assert_(cur_log[0].find('Message 1') != -1)
        self.assert_(cur_log[-1].find('Message 500') != -1)


def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestSimpleLog))

    return suite

if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')
    
