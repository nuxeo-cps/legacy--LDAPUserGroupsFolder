# Copyright (c) 2005 Nuxeo SAS <http://nuxeo.com>
# Author: Florent Guillaume <fg@nuxeo.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#
# $Id$
"""LDAPUserGroupsFolder import/export for CMFSetup.
"""
import unittest

from Products.LDAPUserGroupsFolder.setup import LDAPURL_RE

def check(s):
    return LDAPURL_RE.match(s).groups()

class TestRE(unittest.TestCase):
    def test_1(self):
        self.assertEquals(check('ldap://foo:389'),
                          ('ldap', 'foo', '389'))
    def test_2(self):
        self.assertEquals(check('ldap://foo:389/'),
                          ('ldap', 'foo', '389'))
    def test_3(self):
        self.assertEquals(check('ldap://foo'),
                          ('ldap', 'foo', ''))
    def test_4(self):
        self.assertEquals(check('ldap://foo/'),
                          ('ldap', 'foo', ''))
    def test_5(self):
        self.assertEquals(check('ldap://foo/bar'),
                          ('ldap', 'foo', ''))
    def test_6(self):
        self.assertEquals(check('ldap://foo:123/bar'),
                          ('ldap', 'foo', '123'))
    def test_7(self):
        self.assertEquals(check('ldaps://foo:123'),
                          ('ldaps', 'foo', '123'))
    def test_8(self):
        self.assertEquals(LDAPURL_RE.match('bahldap://foo'), None)


def test_suite():
    suite = unittest.TestSuite((
        unittest.makeSuite(TestRE),
        ))
    return suite

if __name__ == '__main__':
    TestRunner().run(test_suite())
