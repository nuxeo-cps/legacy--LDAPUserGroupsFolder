#!/usr/bin/env python
#####################################################################
#
# testLDAPUser    Tests for the LDAPUser class
#
# This software is governed by a license. See
# LICENSE.txt for the terms of this license.
#
#####################################################################
__version__='$Revision$'[11:-2]

# General Python imports
import unittest
from types import ListType, TupleType

# Zope imports
import ZODB

# LDAPUserFolder package imports
from LDAPUser import LDAPUser

# Tests imports
from config import user, defaults
ug = user.get
dg = defaults.get

class TestLDAPUser(unittest.TestCase):

    def setUp(self):
        self.u_ob = LDAPUser( ug('cn')
                            , ug('user_pw')
                            , ug('user_roles')
                            , []
                            , 'cn=%s,%s' % (ug('cn'), dg('users_base'))
                            , { 'cn' : [ug('cn')]
                              , 'sn' : [ug('sn')]
                              , 'givenName' : [ug('givenName')]
                              , 'objectClasses' : ug('objectClasses')
                              }
                            , ug('mapped_attrs').items()
                            , ug('multivalued_attrs')
                            )

    def testLDAPUserInstantiation(self):
        ae = self.assertEqual
        u = self.u_ob
        ae(u.getProperty('cn'), ug('cn'))
        ae(u.getProperty('sn'), ug('sn'))
        ae(u.getProperty('givenName'), ug('givenName'))
        ae(u._getPassword(), ug('user_pw'))
        ae(u.getId(), ug('cn'))
        ae(u.getUserName(), ug('cn'))
        for role in ug('user_roles'):
            self.assert_(role in u.getRoles())
        self.assert_('Authenticated' in u.getRoles())
        ae(u.getProperty('dn'), 'cn=%s,%s' % (ug('cn'), dg('users_base')))
        ae(u.getUserDN(), 'cn=%s,%s' % (ug('cn'), dg('users_base')))

    def testMappedAttrs(self):
        ae = self.assertEqual
        u = self.u_ob
        map = ug('mapped_attrs')

        for key, mapped_key in map.items():
            ae(u.getProperty(key), u.getProperty(mapped_key))

    def testMultivaluedAttributes(self):
        u = self.u_ob
        multivals = ug('multivalued_attrs')

        for mv in multivals:
            assert(type(u.getProperty(mv)) in (ListType, TupleType))


def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestLDAPUser))

    return suite

if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')
    
