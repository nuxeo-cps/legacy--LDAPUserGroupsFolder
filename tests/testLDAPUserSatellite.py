#!/usr/bin/env python
#####################################################################
#
# testLDAPUserSatellite    Tests for the LDAPUserSatellite
#
# This software is governed by a license. See
# LICENSE.txt for the terms of this license.
#
#####################################################################
__version__='$Revision$'[11:-2]

# General Python imports
import unittest, sys

# Zope imports
import ZODB
from ZODB.DemoStorage import DemoStorage
from App import FindHomes
from OFS.Folder import Folder, manage_addFolder
from OFS.Application import Application

# Do some namespace manipulation to make use of FakeLDAP
import FakeLDAP
if sys.modules.has_key('_ldap'):
    del sys.modules['_ldap']
sys.modules['ldap'] = FakeLDAP

# LDAPUserFolder package imports
from Products.LDAPUserFolder import manage_addLDAPUserFolder
from Products.LDAPUserFolder import manage_addLDAPUserSatellite

# Tests imports
from config import defaults, alternates, user, satellite_defaults
dg = defaults.get
ag = alternates.get
ug = user.get
sg = satellite_defaults.get

class TestLDAPUserSatellite(unittest.TestCase):

    db = None
    jar = None

    def setUp(self):
        if self.db is None:
            s = DemoStorage()
            self.db = ZODB.DB(s)
        if self.jar is not None:
            raise RuntimeError, 'test needs to dbclose() before dbopen()'
        self.jar = self.db.open()
        root = self.jar.root()
        app = Application()
        root['app'] = app
        self.root = root.get('app')
        manage_addFolder(self.root, 'luftest')
        self.folder = self.root.luftest
        manage_addLDAPUserFolder( self.folder
                                , dg('title')
                                , dg('server')
                                , dg('login_attr')
                                , dg('users_base')
                                , dg('users_scope')
                                , dg('roles')
                                , dg('groups_base')
                                , dg('groups_scope')
                                , dg('binduid')
                                , dg('bindpwd')
                                , dg('binduid_usage')
                                , dg('rdn_attr')
                                , dg('local_groups')
                                , dg('use_ssl')
                                , dg('encryption')
                                )
        FakeLDAP.clearTree()
        FakeLDAP.addTreeItems(dg('users_base'))
        FakeLDAP.addTreeItems(dg('groups_base'))
        FakeLDAP.addTreeItems(sg('groups_base'))
        manage_addFolder(self.folder, 'lustest')
        self.lustest = self.folder.lustest
        manage_addLDAPUserSatellite( self.lustest
                                   , sg('luf')
                                   , sg('title')
                                   , sg('recurse')
                                   )
        self.lus = self.lustest.acl_satellite
        acl = self.folder.acl_users
        for role in ug('user_roles'):
            acl.manage_addGroup(role)
        acl.manage_addUser(REQUEST=None, kwargs=user)

    def tearDown(self):
        get_transaction().abort()
        if self.jar is not None:
            self.jar.close()
            self.jar = None
        if self.db is not None:
            self.db.close()
            self.db = None

    def testInstantiation(self):
        lus = getattr(self.lustest, 'acl_satellite').__of__(self.lustest)
        ae = self.assertEqual
        ae(lus._luf, sg('luf'))
        ae(lus.title, sg('title'))
        ae(lus.recurse, sg('recurse'))
        ae(lus.verbose, 2)
        ae(len(lus.getLog()), 0)
        ae(len(lus.getCache()), 0)
        ae(len(lus.getGroupMappings()), 0)
        ae(len(lus.getGroups()), 0)
        ae(len(lus.getGroupedUsers()), 0)
        luf = lus.getLUF()
        ae('/'.join(luf.getPhysicalPath()), sg('luf'))

    def testEdit(self):
        lus = self.lus
        ae = self.assertEqual
        lus.manage_edit( '/acl_users'
                       , sg('groups_base')
                       , sg('groups_scope')
                       , verbose=3
                       , title='New Title'
                       , recurse=1
                       )
        ae(lus.title, 'New Title')
        ae(lus.recurse, 1)
        ae(lus._luf, '/acl_users')
        ae(lus.groups_base, sg('groups_base'))
        ae(lus.groups_scope, sg('groups_scope'))
        ae(lus.verbose, 3)


    def testRoleMapping(self):
        lus = self.lus
        ae = self.assertEqual
        ae(len(lus.getGroupMappings()), 0)
        lus.manage_addGroupMapping('Manager', ['Privileged'])
        ae(len(lus.getGroupMappings()), 1)
        user = self.folder.acl_users.getUser('test')
        roles = lus.getAdditionalRoles(user)
        ae(len(lus.getCache()), 1)
        ae(roles, ['Privileged'])
        lus.manage_deleteGroupMappings(['Manager'])
        ae(len(lus.getGroupMappings()), 0)
        roles = lus.getAdditionalRoles(user)
        ae(len(roles), 0)

    def testLDAPRoleAdding(self):
        lus = self.lus
        ae = self.assertEqual
        acl = lus.getLUF()
        user = self.folder.acl_users.getUser('test')
        acl._delegate.insert( sg('groups_base')
                            , 'cn=Privileged'
                            , { 'objectClass' : ['top', 'groupOfUniqueNames']
                              , 'cn' : ['Privileged']
                              , 'uniqueMember' : user.getUserDN()
                              }
                            )
        lus.manage_edit( sg('luf')
                       , sg('groups_base')
                       , sg('groups_scope')
                       )
        ae(len(lus.getGroups()), 1)
        roles = lus.getAdditionalRoles(user)
        ae(roles, ['Privileged']) 
        ae(len(lus.getGroupedUsers()), 1)
        ae(len(lus.getCache()), 1)


def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestLDAPUserSatellite))

    return suite

if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')
    
