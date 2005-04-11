#!/usr/bin/env python
#####################################################################
#
# testLDAPUserFolder    Tests for the LDAPUserFolder
#
# This software is governed by a license. See
# LICENSE.txt for the terms of this license.
#
#####################################################################
__version__='$Revision$'[11:-2]

# General Python imports
import unittest, sys

from Testing import ZopeTestCase
ZopeTestCase.installProduct('LDAPUserGroupsFolder')

# Zope imports
import ZODB
from ZODB.MappingStorage import MappingStorage
from App import FindHomes
from OFS.Folder import Folder
from AccessControl.SecurityManagement import newSecurityManager, \
                                             noSecurityManager

# Do some namespace manipulation to make use of FakeLDAP
import FakeLDAP
if sys.modules.has_key('_ldap'):
    del sys.modules['_ldap']
sys.modules['ldap'] = FakeLDAP

# LDAPUserFolder package imports
from Products.LDAPUserGroupsFolder import manage_addLDAPUserGroupsFolder

# Tests imports
from config import defaults, alternates, user, manager_user
dg = defaults.get
ag = alternates.get
ug = user.get

class TestLDAPUserFolder(unittest.TestCase):

    db = None
    jar = None

    def setUp(self):
        if self.db is None:
            s = MappingStorage()
            self.db = ZODB.DB(s)
        if self.jar is not None:
            raise RuntimeError, 'test needs to dbclose() before dbopen()'
        self.jar = self.db.open()
        self.root = self.jar.root()
        folder = Folder('luftest')
        self.root['luftest'] = folder
        self.folder = self.root.get('luftest')
        manage_addLDAPUserGroupsFolder( self.folder
                                , dg('title')
                                , dg('server')
                                , dg('login_attr')
                                , dg('users_base')
                                , dg('users_scope')
                                , dg('roles')
                                , dg('groups_base')
                                , dg('groups_scope')
                                , dg('usergroups_base')
                                , dg('usergroups_scope')
                                , dg('binduid')
                                , dg('bindpwd')
                                , dg('binduid_usage')
                                , dg('rdn_attr')
                                , dg('local_groups')
                                , dg('local_usergroups')
                                , dg('use_ssl')
                                , dg('encryption')
                                , dg('read_only')
                                )
        FakeLDAP.clearTree()
        FakeLDAP.addTreeItems(dg('users_base'))
        FakeLDAP.addTreeItems(dg('groups_base'))

    def tearDown(self):
        get_transaction().abort()
        if self.jar is not None:
            self.jar.close()
            self.jar = None
        if self.db is not None:
            self.db.close()
            self.db = None

    def testLUFInstantiation(self):
        acl = self.folder.acl_users
        ae = self.assertEqual
        ae(self.folder.__allow_groups__, self.folder.acl_users)
        ae(acl.getProperty('title'), dg('title'))
        ae(acl.getProperty('LDAP_server'), 'localhost')
        ae(acl.getProperty('LDAP_port'), 389)
        ae(acl.getProperty('_conn_proto'), 'ldap')
        ae(acl.getProperty('_login_attr'), dg('login_attr'))
        ae(acl.getProperty('users_base'), dg('users_base'))
        ae(acl.getProperty('users_scope'), dg('users_scope'))
        ae(acl.getProperty('_roles'), [dg('roles')])
        ae(acl.getProperty('groups_base'), dg('groups_base'))
        ae(acl.getProperty('groups_scope'), dg('groups_scope'))
        ae(acl.getProperty('_binduid'), dg('binduid'))
        ae(acl.getProperty('_bindpwd'), dg('bindpwd'))
        ae(acl.getProperty('_binduid_usage'), dg('binduid_usage'))
        ae(acl.getProperty('_rdnattr'), dg('rdn_attr'))
        ae(acl.getProperty('_local_groups'), not not dg('local_groups'))
        ae(acl.getProperty('_pwd_encryption'), dg('encryption'))
        ae(acl.getProperty('read_only'), not not dg('read_only'))
        ae(acl.getProperty('verbose'), 2)
        ae(len(acl.getLog()), 2)
        ae(len(acl._anonymous_cache.getCache()), 0)
        ae(len(acl._authenticated_cache.getCache()), 0)
        ae(len(acl.getSchemaConfig().keys()), 5)
        ae(len(acl.getSchemaDict()), 5)
        ae(len(acl._groups_store), 0)
        ae(len(acl.getProperty('additional_groups')), 0)
        ae(len(acl.getGroupMappings()), 0)
        ae(len(acl.getServers()), 1)

    def testLDAPDelegateInstantiation(self):
        ld = self.folder.acl_users._delegate
        ae = self.assertEqual
        ae(len(ld.getServers()), 1)
        ae(ld.login_attr, dg('login_attr'))
        ae(ld.rdn_attr, dg('rdn_attr'))
        ae(ld.bind_dn, dg('binduid'))
        ae(ld.bind_pwd, dg('bindpwd'))
        ae(ld.binduid_usage, dg('binduid_usage'))
        ae(ld.u_base, dg('users_base'))
        ae(ld.u_classes, ['top', 'person'])
        ae(ld.read_only, not not dg('read_only'))

    def testLUFEdit(self):
        acl = self.folder.acl_users
        ae = self.assertEqual
        acl.manage_edit(  ag('title')
                        , ag('login_attr')
                        , ag('users_base')
                        , ag('users_scope')
                        , ag('roles')
                        , ag('groups_base')
                        , ag('groups_scope')
                        , ag('usergroups_base')
                        , ag('usergroups_scope')
                        , ag('binduid')
                        , ag('bindpwd')
                        , ag('binduid_usage')
                        , ag('rdn_attr')
                        , ag('obj_classes')
                        , ag('local_groups')
                        , ag('local_usergroups')
                        , ag('encryption')
                        , ag('read_only')
                       )
        ae(acl.getProperty('title'), ag('title'))
        ae(acl.getProperty('_login_attr'), ag('login_attr'))
        ae(acl.getProperty('users_base'), ag('users_base'))
        ae(acl.getProperty('users_scope'), ag('users_scope'))
        ae(', '.join(acl.getProperty('_roles')), ag('roles'))
        ae(acl.getProperty('groups_base'), ag('groups_base'))
        ae(acl.getProperty('groups_scope'), ag('groups_scope'))
        ae(acl.getProperty('_binduid'), ag('binduid'))
        ae(acl.getProperty('_bindpwd'), ag('bindpwd'))
        ae(acl.getProperty('_binduid_usage'), ag('binduid_usage'))
        ae(acl.getProperty('_rdnattr'), ag('rdn_attr'))
        ae(', '.join(acl.getProperty('_user_objclasses')), ag('obj_classes'))
        ae(acl.getProperty('_local_groups'), not not ag('local_groups'))
        ae(acl.getProperty('_pwd_encryption'), ag('encryption'))
        ae(acl.getProperty('read_only'), not not ag('read_only'))

    def testServerManagement(self):
        acl = self.folder.acl_users
        ae = self.assertEqual
        ae(len(acl.getServers()), 1)
        acl.manage_addServer('ldap.some.com', port=636, use_ssl=1)
        ae(len(acl.getServers()), 2)
        acl.manage_addServer('localhost')
        ae(len(acl.getServers()), 2)
        acl.manage_deleteServers([1])
        ae(len(acl.getServers()), 1)
        acl.manage_deleteServers()
        ae(len(acl.getServers()), 1)

    def testGroupMapping(self):
        acl = self.folder.acl_users
        ae = self.assertEqual
        ae(len(acl.getGroupMappings()), 0)
        have_roles = ['ldap_group', 'some_group']
        ae(acl._mapRoles(have_roles), have_roles)
        acl.manage_addGroupMapping('ldap_group', 'zope_role')
        ae(len(acl.getGroupMappings()), 1)
        roles = acl._mapRoles(have_roles)
        ae(len(roles), 3)
        self.assert_('ldap_group' in roles)
        self.assert_('zope_role' in roles)
        self.assert_('some_group' in roles)
        acl.manage_deleteGroupMappings('unknown')
        ae(len(acl.getGroupMappings()), 1)
        acl.manage_deleteGroupMappings(['ldap_group'])
        ae(len(acl.getGroupMappings()), 0)
        ae(acl._mapRoles(have_roles), have_roles)

    def testLDAPSchema(self):
        acl = self.folder.acl_users
        ae = self.assertEqual
        ae(len(acl.getLDAPSchema()), 5)
        ae(len(acl.getSchemaDict()), 5)
        acl.manage_addLDAPSchemaItem( 'telephoneNumber'
                                    , ''
                                    , ''
                                    , 'public'
                                    )
        ae(len(acl.getLDAPSchema()), 6)
        ae(len(acl.getSchemaDict()), 6)
        cur_schema = acl.getSchemaConfig()
        self.assert_('mail' in cur_schema.keys())
        acl.manage_addLDAPSchemaItem( 'cn'
                                    , 'exists'
                                    , ''
                                    , 'exists'
                                    )
        ae(len(acl.getLDAPSchema()), 6)
        ae(len(acl.getSchemaDict()), 6)
        acl.manage_deleteLDAPSchemaItems(['cn', 'unknown', 'mail'])
        ae(len(acl.getLDAPSchema()), 4)
        ae(len(acl.getSchemaDict()), 4)
        cur_schema = acl.getSchemaConfig()
        self.assert_('mail' not in cur_schema.keys())
        self.assert_('cn' not in cur_schema.keys())

    def testSchemaMappedAttrs(self):
        acl = self.folder.acl_users
        ae = self.assertEqual
        ae(len(acl.getMappedUserAttrs()), 1)
        acl.manage_addLDAPSchemaItem( 'jpegPhoto'
                                    , 'Photo'
                                    , 'photo'
                                    , 'public'
                                    )
        ae(len(acl.getMappedUserAttrs()), 2)
        ae(acl.getMappedUserAttrs(),
           (('mail', 'email'), ('jpegPhoto', 'public')))
        acl.manage_deleteLDAPSchemaItems(['jpegPhoto'])
        ae(len(acl.getMappedUserAttrs()), 1)

    def testSchemaMultivaluedAttrs(self):
        acl = self.folder.acl_users
        ae = self.assertEqual
        ae(len(acl.getMultivaluedUserAttrs()), 0)
        acl.manage_addLDAPSchemaItem( 'mail2'
                                    , 'Email2'
                                    , 'yes'
                                    , 'public'
                                    )
        ae(len(acl.getMultivaluedUserAttrs()), 1)
        ae(acl.getMultivaluedUserAttrs(), ('mail2',))

    def testAddUser(self):
        acl = self.folder.acl_users
        ae=self.assertEqual
        for role in ug('user_roles'):
            acl.manage_addGroup(role)
        msg = acl.manage_addUser(REQUEST=None, kwargs=user)
        self.assert_(not msg)
        msg = acl.manage_addUser(REQUEST=None, kwargs=user)
        self.assert_(msg.split(' ')[0] == 'ALREADY_EXISTS')
        user_ob = acl.getUser(ug('cn'))
        self.assertNotEqual(user_ob, None)
        for role in ug('user_roles'):
            self.assert_(role in user_ob.getRoles())
        for role in acl.getProperty('_roles'):
            self.assert_(role in user_ob.getRoles())
        ae(user_ob.getProperty('cn'), ug('cn'))
        ae(user_ob.getProperty('sn'), ug('sn'))
        ae( user_ob.getId()
          , ug(acl.getProperty('_rdnattr'))
          )

    def testAddUserReadOnly(self):
        acl = self.folder.acl_users
        acl.read_only = 1
        acl._delegate.read_only = 1
        ae=self.assertEqual
        msg = acl.manage_addUser(REQUEST=None, kwargs=user)
        self.assert_(msg)
        user_ob = acl.getUser(ug('cn'))
        ae(user_ob, None)

    def testGetUser(self):
        acl = self.folder.acl_users
        for role in ug('user_roles'):
            acl.manage_addGroup(role)
        msg = acl.manage_addUser(REQUEST=None, kwargs=user)
        self.assert_(not msg)
        user_ob = acl.getUser(ug(acl.getProperty('_rdnattr')))
        self.assertNotEqual(user_ob, None)
        user_ob = acl.getUserByDN(user_ob.getUserDN())
        self.assertNotEqual(user_ob, None)
        user_ob = acl.getUserById(ug(acl.getProperty('_rdnattr')))
        self.assertNotEqual(user_ob, None)
        self.assertEqual(len(acl.getUserNames()), 1)

    def testAuthenticateUser(self):
        acl = self.folder.acl_users
        for role in ug('user_roles'):
            acl.manage_addGroup(role)
        msg = acl.manage_addUser(REQUEST=None, kwargs=user)
        self.assert_(not msg)
        user_ob = acl.authenticate( ug(acl.getProperty('_rdnattr'))
                                  , ug('user_pw')
                                  , {}
                                  )
        self.assertNotEqual(user_ob, None)
        user_ob = acl.authenticate( ug(acl.getProperty('_rdnattr'))
                                  , ''
                                  , {}
                                  )
        self.assertEqual(user_ob, None)
        user_ob = acl.authenticate( ug(acl.getProperty('_rdnattr'))
                                  , 'falsepassword'
                                  , {}
                                  )
        self.assertEqual(user_ob, None)

    def testDeleteUser(self):
        acl = self.folder.acl_users
        msg = acl.manage_addUser(REQUEST=None, kwargs=user)
        self.assert_(not msg)
        msg = acl.manage_addUser(REQUEST=None, kwargs=manager_user)
        self.assert_(not msg)
        mgr_ob = acl.getUser(manager_user.get(acl.getProperty('_rdnattr')))
        self.assertNotEqual(mgr_ob, None)
        newSecurityManager({}, mgr_ob)
        user_ob = acl.getUser(ug(acl.getProperty('_rdnattr')))
        self.assertNotEqual(user_ob, None)
        user_dn = user_ob.getUserDN()
        acl.manage_deleteUsers([user_dn])
        user_ob = acl.getUser(ug(acl.getProperty('_rdnattr')))
        self.assertEqual(user_ob, None)
        self.assertEqual(acl.getGroups(dn=user_dn), [])
        noSecurityManager()

    def testDeleteUserReadOnly(self):
        acl = self.folder.acl_users
        for role in ug('user_roles'):
            acl.manage_addGroup(role)
        msg = acl.manage_addUser(REQUEST=None, kwargs=user)
        self.assert_(not msg)
        user_ob = acl.getUser(ug(acl.getProperty('_rdnattr')))
        self.assertNotEqual(user_ob, None)
        user_dn = user_ob.getUserDN()
        acl.read_only = 1
        acl._delegate.read_only = 1
        acl.manage_deleteUsers([user_dn])
        user_ob = acl.getUser(ug(acl.getProperty('_rdnattr')))
        self.assertNotEqual(user_ob, None)
        self.assertNotEqual(acl.getGroups(dn=user_dn), [])

    def testEditUser(self):
        acl = self.folder.acl_users
        msg = acl.manage_addUser(REQUEST=None, kwargs=user)
        self.assert_(not msg)
        user_ob = acl.getUser(ug(acl.getProperty('_rdnattr')))
        self.assertNotEqual(user_ob, None)
        user_dn = user_ob.getUserDN()
        msg = acl.manage_editUser(user_dn, kwargs={'sn' : 'New'})
        self.assert_(not msg)
        user_ob = acl.getUser(ug(acl.getProperty('_rdnattr')))
        self.assertEqual(user_ob.getProperty('sn'), 'New')

    def testEditUserReadOnly(self):
        acl = self.folder.acl_users
        msg = acl.manage_addUser(REQUEST=None, kwargs=user)
        self.assert_(not msg)
        user_ob = acl.getUser(ug(acl.getProperty('_rdnattr')))
        self.assertNotEqual(user_ob, None)
        user_dn = user_ob.getUserDN()
        acl.read_only = 1
        acl._delegate.read_only = 1
        msg = acl.manage_editUser(user_dn, kwargs={'sn' : 'New'})
        self.assert_(msg)
        user_ob = acl.getUser(ug(acl.getProperty('_rdnattr')))
        self.assertEqual(user_ob.getProperty('sn'), ug('sn'))

    def testEditUserPassword(self):
        conn = FakeLDAP.initialize('')
        acl = self.folder.acl_users
        msg = acl.manage_addUser(REQUEST=None, kwargs=user)
        self.assert_(not msg)
        user_ob = acl.getUser(ug(acl.getProperty('_rdnattr')))
        self.assertNotEqual(user_ob, None)
        user_dn = user_ob.getUserDN() 
        res = conn.search_s(user_ob.getUserDN(), scope=FakeLDAP.SCOPE_BASE)
        old_pw = res[0][1]['userPassword'][0]
        acl.manage_editUserPassword(user_dn, 'newpass')
        user_ob = acl.getUser(ug(acl.getProperty('_rdnattr')))
        self.assertNotEqual(user_ob, None)
        res = conn.search_s(user_ob.getUserDN(), scope=FakeLDAP.SCOPE_BASE)
        new_pw = res[0][1]['userPassword'][0]
        self.assertNotEqual(old_pw, new_pw)

    def testEditUserPasswordReadOnly(self):
        conn = FakeLDAP.initialize('')
        acl = self.folder.acl_users
        msg = acl.manage_addUser(REQUEST=None, kwargs=user)
        self.assert_(not msg)
        user_ob = acl.getUser(ug(acl.getProperty('_rdnattr')))
        self.assertNotEqual(user_ob, None)
        user_dn = user_ob.getUserDN() 
        res = conn.search_s(user_ob.getUserDN(), scope=FakeLDAP.SCOPE_BASE)
        old_pw = res[0][1]['userPassword'][0]
        acl.read_only = 1
        acl._delegate.read_only = 1
        acl.manage_editUserPassword(user_dn, 'newpass')
        user_ob = acl.getUser(ug(acl.getProperty('_rdnattr')))
        self.assertNotEqual(user_ob, None)
        res = conn.search_s(user_ob.getUserDN(), scope=FakeLDAP.SCOPE_BASE)
        new_pw = res[0][1]['userPassword'][0]
        self.assertEqual(old_pw, new_pw)

    def testEditUserRoles(self):
        acl = self.folder.acl_users
        for role in ug('user_roles'):
            acl.manage_addGroup(role)
        new_role = 'Privileged'
        acl.manage_addGroup(new_role)
        msg = acl.manage_addUser(REQUEST=None, kwargs=user)
        self.assert_(not msg)
        user_ob = acl.getUser(ug(acl.getProperty('_rdnattr')))
        self.assertNotEqual(user_ob, None)
        self.assert_(new_role not in user_ob.getRoles())
        user_dn = user_ob.getUserDN()
        acl.manage_editUserRoles(user_dn, ['Manager', new_role])
        user_ob = acl.getUser(ug(acl.getProperty('_rdnattr')))
        self.assertNotEqual(user_ob, None)
        self.assert_(new_role in user_ob.getRoles())

    def testEditUserRolesReadOnly(self):
        acl = self.folder.acl_users
        for role in ug('user_roles'):
            acl.manage_addGroup(role)
        new_role = 'Privileged'
        acl.manage_addGroup(new_role)
        msg = acl.manage_addUser(REQUEST=None, kwargs=user)
        self.assert_(not msg)
        user_ob = acl.getUser(ug(acl.getProperty('_rdnattr')))
        self.assertNotEqual(user_ob, None)
        self.assert_(new_role not in user_ob.getRoles())
        user_dn = user_ob.getUserDN()
        acl._delegate.read_only = 1
        acl.manage_editUserPassword(user_dn, 'newpass')
        acl.manage_editUserRoles(user_dn, ['Manager', new_role])
        user_ob = acl.getUser(ug(acl.getProperty('_rdnattr')))
        self.assertNotEqual(user_ob, None)
        self.assert_(new_role not in user_ob.getRoles())

    def testModRDN(self):
        acl = self.folder.acl_users
        ae = self.assertEqual
        for role in ug('user_roles'):
            acl.manage_addGroup(role)
        msg = acl.manage_addUser(REQUEST=None, kwargs=manager_user)
        self.assert_(not msg)
        mgr_ob = acl.getUser(manager_user.get(acl.getProperty('_rdnattr')))
        self.assertNotEqual(mgr_ob, None)
        newSecurityManager({}, mgr_ob)
        msg = acl.manage_addUser(REQUEST=None, kwargs=user)
        self.assert_(not msg)
        user_ob = acl.getUser(ug(acl.getProperty('_rdnattr')))
        self.assertNotEqual(user_ob, None)
        user_dn = user_ob.getUserDN()
        msg = acl.manage_editUser(user_dn, kwargs={'cn' : 'new'})
        user_ob = acl.getUser('new')
        ae(user_ob.getProperty('cn'), 'new') 
        ae(user_ob.getId(), 'new')
        new_dn = 'cn=new,%s' % acl.getProperty('users_base')
        ae(user_ob.getUserDN(), new_dn)
        for role in ug('user_roles'):
            self.assert_(role in user_ob.getRoles())
        for role in acl.getProperty('_roles'):
            self.assert_(role in user_ob.getRoles())
        noSecurityManager()

    def testSetUserProperty(self):
        acl = self.folder.acl_users
        msg = acl.manage_addUser(REQUEST=None, kwargs=manager_user)
        self.assert_(not msg)
        mgr_ob = acl.getUser(manager_user.get(acl.getProperty('_rdnattr')))
        self.assertNotEqual(mgr_ob, None)
        self.assertEqual( mgr_ob.getProperty('sn')
                        , manager_user.get('sn')
                        )
        acl.manage_setUserProperty( mgr_ob.getUserDN()
                                  , 'sn'
                                  , 'NewLastName'
                                  )
        mgr_ob = acl.getUser(manager_user.get(acl.getProperty('_rdnattr')))
        self.assertEqual( mgr_ob.getProperty('sn')
                        , 'NewLastName'
                        )
        # Trying to set through the user object API.
        mgr_ob.setProperty('sn', 'New')
        self.assert_(mgr_ob.getProperty('sn') == 'New')
        mgr_ob.setProperties(cn='NewCN', sn='Newer')
        self.assert_(mgr_ob.getProperties( ('cn', 'sn')) == \
                     {'cn': 'NewCN', 'sn': 'Newer'})

    def testCPSRoleAPI(self):
        aclu = self.folder.acl_users
        msg = aclu.manage_addUser(REQUEST=None, kwargs=user)
        self.assert_(not msg)
        msg = aclu.manage_addUser(REQUEST=None, kwargs=manager_user)
        self.assert_(not msg)
        aclu.userFolderAddRole('Role1')
        aclu.userFolderAddRole('Role2')
        self.assert_('Role1' in self.folder.userdefined_roles())
        self.assert_('Role2' in self.folder.userdefined_roles())
        groups = [g[0] for g in aclu.getGroups()]
        groups.sort()
        self.assertEquals(groups, ['Role1', 'Role2'])
        aclu.setRolesOfUser(('Role1', 'Role2'), 'mgr')
        aclu.setUsersOfRole(('mgr', 'test'), 'Role1')
        roles = list(aclu.getUser('mgr').getRoles())
        roles.sort()
        self.assert_(roles == ['Anonymous', 'Authenticated', 'Role1', 'Role2'])
        owners = aclu.getUsersOfRole('Role1')
        owners.sort()
        self.assert_(owners == ['mgr', 'test'])
        self.assert_(aclu.getUsersOfRole('Role2') == ['mgr'])
        aclu.userFolderDelRoles(('Role2',))
        self.assert_('Role2' not in self.folder.userdefined_roles())
        groups = [g[0] for g in aclu.getGroups()]
        groups.sort()
        self.assertEquals(groups, ['Role1'])

    def testCPSGroupAPI(self):
        aclu = self.folder.acl_users
        msg = aclu.manage_addUser(REQUEST=None, kwargs=user)
        self.assert_(not msg)
        msg = aclu.manage_addUser(REQUEST=None, kwargs=manager_user)
        self.assert_(not msg)
        aclu.userFolderAddGroup('group1')
        aclu.userFolderAddGroup('group2')
        self.assert_(aclu.getGroupById('group1') is not None)
        groups = list(aclu.getGroupNames())
        groups.sort()
        self.assert_(groups == ['group1', 'group2'])
        aclu.setGroupsOfUser(['group1', 'group2'], 'test')
        aclu.setUsersOfGroup(['test', 'mgr'], 'group1')
        users = aclu.getUsersOfGroup('group1')
        users.sort()
        self.assert_(users == ['mgr', 'test'])
        groups = list(aclu.getUser('test').getGroups())
        groups.sort()
        self.assert_(groups == ['group1', 'group2'])


def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestLDAPUserFolder))

    return suite

if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')
    
