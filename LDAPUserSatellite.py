#####################################################################
#
# LDAPUserSatellite	Fake user folder to change roles
#
# This software is governed by a license. See
# LICENSE.txt for the terms of this license.
#
#####################################################################
__version__='$Revision$'[11:-2]

# General Python imports
import os, urllib

# Zope imports
from Globals import package_home, InitializeClass, MessageDialog, DTMLFile
from Acquisition import aq_base
from AccessControl import ClassSecurityInfo
from AccessControl.Permissions import view_management_screens, manage_users
from AccessControl.SpecialUsers import emergency_user
from OFS.SimpleItem import SimpleItem
from DateTime.DateTime import DateTime

# LDAPUserFolder package imports
from LDAPUser import LDAPUser
from LDAPDelegate import explode_dn, ADD, DELETE
from utils import GROUP_MEMBER_MAP
from SimpleLog import SimpleLog


_dtmldir = os.path.join(package_home(globals()), 'dtml')
addLDAPUserSatelliteForm = DTMLFile('addLDAPUserSatellite', _dtmldir)
CHANGE_LUF_PERMISSION = 'Change user folder'


class LDAPUserSatellite(SimpleItem):
    """ 
        LDAPUserSatellite

        The LDAPUserSatellite is used to compute additional roles
        a given user might have.
    """
    security = ClassSecurityInfo()

    meta_type = 'LDAPUserSatellite'
    id = 'acl_satellite'


    #################################################################
    #
    # ZMI management screens
    #
    #################################################################

    manage_options=(
        (
        {'label' : 'Configure',	'action' : 'manage_main', 
         'help'  : ('LDAPUserGroupsFolder','ConfigureSatellite.stx')},
        {'label' : 'Caches', 'action' : 'manage_cache',
         'help'  : ('LDAPUserGroupsFolder', 'CachesSatellite.stx')},
        {'label' : 'Log', 'action' : 'manage_log',
         'help'  : ('LDAPUserGroupsFolder', 'LogSatellite.stx')},
        )
        + SimpleItem.manage_options
        ) 

    security.declareProtected(view_management_screens, 'manage')
    security.declareProtected(view_management_screens, 'manage_main')
    manage = manage_main = DTMLFile('dtml/sat_properties', globals())
    manage_main._setName('manage_main')
    
    security.declareProtected(view_management_screens, 'manage_log')
    manage_log = DTMLFile('dtml/sat_log', globals())

    security.declareProtected(view_management_screens, 'manage_cache')
    manage_cache = DTMLFile('dtml/sat_cache', globals())


    #################################################################
    # Initialization code
    #################################################################

    def __setstate__(self, v):
        """
            __setstate__ is called whenever the instance is loaded
            from the ZODB, like when Zope is restarted.
        """
        LDAPUserSatellite.inheritedAttribute('__setstate__')(self, v)
        self._log = SimpleLog()
        self._clearCaches()

        if not hasattr(self, 'verbose'):
            self.verbose = 2

        if self.verbose > 2:
            self._log.log(3,'Re-initialized through __setstate__')


    def __init__(self, luf, title='', recurse=0):
        """ Create a new LDAPUserSatellite instance """
        self.title = title
        self.recurse = recurse
        self._luf = luf
        self.verbose = 2    # _log needs it
        self.groups_base = ''
        self.groups_scope = ''
        self.groups_map = {}
        self._log = SimpleLog()
        self._v_cache = {}
        self._v_expiration = {}

       
    security.declarePrivate('_clearCaches')
    def _clearCaches(self):
        """ Clear all logs and caches for user-related information """
        self._v_cache = {} # Cache for user ID - role mapping
        self._v_expiration = {} # Cache for user ID - expiration mapping
        self._log.clear()


    security.declareProtected(manage_users, 'manage_reinit')
    def manage_reinit(self, REQUEST=None):
        """ re-initialize and clear out users and log """
        self._clearCaches()
        self.verbose > 1 and self._log.log(2, 'Reinitialized')

        if REQUEST:
            msg = 'User caches cleared'
            return self.manage_cache(manage_tabs_message=msg)


    security.declareProtected(CHANGE_LUF_PERMISSION, 'manage_edit')
    def manage_edit( self
                   , luf
                   , groups_base
                   , groups_scope
                   , verbose=2
                   , title=''
                   , recurse=0
                   , REQUEST=None 
                   ):
        """ Edit the LDAPUserSatellite Object """
        self.title = title
        self.recurse = recurse
        self.verbose = verbose
        self.groups_base = groups_base
        self.groups_scope = groups_scope

        if not luf.startswith('/'):
            luf = '/%s' % luf

        self._luf = luf

        self._clearCaches()

        if REQUEST:
            msg = 'Properties changed'
            return self.manage_main(manage_tabs_message=msg)


    security.declarePrivate('_cacheRoles')
    def _cacheRoles(self, name, roles=[], expiration=0):
        """ Stick something into my internal cache """
        if not name or not roles:
            return

        if name != emergency_user.getUserName():
            name = name.lower()
            self._v_cache[name] = roles
            self._v_expiration[name] = expiration


    security.declareProtected(manage_users, 'getExpiration')
    def getExpiration(self, name):
        """ Retrieve a user record's expiration """
        name = name.lower()

        return DateTime(self._v_expiration.get(name, 0))


    security.declarePrivate('getAdditionalRoles')
    def getAdditionalRoles(self, user, already_added=()):
        """ extend the user roles """
        my_path = self.absolute_url(1)
        add_role_dict = {}
        if user is None:
            return []

        if self.recurse == 1:
            self_path = self.getPhysicalPath()
            other_satellites = self.superValues('LDAPUserSatellite')
            other_satellites.reverse()

            for sat in other_satellites:
                if sat.getPhysicalPath() != self_path:
                    add_role_list = sat.getAdditionalRoles(user, already_added)
                    newly_added = {}

                    for add_role in add_role_list:
                        newly_added[add_role] = 1

                    for add_role in already_added:
                        newly_added[add_role] = 1

                    already_added = tuple(newly_added.keys())

        luf = self.getLUF()
        user_id = user.getId()
        user_expiration = user._created + luf.getCacheTimeout('authenticated')

        if ( self._v_cache.has_key(user_id) and
             self._v_expiration.get(user_id, 0) >= user_expiration ):
            self.verbose > 6 and self._log.log(7, 'Used cached "%s"' % user_id)
            return self._v_cache.get(user_id)

        if self.groups_base:   # We were given a search base, so search there
            user_dn = user.getUserDN()
            group_filter = '(|(uniquemember=%s)(member=%s))' % (user_dn, user_dn)

            res = luf._delegate.search( self.groups_base
                                      , self.groups_scope
                                      , group_filter
                                      , attrs = ['dn', 'cn']
                                      )

            if res['size'] > 0:
                resultset = res['results']
                for i in range(res['size']):
                    dn = resultset[i].get('dn')
                    try:
                        cn = resultset[i].get('cn')[0]
                    except KeyError:    # NDS oddity
                        cn = explode_dn(dn, 1)[0]

                    add_role_dict[cn] = 1

        for add_role in already_added:
            add_role_dict[add_role] = 1
        already_added = ()

        if self.groups_map:     # We have a group mapping, so map away
            roles = list(user.getRoles())
            roles.extend(add_role_dict.keys())

            for role in roles:
                mapped_roles = self.groups_map.get(role, [])
                for mapped_role in mapped_roles:
                    if mapped_role:
                        add_role_dict[mapped_role] = 1

        added_roles = add_role_dict.keys()

        if added_roles and self.verbose > 4:
            add_roles = ', '.join(added_roles)
            msg = 'Added roles %s to user %s' % (add_roles, user_id)
            self._log.log(5, msg)

        self._cacheRoles(user_id, added_roles, user_expiration)

        return added_roles


    security.declareProtected(manage_users, 'getLUF')
    def getLUF(self):
        """ Return my LDAP User Folder """
        return self.unrestrictedTraverse(self._luf)


    security.declareProtected(manage_users, 'getCache')
    def getCache(self):
        """ Return a list of *cached* user objects """
        return self._v_cache.items()

    security.declareProtected( manage_users, 'getGroups' )
    def getAllGroups(self):
        """
            returns a list of possible groups from the ldap tree.
            Used e.g. in showgroups.dtml
        """
        groups_dict = {}
        luf = self.getLUF()
        groups = list(luf.getGroups())
        groups.extend(self.getGroups())

        for group in groups:
            groups_dict[group] = 1

        return tuple(groups_dict.keys())


    security.declareProtected(manage_users, 'getGroups')
    def getGroups(self, dn='*', attr=None):
        """ return group records i know about """
        group_list = []

        if self.groups_base:
            no_show = ('Anonymous', 'Authenticated', 'Shared')
            group_filter = '(|(uniquemember=%s)(member=%s))' % (dn, dn)
            luf = self.getLUF()

            res = luf._delegate.search( self.groups_base
                                      , self.groups_scope
                                      , group_filter
                                      , attrs=['dn', 'cn']
                                      )

            if res['size'] > 0:
                resultset = res['results']
                for i in range(res['size']):
                    dn = resultset[i].get('dn')
                    try:
                        cn = resultset[i].get('cn')[0]
                    except KeyError:    # NDS oddity
                        cn = explode_dn(dn, 1)[0]

                    if attr is None:
                        group_list.append((cn, dn))
                    elif attr == 'cn':
                        group_list.append(cn)
                    elif attr == 'dn':
                        group_list.append(dn)

        return group_list

    security.declareProtected(manage_users, 'getGroupDetails')
    def getGroupDetails(self, encoded_cn):
        """ Return all group details """
        result = []
        cn = urllib.unquote(encoded_cn)
        luf = self.getLUF()

        res = luf._delegate.search( self.groups_base
                                  , self.groups_scope
                                  , 'cn=%s' % cn
                                  , ['uniqueMember', 'member']
                                  )

        if res['exception']:
            result = (('Exception', res['exception']),)
        elif res['size'] > 0:
            result = res['results'][0].items()
            result.sort()

        return tuple(result)


    security.declareProtected(manage_users, 'getGroupedUsers')
    def getGroupedUsers(self, groups=None):
        """ Retrieve all users that in the groups i know about """
        all_dns = {}
        users = []
        luf = self.getLUF()
        possible_members = GROUP_MEMBER_MAP.values()

        if groups is None:
            groups = self.getGroups()

        for group_id, group_dn in groups:
            group_details = self.getGroupDetails(group_id)

            for attribute_name, dn_list in group_details:
                if attribute_name in possible_members:
                    for dn in dn_list:
                        all_dns[dn] = 1

        for dn in all_dns.keys():
            user = luf.getUserByDN(dn)

            if user is not None:
                users.append(user.__of__(self))

        return tuple(users)


    security.declareProtected(manage_users, 'manage_editUserRoles')
    def manage_editUserRoles(self, user_dn, role_dns=[], REQUEST=None):
        """ Edit the roles (groups) of a user """
        all_groups = self.getGroups(attr='dn')
        cur_groups = self.getGroups(dn=user_dn, attr='dn')
        operations = []
        luf = self.getLUF()

        user = self.getUserByDN(user_dn)
        if user is None:
            return

        for role_dn in role_dns:
            if role_dn not in all_groups:
                newgroup_type = 'groupOfUniqueNames'
                newgroup_member = GROUP_MEMBER_MAP.get(newgroup_type)
                newgroup_name = explode_dn(role_dn, 1)[0]
                connection = luf._connect()
                attr_list = [ ('objectClass', ['top', newgroup_type])
                            , ('cn', newgroup_name)
                            , (newgroup_member, [user_dn, luf._binduid])
                            ]
                connection.add_s(role_dn, attr_list)


        for group in all_groups:
            if group in cur_groups and group not in role_dns:
                operations.append({ 'op'     : DELETE
                                  , 'target' : group
                                  , 'type'   : luf.getGroupType(group)
                                  } )
            elif group in role_dns and group not in cur_groups:
                operations.append({ 'op'     : ADD
                                  , 'target' : group
                                  , 'type'   : luf.getGroupType(group)
                                  } )

        if operations:
            connection = luf._connect()

            for to_do in operations:
                mod_list = ( ( to_do['op']
                             , GROUP_MEMBER_MAP.get(to_do['type'])
                             , user_dn
                             ), )
                try:
                    connection.modify_s(to_do['target'], mod_list)
                except Exception, e:
                    msg = str(e)

            msg = 'Roles changed for %s' % (user_dn)
        else:
            msg = 'No roles changed for %s' % (user_dn)

        user_obj = self.getUserByDN(user_dn)
        if user_obj is not None:
            self._expireUser(user_obj)

        if REQUEST:
            return self.manage_userrecords( manage_tabs_message=msg
                                          , user_dn=user_dn
                                          )


    security.declareProtected(manage_users, '_expireUser')
    def _expireUser(self, user_obj):
        """ Purge user object from caches """
        name = user_obj.getId().lower()

        if self._v_cache.has_key(name):
            del self._v_cache[name]

        if self._v_expiration.has_key(name):
            del self._v_expiration[name]


    def getLog(self):
        """ Get the log for displaying """
        return self._log.getLog()


    security.declareProtected(manage_users, 'getGroupMappings')
    def getGroupMappings(self):
        """ Return the dictionary that maps LDAP groups map to Zope roles """
        return self.groups_map.items()


    security.declareProtected(manage_users, 'manage_addGroupMapping')
    def manage_addGroupMapping(self, group_name, role_names=[], REQUEST=None):
        """ Map a LDAP group to a Zope role """
        if len(role_names) < 1:
            msg = 'You did not select any Zope roles to map to!'

        else:
            mappings = self.groups_map
            mappings[group_name] = role_names
            self.groups_map = mappings
            self._clearCaches()

            msg = 'Added LDAP group to Zope role mapping: %s -> %s' % (
                    group_name, ', '.join(role_names))

        if REQUEST:
            return self.manage_main(manage_tabs_message=msg)


    security.declareProtected(manage_users, 'manage_deleteGroupMappings') 
    def manage_deleteGroupMappings(self, group_names, REQUEST=None):
        """ Delete mappings from LDAP group to Zope role """
        mappings = self.groups_map

        for group_name in group_names:
            if mappings.has_key(group_name):
                del mappings[group_name]

        self.groups_map = mappings
        self._clearCaches()
        msg = 'Deleted LDAP group to Zope role mapping for: %s' % (
            ', '.join(group_names))

        if REQUEST:
            return self.manage_main(manage_tabs_message=msg)



def manage_addLDAPUserSatellite(self, luf, title='', recurse=0, REQUEST=None):
    """ Called by Zope to create and install an LDAPUserSatellite """

    if hasattr(aq_base(self), 'acl_satellite') and REQUEST is not None:
        msg = 'This object already contains a LDAPUserSatellite'
        
        return MessageDialog(
               title  = 'Item Exists',
               message = msg,
               action = '%s/manage_main' % REQUEST['URL1'])

    n = LDAPUserSatellite(luf, title, recurse)

    self._setObject('acl_satellite', n)
 
    # return to the parent object's manage_main
    if REQUEST:
        url = '%s/acl_satellite/manage_main' % self.this().absolute_url()
        REQUEST.RESPONSE.redirect(url)


InitializeClass(LDAPUserSatellite)
