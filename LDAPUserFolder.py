#####################################################################
#
# LDAPUserGroupsFolder	An LDAP-based user source for Zope
#
# This product includes software developed by Jens Vagelpohl for use in
# the Z Object Publishing Environment (http://www.zope.org/).
#
# This software is governed by a license. See
# LICENSE.txt for the terms of this license.
#
#####################################################################
__version__='$Revision$'[11:-2]

# General python imports
import time, os, urllib
from types import StringType, ListType, TupleType

# Zope imports
from Globals import DTMLFile, package_home, InitializeClass
from Acquisition import aq_base, aq_inner, aq_parent
from AccessControl import ClassSecurityInfo
from AccessControl.User import BasicUserFolder, domainSpecMatch
from AccessControl.SecurityManagement import getSecurityManager
from AccessControl.Permissions import view_management_screens, \
                                      manage_users, \
                                      view
from AccessControl.PermissionRole import rolesForPermissionOn
from OFS.SimpleItem import SimpleItem
from BTrees.OOBTree import OOBTree

# LDAPUserFolder package imports
from LDAPUser import LDAPUser, CPSGroup
from LDAPDelegate import LDAPDelegate, explode_dn
from LDAPDelegate import ADD, DELETE, REPLACE, BASE
from SimpleLog import SimpleLog
from SimpleCache import SimpleCache
from utils import _createLDAPPassword, to_utf8, crypt
from utils import ldap_scopes, GROUP_MEMBER_MAP, filter_format
from utils import _verifyUnicode, encoding
from utils import _normalizeDN

try:
    from Products.CMFCore.utils import getToolByName
    _cmf_support = 1
except ImportError:
    _cmf_support = 0

_marker = []
_dtmldir = os.path.join(package_home(globals()), 'dtml')
addLDAPUserFolderForm = DTMLFile('addLDAPUserFolder', _dtmldir)
EDIT_PERMISSION = 'Change user folder'


class LDAPUserFolder(BasicUserFolder):
    """ 
        LDAPUserFolder

        The LDAPUserFolder is a user database.  It contains management 
        hooks so that it can be added to a Zope folder as an 'acl_users'
        database.  Its important public method is validate() which
        returns a Zope user object of type LDAPUser
    """
    security = ClassSecurityInfo()

    meta_type = 'LDAPUserGroupsFolder'
    id = 'acl_users'
    isAUserFolder = 1


    #################################################################
    #
    # Setting up all ZMI management screens and default login pages
    #
    #################################################################

    manage_options=(
        (
        {'label' : 'Configure',	'action' : 'manage_main', 
         'help'  : ('LDAPUserGroupsFolder','Configure.stx')},
        {'label' : 'LDAP Schema', 'action' : 'manage_ldapschema',
         'help'  : ('LDAPUserGroupsFolder', 'Schema.stx')},
        {'label' : 'Caches', 'action' : 'manage_cache',
         'help'  : ('LDAPUserGroupsFolder', 'Caches.stx')},
        {'label' : 'Users', 'action' : 'manage_userrecords',
         'help'  : ('LDAPUserGroupsFolder', 'Users.stx')},
        {'label' : 'Roles', 'action' : 'manage_grouprecords',
         'help' : ('LDAPUserGroupsFolder', 'Groups.stx')},
        {'label' : 'Groups', 'action' : 'manage_usergrouprecords',
         'help' : ('LDAPUserGroupsFolder', 'UserGroups.stx')},
        {'label' : 'Log', 'action' : 'manage_log',
         'help'  : ('LDAPUserGroupsFolder', 'Log.stx')},
        )
        + SimpleItem.manage_options
        ) 

    security.declareProtected(view_management_screens, 'manage')
    security.declareProtected(view_management_screens, 'manage_main')
    manage = manage_main = DTMLFile('dtml/properties', globals())
    manage_main._setName('manage_main')
    
    security.declareProtected(view_management_screens, 'manage_ldapschema')
    manage_ldapschema = DTMLFile('dtml/ldapschema', globals())
    
    security.declareProtected(view_management_screens, 'manage_log')
    manage_log = DTMLFile('dtml/log', globals())

    security.declareProtected(view_management_screens, 'manage_cache')
    manage_cache = DTMLFile('dtml/cache', globals())

    security.declareProtected(view_management_screens, 'manage_userrecords')
    manage_userrecords = DTMLFile('dtml/users', globals())
    
    security.declareProtected(view_management_screens, 'manage_grouprecords')
    manage_grouprecords = DTMLFile('dtml/groups', globals())
    
    security.declareProtected(view_management_screens, 'manage_usergrouprecords')
    manage_usergrouprecords = DTMLFile('dtml/usergroups', globals())

    #################################################################
    #
    # Initialization code
    #
    #################################################################


    def __setstate__(self, v):
        """
            __setstate__ is called whenever the instance is loaded
            from the ZODB, like when Zope is restarted.
        """
        # Call inherited __setstate__ methods if they exist
        LDAPUserFolder.inheritedAttribute('__setstate__')(self, v)

        # Reset log
        self._log = SimpleLog()

        # Reset user caches
        anon_timeout = self.getCacheTimeout('anonymous')
        self._anonymous_cache = SimpleCache()
        self._anonymous_cache.setTimeout(anon_timeout)

        auth_timeout = self.getCacheTimeout('authenticated')
        self._authenticated_cache = SimpleCache()
        self._authenticated_cache.setTimeout(auth_timeout)

        self._clearCaches()

        # Make sure we always have the verbose attribute, otherwise logs break
        if not hasattr(self, 'verbose'):
            self.verbose = 2

        if self.verbose > 2:
            self._log.log(3, 'LDAPUserGroupsFolder reinitialized by __setstate__')


    def __init__( self, title, LDAP_server, login_attr , users_base
                , users_scope, roles , groups_base, groups_scope
                , usergroups_base, usergroups_scope
                , binduid, bindpwd, binduid_usage, rdn_attr
                , local_groups=0
                , local_usergroups=0
                , encryption='SHA'
                , use_ssl=0, read_only=0, REQUEST=None
                ):
        """ Create a new LDAPUserFolder instance """
        self.verbose = 2    # _log needs it
        self._log = SimpleLog()
        self._delegate = LDAPDelegate()
        self._ldapschema = { 'cn' : { 'ldap_name' : 'cn'
                                    , 'friendly_name' : 'Canonical Name'
                                    , 'multivalued' : ''
                                    , 'public_name' : ''
                                    }
                           , 'sn' : { 'ldap_name' : 'sn'
                                    , 'friendly_name' : 'Last Name'
                                    , 'multivalued' : ''
                                    , 'public_name' : ''
                                    }
                           }

        # Local DN to role/usergroup tree for storing roles
        self._groups_store = OOBTree()
        self._usergroups_store = OOBTree()
        # List of additionally known roles/usergroups
        self._additional_groups = []
        self._additional_usergroups = []
        # Place to store mappings from LDAP group to Zope role
        self._groups_mappings = {}

        # Caching-related
        self._anonymous_cache = SimpleCache()
        self._anonymous_timeout = 600
        self._authenticated_cache = SimpleCache()
        self._authenticated_timeout = 600

        if LDAP_server.find(':') != -1:
            self.LDAP_server = LDAP_server.split(':')[0].strip()
            self.LDAP_port = int(LDAP_server.split(':')[1])
        else:
            if use_ssl:
                self.LDAP_port = 636
            else:
                self.LDAP_port = 389

            self.LDAP_server = LDAP_server.strip()

        if not not use_ssl:
            self._conn_proto = 'ldaps'
        else:
            self._conn_proto = 'ldap'

        self._delegate.addServer( self.LDAP_server
                                , self.LDAP_port
                                , use_ssl
                                )

        self.manage_edit( title, login_attr, users_base, users_scope
                        , roles, groups_base, groups_scope
                        , usergroups_base, usergroups_scope
                        , binduid
                        , bindpwd, binduid_usage, rdn_attr, 'top,person'
                        , local_groups
                        , local_usergroups
                        , encryption, read_only
                        )


    security.declarePrivate('_clearCaches')
    def _clearCaches(self):
        """ Clear all logs and caches for user-related information """
        self._anonymous_cache.clear()
        self._authenticated_cache.clear()
        self._log.clear()
        self._v_userlist = []
        self._v_userlistexpire = 0


    security.declarePrivate('_lookupuser')
    def _lookupuser(self, uid, pwd=None):
        """
            returns a unique RID and the groups a uid belongs to 
            as well as a dictionary containing user attributes
            and also the usergroups
        """
        if self._login_attr == 'dn':
            users_base = uid
            search_str = '(objectClass=*)'
        else:
            users_base = self.users_base
            ob_flt = [filter_format('(%s=%s)', (self._login_attr, uid))]
            ob_flt.extend( [filter_format('(%s=%s)', ('objectClass', o))
                            for o in self._user_objclasses] )
            search_str = '(&%s)' % ''.join(ob_flt)

        # Step 1: Bind either as the Manager or anonymously to look
        #         up the user from the login given
        if self._binduid_usage > 0:
            bind_dn = self._binduid
            bind_pwd = self._bindpwd
        else:
            bind_dn = bind_pwd = ''

        if self.verbose > 8:
            msg = '_lookupuser: Binding as "%s:%s"' % (bind_dn, bind_pwd)
            self._log.log(9, msg)
            msg = '_lookupuser: Using filter "%s"' % search_str
            self._log.log(9, msg)

        known_attrs = self.getSchemaConfig().keys()

        res = self._delegate.search( base=users_base
                                   , scope=self.users_scope
                                   , filter=search_str
                                   , attrs=known_attrs
                                   , bind_dn=bind_dn
                                   , bind_pwd=bind_pwd
                                   )

        if res['size'] == 0 or res['exception']:
            msg = '_lookupuser: No user "%s" (%s)' % (uid, res['exception'])
            self.verbose > 3 and self._log.log(4, msg)
            return None, None, None, None

        user_attrs = res['results'][0]
        dn = user_attrs.get('dn')
        utf8_dn = to_utf8(dn)

        if pwd is not None:
            # Step 2: Re-bind using the password passed in and the DN we
            #         looked up in Step 1. This will catch bad passwords.
            if self._binduid_usage != 1:
                user_dn = dn
                user_pwd = pwd
            else:
                user_dn = self._binduid
                user_pwd = self._bindpwd

                # Even though I am going to use the Manager DN and password
                # for the "final" lookup I *must* ensure that the password
                # is not a bad password. Since LDAP passwords
                # are one-way encoded I must ask the LDAP server to verify
                # the password, I cannot do it myself.
                try:
                    self._delegate.connect(bind_dn=utf8_dn, bind_pwd=pwd)
                except:
                    # Something went wrong, most likely bad credentials
                    msg = '_lookupuser: Binding as "%s:%s" fails' % (dn, pwd)
                    self.verbose > 3 and self._log.log(4, msg)
                    return None, None, None, None

            if self.verbose > 8:
                msg = '_lookupuser: Re-binding as "%s:%s"' % (user_dn,user_pwd)
                self._log.log(9, msg)

            auth_res = self._delegate.search( base=utf8_dn
                                            , scope=BASE
                                            , filter='(objectClass=*)'
                                            , attrs=known_attrs
                                            , bind_dn=user_dn
                                            , bind_pwd=user_pwd
                                            )

            if auth_res['size'] == 0 or auth_res['exception']:
                msg = '_lookupuser: "%s" lookup fails bound as "%s"' % (dn, dn)
                self.verbose > 3 and self._log.log(4, msg)
                return None, None, None, None
            
            user_attrs = auth_res['results'][0]

        else:
            user_pwd = pwd

        self.verbose > 4 and self._log.log(5,
             '_lookupUser: user_attrs = %s' % str(user_attrs))

        groups = list(self.getGroups(dn=dn, attr='cn', pwd=user_pwd))
        roles = self._mapRoles(groups)
        roles.extend(self._roles)
        usergroups = list(self.getUserGroups(dn=dn, attr='cn', pwd=user_pwd))

        return roles, dn, user_attrs, usergroups


    security.declareProtected(manage_users, 'manage_reinit')
    def manage_reinit(self, REQUEST=None):
        """ re-initialize and clear out users and log """
        self._clearCaches()
        self._v_conn = None
        self.verbose > 2 and self._log.log(3, 'Cleared caches on Caches tab')

        if REQUEST:
            msg = 'User caches cleared'
            return self.manage_cache(manage_tabs_message=msg)


    security.declarePrivate('_setProperty')
    def _setProperty(self, prop_name, prop_value):
        """ Set a property on the LDAP User Folder object """
        if not hasattr(self, prop_name):
            msg = 'No property "%s" on the LDAP User Folder' % prop_name
            raise AttributeError, msg

        setattr(self, prop_name, prop_value)


    security.declareProtected(EDIT_PERMISSION, 'manage_changeProperty')
    def manage_changeProperty( self
                             , prop_name
                             , prop_value
                             , client_form='manage_main'
                             , REQUEST=None
                             ):
        """ The public front end for changing single properties """
        try:
            self._setProperty(prop_name, prop_value)
            self._clearCaches()
            msg = 'Attribute "%s" changed.' % prop_name
        except AttributeError, e:
            msg = e.args[0]

        if REQUEST is not None:
            form = getattr(self, client_form)
            return form(manage_tabs_message=msg)


    security.declareProtected(EDIT_PERMISSION, 'manage_edit')
    def manage_edit( self, title, login_attr, users_base
                   , users_scope, roles,  groups_base, groups_scope
                   , usergroups_base, usergroups_scope
                   , binduid, bindpwd, binduid_usage=1, rdn_attr='cn'
                   , obj_classes='top,person', local_groups=0
                   , local_usergroups=0
                   , encryption='SHA', read_only=0, REQUEST=None
                   ):
        """ Edit the LDAPUserFolder Object """
        if not binduid:
            binduid_usage = 0

        self.title = title
        self.users_base = users_base
        self.users_scope = users_scope
        self.groups_base = groups_base or users_base
        self.groups_scope = groups_scope
        self.usergroups_base = usergroups_base or users_base
        self.usergroups_scope = usergroups_scope
        self.read_only = not not read_only

        self._delegate.edit( login_attr, users_base, rdn_attr
                           , obj_classes, binduid, bindpwd
                           , binduid_usage, read_only
                           )

        if isinstance(roles, StringType):
            roles = [x.strip() for x in roles.split(',')]
        self._roles = roles

        self._binduid = binduid
        self._bindpwd = bindpwd
        self._binduid_usage = int(binduid_usage)

        self._local_groups = not not local_groups
        self._local_usergroups = not not local_usergroups

        if encryption == 'crypt' and crypt is None:
            encryption = 'SHA'

        self._pwd_encryption = encryption

        if isinstance(obj_classes, StringType):
            obj_classes = [x.strip() for x in obj_classes.split(',')]
        self._user_objclasses = obj_classes

        my_attrs = self.getSchemaConfig().keys()

        if rdn_attr not in my_attrs:
            self.manage_addLDAPSchemaItem( ldap_name=rdn_attr
                                         , friendly_name=rdn_attr
                                         )
        self._rdnattr = rdn_attr

        if login_attr not in my_attrs:
            self.manage_addLDAPSchemaItem( ldap_name=login_attr
                                         , friendly_name=login_attr
                                         )
        self._login_attr = login_attr
        
        self._clearCaches()
        self.verbose > 1 and self._log.log(2, 'Properties changed')
        msg = 'Properties changed'

        connection = self._delegate.connect()
        if connection is None:
            msg = 'Cannot+connect+to+LDAP+server'

        if REQUEST:
            return self.manage_main(manage_tabs_message=msg)


    security.declareProtected(manage_users, 'manage_addServer')
    def manage_addServer(self, host, port='389', use_ssl=0, REQUEST=None):
        """ Add a new server to the list of servers in use """
        self._delegate.addServer(host, port, use_ssl)
        msg = 'Server at %s:%s added' % (host, port)

        if REQUEST:
            return self.manage_main(manage_tabs_message=msg)


    security.declareProtected(manage_users, 'getServers')
    def getServers(self):
        """ Proxy method used for the ZMI """
        return tuple(self._delegate.getServers())


    security.declareProtected(manage_users, 'manage_deleteServers')
    def manage_deleteServers(self, position_list=[], REQUEST=None):
        """ Delete servers from the list of servers in use """
        if len(position_list) == 0:
            msg = 'No servers selected'
        else:
            self._delegate.deleteServers(position_list)
            msg = 'Servers deleted'

        if REQUEST:
            return self.manage_main(manage_tabs_message=msg)


    security.declareProtected(manage_users, 'getMappedUserAttrs')
    def getMappedUserAttrs(self):
        """ Return the mapped user attributes """
        schema = self.getSchemaDict()
        pn = 'public_name'
        ln = 'ldap_name'

        return tuple([(x[ln], x[pn]) for x in schema if x.get(pn, '')])


    security.declareProtected('manage_users', 'getMultivaluedUserAttrs')
    def getMultivaluedUserAttrs(self):
        """ Return sequence of user attributes that are multi-valued"""
        schema = self.getSchemaDict()
        mv = [x['ldap_name'] for x in schema if x.get('multivalued', '')]

        return tuple(mv)


    security.declareProtected(manage_users, 'getUsers')
    def getUsers(self, authenticated=1):
        """Return a list of *cached* user objects"""
        if authenticated:
            return self._authenticated_cache.getCache()
        else:
            return self._anonymous_cache.getCache()


    security.declareProtected(manage_users, 'getUserNames')
    def getUserNames(self):
        """ Return a list of usernames """
        if not hasattr(self,'_v_userlistexpire'):
            self._v_userlistexpire = 0

        if self._v_userlistexpire > time.time():
            return self._v_userlist

        s = {}
        lscope = ldap_scopes[self.users_scope]
        login_attr = self._login_attr

        if login_attr == 'dn':
            wanted_attrs = []
        else:
            wanted_attrs = [login_attr]

        res = self._delegate.search( base=self.users_base
                                   , scope=self.users_scope
                                   , attrs=wanted_attrs
                                   )

        if res['size'] == 0 or res['exception']:
            msg = 'getUserNames: Cannot find any users (%s)' % res['exception']
            self._log.log(2, msg)

            return []

        result_dicts = res['results']
        for i in range(res['size']):
            if login_attr != 'dn':
                name_list = result_dicts[i].get(login_attr, [])
            else:
                name_list = result_dicts[i].get(login_attr)

            for name in name_list:
                s[name] = None

        self._v_userlist = s.keys()
        self._v_userlist.sort()
        self._v_userlistexpire = time.time() + 600 # Expire after 600 secs

        return self._v_userlist


    security.declareProtected(manage_users, 'getUser')
    def getUser(self, name, pwd=None):
        """Return the named user object or None"""
        if pwd is not None:
            cache_type = 'authenticated'
            cached_user = self._authenticated_cache.get(name, pwd)
        else:
            cache_type = 'anonymous'
            cached_user = self._anonymous_cache.get(name)

        if cached_user:
            if self.verbose > 6:
                msg = 'getUser: "%s" cached in %s cache' % (name, cache_type)
                self._log.log(7, msg)
            return cached_user

        user_roles, user_dn, user_attrs, user_groups = self._lookupuser(uid=name, pwd=pwd)
        if user_dn is None:
            msg = 'getUser: "%s" not found' % name
            self.verbose > 3 and self._log.log(4, msg)
            return None

        if user_attrs is None:
            msg = 'getUser: "%s" has no properties, bailing' % name
            self.verbose > 3 and self._log.log(4, msg)
            return None

        if user_roles is None or user_roles == self._roles:
            msg = 'getUser: "%s" only has roles %s' % (name, str(user_roles))
            self.verbose > 8 and self._log.log(9, msg)

        login_name = user_attrs.get(self._login_attr)
        if self._login_attr != 'dn':
            login_name = login_name[0]

        user_obj = LDAPUser( login_name
                           , pwd or 'undef'
                           , user_roles or []
                           , user_groups or []
                           , []
                           , user_dn
                           , user_attrs
                           , self.getMappedUserAttrs()
                           , self.getMultivaluedUserAttrs()
                           )

        if pwd is not None:
            self._authenticated_cache.set(name, user_obj)
        else:
            self._anonymous_cache.set(name, user_obj)

        return user_obj


    security.declareProtected(manage_users, 'getUserById')
    def getUserById(self, id, default=_marker):
        """ Return a user object by ID (in this case by username) """
        try:
            return self.getUser(id)

        except:
            if default is _marker: 
                raise

            return default


    def getUserByDN(self, user_dn):
        """ Make a user object from a DN """
        res = self._delegate.search( base=user_dn
                                   , scope=BASE
                                   , attrs=[self._login_attr]
                                   )

        if res['exception'] or res['size'] == 0:
            return None

        user_id = res['results'][0].get(self._login_attr)[0]
        user_obj = self.getUser(user_id)

        return user_obj


    def authenticate(self, name, password, request):
        super = self._emergency_user

        if not name:
            return None

        if super and name == super.getUserName():
            user = super
        else:
            user = self.getUser(name, password)

        if user is not None:
            domains = user.getDomains()
            if domains:
                return (domainSpecMatch(domains, request) and user) or None
            
        return user


    #################################################################
    #
    # Stuff formerly in LDAPShared.py
    #
    #################################################################

    security.declareProtected(manage_users, 'getUserDetails')
    def getUserDetails(self, encoded_dn, format=None, attrs=[]):
        """ Return all attributes for a given DN """
        dn = to_utf8(urllib.unquote(encoded_dn))

        res = self._delegate.search( base=dn
                                   , scope=BASE
                                   , attrs=attrs
                                   )

        if res['exception']:
            if format == None:
                result = ((res['exception'], res),)
            elif format == 'dictionary':
                result = { 'cn': '###Error: %s' % res['exception'] }
        elif res['size'] > 0:
            value_dict = res['results'][0]

            if format == None:
                result = value_dict.items()
                result.sort()
            elif format == 'dictionary':
                result = value_dict
        else:
            if format == None:
                result = ()
            elif format == 'dictionary':
                result = {}

        return result


    security.declareProtected(manage_users, 'getGroupDetails')
    def getGroupDetails(self, encoded_cn):
        """ Return all group details """
        result = ()
        cn = urllib.unquote(encoded_cn)

        if not self._local_groups:
            res = self._delegate.search( base=self.groups_base
                                       , scope=self.groups_scope
                                       , filter=filter_format('(cn=%s)', (cn,))
                                       , attrs=['uniqueMember', 'member']
                                       )

            if res['exception']:
                exc = res['exception']
                msg = 'getGroupDetails: No group "%s" (%s)' % (cn, exc)
                self._log.log(3, msg)
                result = (('Exception', exc),)

            elif res['size'] > 0:
                result = res['results'][0].items()
                result.sort()

            else:
                msg = 'getGroupDetails: No group "%s"' % cn
                self._log.log(3, msg)

        else:
            g_dn = ''
            all_groups = self.getGroups()
            for group_cn, group_dn in all_groups:
                if group_cn == cn:
                    g_dn = group_dn
                    break

            if g_dn:
                users = []

                for user_dn, role_dns in self._groups_store.items():
                    if g_dn in role_dns:
                        users.append(user_dn)

                result = [('', users)]

        return result


    security.declareProtected(manage_users, 'getUserGroupDetails')
    def getUserGroupDetails(self, cn):
        """Return all user group details."""
        result = ()

        if not self._local_usergroups:
            res = self._delegate.search( base=self.usergroups_base
                                       , scope=self.usergroups_scope
                                       , filter=filter_format('(cn=%s)', (cn,))
                                       , attrs=['uniqueMember', 'member']
                                       )

            if res['exception']:
                exc = res['exception']
                msg = 'getUserGroupDetails: No usergroup "%s" (%s)' % (cn, exc)
                self._log.log(3, msg)
                result = (('Exception', exc),)

            elif res['size'] > 0:
                result = res['results'][0].items()
                result.sort()

            else:
                msg = 'getUserGroupDetails: No user group "%s"' % cn
                self._log.log(3, msg)

        else:
            g_dn = cn
            users = []
            for user_dn, usergroup_dns in self._usergroups_store.items():
                if g_dn in usergroup_dns:
                    users.append(user_dn)
            result = [('', users)]

        return result


    security.declareProtected(manage_users, 'getGroupedUsers')
    def getGroupedUsers(self, groups=None):
        """ Return all those users that are in a group """
        all_dns = {}
        users = []
        member_attrs = GROUP_MEMBER_MAP.values()

        if groups is None:
            groups = self.getGroups()

        for group_id, group_dn in groups:
            group_details = self.getGroupDetails(group_id)
            for key, vals in group_details:
                if key in member_attrs or key == '':
                    # If the key is an empty string then the groups are
                    # stored inside the user folder itself.
                    for dn in vals:
                        all_dns[dn] = 1

        for dn in all_dns.keys():
            try:
                user = self.getUserByDN(dn)
            except: 
                user = None

            if user is not None:
                users.append(user.__of__(self))

        return tuple(users)


    security.declareProtected(manage_users, 'getLocalUsers')
    def getLocalUsers(self):
        """ Return all those users who are in locally stored groups """
        local_users = []

        for user_dn, user_roles in self._groups_store.items():
            local_users.append((user_dn, user_roles))

        return tuple(local_users)


    security.declareProtected(manage_users, 'findUser')
    def findUser(self, search_param, search_term, attrs=[]):
        """ Look up matching user records based on attributes """
        lscope = ldap_scopes[self.users_scope]
        users  = []

        if search_param == 'dn':
            users_base = search_term
            search_str = '(objectClass=*)'
        else:
            users_base = self.users_base
            if search_term:
                search_str = filter_format( '(%s=*%s*)'
                                          , (search_param, search_term)
                                          )
            else:
                search_str = '(%s=*)' % search_param

        res = self._delegate.search( base=users_base
                                   , scope=self.users_scope
                                   , filter=search_str
                                   , attrs=attrs
                                   )

        if res['exception']:
            msg = 'findUser Exception (%s)' % res['exception']
            self.verbose > 1 and self._log.log(2, msg)
            msg = 'findUser searched term "%s", param "%s"' % ( search_term
                                                              , search_param
                                                              )
            self.verbose > 8 and self._log.log(9, msg)
            users = [{ 'dn' : res['exception']
                     , 'cn' : 'n/a'
                     , 'sn' : 'Error'
                     }]

        elif res['size'] > 0:
            res_dicts = res['results']
            for i in range(res['size']):
                dn = res_dicts[i].get('dn')
                rec_dict = {}
                rec_dict['sn'] = rec_dict['cn'] = ''

                for key, val in res_dicts[i].items():
                    rec_dict[key] = val[0]

                rec_dict['dn'] = dn

                users.append(rec_dict)

        return users


    security.declareProtected(manage_users, 'getGroups')
    def getGroups(self, dn='*', attr=None, pwd=''):
        """
            returns a list of possible groups from the ldap tree
            (Used e.g. in showgroups.dtml) or, if a DN is passed
            in, all groups for that particular DN.
        """
        group_list = []
        no_show = ('Anonymous', 'Authenticated', 'Shared')

        if self._local_groups:
            if dn != '*':
                all_groups_list = self._groups_store.get(dn) or []
            else:
                all_groups_dict = {}
                zope_roles = list(self.valid_roles())
                zope_roles.extend(list(self._additional_groups))

                for role_name in zope_roles:
                    if role_name not in no_show:
                        all_groups_dict[role_name] = 1

                all_groups_list = all_groups_dict.keys()

            for group in all_groups_list:
                if attr is None:
                    group_list.append((group, group))
                else:
                    group_list.append(group)

            group_list.sort()

        else:
            gscope = ldap_scopes[self.groups_scope]

            if dn != '*':
                f_template = '(&(objectClass=%s)(%s=%s))'
                group_filter = '(|'

                for g_name, m_name in GROUP_MEMBER_MAP.items():
                    fltr = filter_format(f_template, (g_name, m_name, dn))
                    group_filter += fltr

                group_filter += ')'
                    
            else:
                group_filter = '(|'

                for g_name in GROUP_MEMBER_MAP.keys():
                    fltr = filter_format('(objectClass=%s)', (g_name,))
                    group_filter += fltr

                group_filter += ')'

            res = self._delegate.search( base=self.groups_base
                                       , scope=gscope
                                       , filter=group_filter
                                       , attrs=['cn']
                                       , bind_dn=''
                                       , bind_pwd=''
                                       )

            exc = res['exception']
            if exc:
                if attr is None:
                    group_list = (('', exc),)
                else:
                    group_list = (exc,)
            elif res['size'] > 0:
                res_dicts = res['results']
                for i in range(res['size']):
                    dn = res_dicts[i].get('dn')
                    try:
                        cn = res_dicts[i]['cn'][0]
                    except KeyError:    # NDS oddity
                        cn = explode_dn(dn, 1)[0]

                    if attr is None:
                        group_list.append((cn, dn))
                    elif attr == 'cn':
                        group_list.append(cn)
                    elif attr == 'dn':
                        group_list.append(dn)

        return group_list


    security.declareProtected(manage_users, 'getUserGroups')
    def getUserGroups(self, dn='*', attr=None, pwd=''):
        """
            returns a list of possible user groups from the ldap tree
            (Used e.g. in usergroups.dtml) or, if a DN is passed
            in, all user groups for that particular DN.
        """
        usergroup_list = []

        if self._local_usergroups:
            if dn != '*':
                all_usergroups_list = self._usergroups_store.get(dn) or []
            else:
                all_usergroups_list = self._additional_usergroups

            for usergroup in all_usergroups_list:
                if attr is None:
                    usergroup_list.append((usergroup, usergroup))
                else:
                    usergroup_list.append(usergroup)

            usergroup_list.sort()

        else:
            ugscope = ldap_scopes[self.usergroups_scope]

            if dn != '*':
                f_template = '(&(objectClass=%s)(%s=%s))'
                usergroup_filter = '(|'

                for g_name, m_name in GROUP_MEMBER_MAP.items():
                    fltr = filter_format(f_template, (g_name, m_name, dn))
                    usergroup_filter += fltr

                usergroup_filter += ')'

            else:
                usergroup_filter = '(|'

                for g_name in GROUP_MEMBER_MAP.keys():
                    fltr = filter_format('(objectClass=%s)', (g_name,))
                    usergroup_filter += fltr

                usergroup_filter += ')'

            res = self._delegate.search( base=self.usergroups_base
                                       , scope=ugscope
                                       , filter=usergroup_filter
                                       , attrs=['cn']
                                       , bind_dn=''
                                       , bind_pwd=''
                                       )

            exc = res['exception']
            if exc:
                if attr is None:
                    usergroup_list = (('', exc),)
                else:
                    usergroup_list = (exc,)
            elif res['size'] > 0:
                res_dicts = res['results']
                for i in range(res['size']):
                    dn = res_dicts[i].get('dn')
                    try:
                        cn = res_dicts[i]['cn'][0]
                    except KeyError:    # NDS oddity
                        cn = explode_dn(dn, 1)[0]

                    if attr is None:
                        usergroup_list.append((cn, dn))
                    elif attr == 'cn':
                        usergroup_list.append(cn)
                    elif attr == 'dn':
                        usergroup_list.append(dn)

        return usergroup_list

    security.declareProtected(manage_users, 'getGroupType')
    def getGroupType(self, group_dn):
        """ get the type of group """
        if self._local_groups:
            if group_dn in self._additional_groups:
                group_type = 'Custom Role'
            else:
                group_type = 'Zope Built-in Role'

        else:
            group_type = 'n/a'
            res = self._delegate.search( base=group_dn
                                       , scope=BASE
                                       , attrs=['objectClass']
                                       )

            if res['exception']:
                msg = 'getGroupType: No group "%s" (%s)' % ( group_dn
                                                           , res['exception']
                                                           )
                self.verbose > 1 and self._log.log(2, msg)

            else:
                groups = GROUP_MEMBER_MAP.keys()
                l_groups = [x.lower() for x in groups]
                g_attrs = res['results'][0]
                group_obclasses = g_attrs.get('objectClass', [])
                group_obclasses.extend(g_attrs.get('objectclass', []))
                g_types = [x for x in group_obclasses if x.lower() in l_groups]

                if len(g_types) > 0:
                    group_type = g_types[0]

        return group_type


    security.declareProtected(manage_users, 'getUserGroupType')
    def getUserGroupType(self, usergroup_dn):
        """ get the type of user group """
        if self._local_usergroups:
            if usergroup_dn in self._additional_usergroups:
                group_type = 'Custom Group'
            else:
                group_type = 'Zope Built-in Group'

        else:
            usergroup_type = 'n/a'
            res = self._delegate.search( base=usergroup_dn
                                       , scope=BASE
                                       , attrs=['objectClass']
                                       )

            if res['exception']:
                msg = 'getUserGroupType: No group "%s" (%s)' % (
                    usergroup_dn, res['exception'])
                self.verbose > 1 and self._log.log(2, msg)

            else:
                groups = GROUP_MEMBER_MAP.keys()
                l_groups = [x.lower() for x in groups]
                g_attrs = res['results'][0]
                group_obclasses = g_attrs.get('objectClass', [])
                group_obclasses.extend(g_attrs.get('objectclass', []))
                g_types = [x for x in group_obclasses if x.lower() in l_groups]

                if len(g_types) > 0:
                    usergroup_type = g_types[0]

        return usergroup_type


    security.declareProtected(manage_users, 'getGroupMappings')
    def getGroupMappings(self):
        """ Return the dictionary that maps LDAP groups map to Zope roles """
        mappings = getattr(self, '_groups_mappings', {})

        return mappings.items()


    security.declareProtected(manage_users, 'manage_addGroupMapping')
    def manage_addGroupMapping(self, group_name, role_name, REQUEST=None):
        """ Map a LDAP group to a Zope role """
        mappings = getattr(self, '_groups_mappings', {})
        mappings[group_name] = role_name

        self._groups_mappings = mappings
        self._clearCaches()
        msg = 'Added LDAP group to Zope role mapping: %s -> %s' % (
                group_name, role_name)

        if REQUEST:
            return self.manage_grouprecords(manage_tabs_message=msg)


    security.declareProtected(manage_users, 'manage_deleteGroupMappings')
    def manage_deleteGroupMappings(self, group_names, REQUEST=None):
        """ Delete mappings from LDAP group to Zope role """
        mappings = getattr(self, '_groups_mappings', {})

        for group_name in group_names:
            if mappings.has_key(group_name):
                del mappings[group_name]

        self._groups_mappings = mappings
        self._clearCaches()
        msg = 'Deleted LDAP group to Zope role mapping for: %s' % (
            ', '.join(group_names))

        if REQUEST:
            return self.manage_grouprecords(manage_tabs_message=msg)


    def _mapRoles(self, groups):
        """ Perform the mapping of LDAP groups to Zope roles """
        mappings = getattr(self, '_groups_mappings', {})
        roles = []
        
        for group in groups:
            roles.append(group)
            mapped_role = mappings.get(group, None)
            if mapped_role is not None and mapped_role not in roles:
                roles.append(mapped_role)

        return roles


    security.declareProtected(view_management_screens, 'getProperty')
    def getProperty(self, prop_name, default=''):
        """ Get at LDAPUserFolder properties """
        return getattr(self, prop_name, default)


    security.declareProtected(manage_users, 'getLDAPSchema')
    def getLDAPSchema(self):
        """ Retrieve the LDAP schema this product knows about """
        raw_schema = self.getSchemaDict()
        schema = [(x['ldap_name'], x['friendly_name']) for x in raw_schema]
        schema.sort()

        return tuple(schema)


    security.declareProtected(manage_users, 'getSchemaDict')
    def getSchemaDict(self):
        """ Retrieve schema as list of dictionaries """
        all_items = self.getSchemaConfig().values()
        all_items.sort()

        return tuple(all_items)


    security.declareProtected(EDIT_PERMISSION, 'setSchemaConfig')
    def setSchemaConfig(self, schema):
        """ Set the LDAP schema configuration """
        self._ldapschema = schema
        self._clearCaches()


    security.declareProtected(manage_users, 'getSchemaConfig')
    def getSchemaConfig(self):
        """ Retrieve the LDAP schema configuration """
        return self._ldapschema


##     # UserGroupsFolder specific APIs XXX needed ?

##     security.declareProtected(manage_users, 'userFolderAddGroup')
##     def userFolderAddGroup(self, groupname, **kw):
##         """Creates a group"""
##         self.manage_addUserGroup(groupname)


##     security.declareProtected(manage_users, 'userFolderDelGroups')
##     def userFolderDelGroups(self, groupnames):
##         """Deletes groups"""
##         self.manage_deleteUserGroups(groupnames)

    def _getMappedProperties(self):
        """Get a list of tuples for (ldap_attr, public_attr).

        login_attr -> 'id' is always considered a mapping.
        """
        mapped = []
        login_attr = self._login_attr
        has_login = 0
        for ldap_attr, names in self.getSchemaConfig().items():
            public_name = names['public_name']
            if public_name:
                mapped.append((ldap_attr, public_name))
        mapped.append((login_attr, 'id'))
        return mapped

    def _addMappedPropertiesToEntry(self, entry, mapped):
        """Add mapped properties to entry."""
        for ldap_attr, public_attr in mapped:
            if entry.has_key(ldap_attr):
                entry[public_attr] = entry[ldap_attr]

    def _removeMappedPropertiesFromEntry(self, entry, mapped):
        """Remove mapped properties from entry."""
        for ldap_attr, public_attr in mapped:
            if entry.has_key(public_attr):
                entry[ldap_attr] = entry[public_attr]
                del entry[public_attr]


    def _searchWithFilter(self, filter, roles=None, groups=None, attrs=[]):
        """Do a search on users.

        Uses the given filter, and also filters on roles and groups.
        """
        if not filter:
            filter = '(objectClass=*)'

        from zLOG import LOG, DEBUG
        LOG('_searchWithFilter', DEBUG, 'filter=%s' % filter)

        res = self._delegate.search(base=self.users_base,
                                    scope=self.users_scope,
                                    filter=filter,
                                    attrs=attrs)
        err = res['exception']
        if err:
            msg = "searchUsers Exception (%s)" % err
            if self.verbose > 1:
                self._log.log(2, msg)
            return err

        results = res['results']

        if roles or groups:
            member_attrs = GROUP_MEMBER_MAP.values() + ['']
            role_dns = {}
            for role in roles or []:
                for key, user_dns in self.getGroupDetails(role):
                    if key in member_attrs:
                        for dn in user_dns:
                            role_dns[_normalizeDN(dn)] = None
            group_dns = {}
            for group in groups or []:
                for key, user_dns in self.getUserGroupDetails(group):
                    if key in member_attrs:
                        for dn in user_dns:
                            group_dns[_normalizeDN(dn)] = None

            # Intersect dns
            if roles and not groups:
                dns = role_dns
            elif groups and not roles:
                dns = group_dns
            else: # roles and groups
                if len(role_dns) < len(group_dns):
                    small, big = role_dns, group_dns
                else:
                    small, big = group_dns, role_dns
                # Intersect
                dns = {}
                for dn in small.keys():
                    if big.has_key(dn):
                        dns[dn] = None

            # Filter by those dns.
            results = [e for e in results
                       if dns.has_key(_normalizeDN(e['dn']))]

            # XXX FIXME The results entries are missing roles and groups
            # props (if in attrs)... But fixing it means requerying them
            # for all entries.

        return results

    #
    # Extended User Folder API
    #

    def listUserProperties(self):
        """Lists properties settable or searchable on the users."""
        schema = self.getSchemaConfig()
        attrs = {
            'id': None,
            'roles': None,
            'groups': None,
            'dn': None,
            }
        for attr, names in schema.items():
            attrs[attr] = None
            if names.get('public_name'):
                # Add mapped attribute.
                attrs[names['public_name']] = None
        return attrs.keys()

    def searchUsers(self, query={}, props=None, options=None, **kw):
        """Search for users having certain properties.

        If props is None, returns a list of ids:
          ['user1', 'user2']

        If props is not None, it must be sequence of property ids. The
        method will return a list of tuples containing the user id and a
        dictionary of available properties:
          [('user1', {'email': 'foo', 'age': 75}), ('user2', {'age': 5})]
        """
        allowed_props = self.listUserProperties()
        mapped = self._getMappedProperties()
        kw.update(query)
        query = kw
        self._removeMappedPropertiesFromEntry(query, mapped)

        filter_elems = []
        for key, value in query.items():
            if key not in allowed_props:
                continue
            if key in ('roles', 'groups'):
                # Treated specially.
                continue
            if key == 'dn': # XXX treat it
                continue
            if not value:
                continue
            if value == '*':
                value = ''
            if isinstance(value, StringType):
                if value:
                    f = filter_format('(%s=*%s*)', (key, value))
                else:
                    f = filter_format('(%s=*)', (key,))
            elif isinstance(value, ListType) or isinstance(value, TupleType):
                fl = []
                for v in value:
                    fv = filter_format('(%s=%s)', (key, v))
                    fl.append(fv)
                f = ''.join(fl)
                if len(fl) > 1:
                    f = '(|%s)' % f
            else:
                raise ValueError("Bad value %s for '%s'" % `value`, key)
            filter_elems.append(f)
        filter = ''.join(filter_elems)
        if len(filter_elems) > 1:
            filter = '(&%s)' % filter

        # Do the search.

        if props is None:
            attrs = []
        else:
            attrs = [p for p in props if p in allowed_props]
        login_attr = self._login_attr
        if login_attr not in attrs:
            attrs.append(login_attr)

        results = self._searchWithFilter(filter,
                                         roles=query.get('roles'),
                                         groups=query.get('groups'),
                                         attrs=attrs)

        if isinstance(results, StringType):
            err = results
            msg = "searchUsers Exception (%s)" % err
            if self.verbose > 1:
                self._log.log(2, msg)
            if props is None:
                return [err]
            else:
                return [(err, {})]

        # Prepare the results.

        if props is None:
            if login_attr == 'dn':
                return [e['dn'] for e in results]
            else:
                return [e[login_attr][0] for e in results]

        schema = self.getSchemaConfig()
        users = []
        for e in results:
            entry = {}
            for attr, value in e.items():
                if attr == 'dn':
                    pass
                elif schema.get(attr, {}).get('multivalued'):
                    pass
                else:
                    value = '; '.join(value)
                entry[attr] = value
                if attr == login_attr:
                    id = value
            self._addMappedPropertiesToEntry(entry, mapped)
            users.append((id, entry))

        return users

    #
    # CPS User Folder behavior.
    # XXX In need of refactoring.
    #

    def _getUserLoginFromDN(self, user_dn):
        """Return the login of a user from its DN.

        Returns None if the DN is invalid.
        """
        # Check if we can get the login attribute from the dn.
        try:
            rdn = user_dn.split(',')[0]
            rdn_attr, rdn_value = rdn.split('=', 1)
        except (IndexError, ValueError):
            # Invalid DN
            return None
        if rdn_attr == self._login_attr:
            user_id = rdn_value
        else:
            # We have to lookup the user to get its login attribute.
            res = self._delegate.search(base=user_dn,
                                        scope=BASE,
                                        attrs=[self._login_attr]
                                        )
            if res['exception'] or not res['size']:
                return None

            user_id = res['results'][0].get(self._login_attr)[0]
        user_id = _verifyUnicode(user_id).encode(encoding)
        return user_id

    security.declareProtected(manage_users, 'getGroupNames')
    def getGroupNames(self):
        """Return a list of group names."""
        return tuple(self.getUserGroups(attr='cn'))


    security.declareProtected(manage_users, 'getGroupById')
    def getGroupById(self, groupname, default=_marker):
        """Return the given group.

        The only method callable on a group is getUsers().
        """
        member_attrs = GROUP_MEMBER_MAP.values() + ['']
        dns = {}
        result = self.getUserGroupDetails(groupname)
        # XXX Detect if group doesn't exist.
        for key, user_dns in result:
            if key in member_attrs:
                for dn in user_dns:
                    dns[dn] = None
        users = {}
        for dn in dns.keys():
            user_id = self._getUserLoginFromDN(dn)
            if user_id is not None:
                users[user_id] = None
        users = users.keys()

        return CPSGroup(groupname, users)


    security.declareProtected(manage_users, 'userFolderAddRole')
    def userFolderAddRole(self, role):
        """Add a new role."""
        # XXX Should it also be added to the container as zope roles?
        self.manage_addGroup(role)


    security.declareProtected(manage_users, 'userFolderAddGroup')
    def userFolderAddGroup(self, group):
        """Add a new group."""
        self.manage_addUserGroup(group)


    security.declarePrivate('mergedLocalRoles')
    def mergedLocalRoles(self, object, withgroups=0):
        """Return a merging of object and its ancestors' __ac_local_roles__.

        When called with withgroups=1, the keys are
        of the form user:foo and group:bar.
        """
        # Modified from AccessControl.User.getRolesInContext().
        merged = {}
        object = getattr(object, 'aq_inner', object)
        while 1:
            if hasattr(object, '__ac_local_roles__'):
                dict = object.__ac_local_roles__ or {}
                if callable(dict):
                    dict = dict()
                for k, v in dict.items():
                    if withgroups:
                        k = 'user:'+k # groups
                    if merged.has_key(k):
                        merged[k] = merged[k] + v
                    else:
                        merged[k] = v
            # deal with groups
            if withgroups:
                if hasattr(object, '__ac_local_group_roles__'):
                    dict = object.__ac_local_group_roles__ or {}
                    if callable(dict):
                        dict = dict()
                    for k, v in dict.items():
                        k = 'group:'+k
                        if merged.has_key(k):
                            merged[k] = merged[k] + v
                        else:
                            merged[k] = v
            # end groups
            if hasattr(object, 'aq_parent'):
                object = object.aq_parent
                object = getattr(object, 'aq_inner', object)
                continue
            if hasattr(object, 'im_self'):
                object = object.im_self
                object = getattr(object, 'aq_inner', object)
                continue
            break
        return merged

    security.declarePrivate('mergedLocalRolesWithPath')
    def mergedLocalRolesWithPath(self, object, withgroups=0):
        """Return a merging of object and its ancestors' local roles
        with path information.

        When called with withgroups=1, the keys are
        of the form user:foo and group:bar.

        The path (relative to the CMF portal) corresponding to the
        object where the role takes place is added with the role in the
        result. In this case of the form :
        {'user:foo': [{'url':url, 'roles':[Role0, Role1]},
                      {'url':url, 'roles':[Role1]}],..}.

        This method only works if CMF is present.
        """
        if not _cmf_support:
            # No CMF support: now way to take advantages of this feature
            return []
        utool = getToolByName(object, 'portal_url')
        # Modified from AccessControl.User.getRolesInContext().
        merged = {}
        object = getattr(object, 'aq_inner', object)
        while 1:
            if hasattr(object, '__ac_local_roles__'):
                dict = object.__ac_local_roles__ or {}
                if callable(dict):
                    dict = dict()
                obj_url = utool.getRelativeUrl(object)
                for k, v in dict.items():
                    if withgroups:
                        k = 'user:'+k # groups
                    if merged.has_key(k):
                        merged[k].append({'url': obj_url, 'roles': v})
                    else:
                        merged[k] = [{'url': obj_url, 'roles': v}]
            # deal with groups
            if withgroups:
                if hasattr(object, '__ac_local_group_roles__'):
                    dict = object.__ac_local_group_roles__ or {}
                    if callable(dict):
                        dict = dict()
                    obj_url = utool.getRelativeUrl(object)
                    for k, v in dict.items():
                        k = 'group:'+k
                        if merged.has_key(k):
                            merged[k].append({'url': obj_url, 'roles': v})
                        else:
                            merged[k] = [{'url': obj_url, 'roles': v}]
            # end groups
            if hasattr(object, 'aq_parent'):
                object = object.aq_parent
                object = getattr(object, 'aq_inner', object)
                continue
            if hasattr(object, 'im_self'):
                object = object.im_self
                object = getattr(object, 'aq_inner', object)
                continue
            break
        return merged

    def _allowedRolesAndUsers(self, ob):
        """
        Return a list of roles, users and groups with View permission.
        Used by PortalCatalog to filter out items you're not allowed to see.
        """
        allowed = {}
        for r in rolesForPermissionOn('View', ob):
            allowed[r] = 1
        localroles = self.mergedLocalRoles(ob, withgroups=1) # groups
        for user_or_group, roles in localroles.items():
            for role in roles:
                if allowed.has_key(role):
                    allowed[user_or_group] = 1
        if allowed.has_key('Owner'):
            del allowed['Owner']
        return list(allowed.keys())

    #
    # ZMI management
    #

    security.declareProtected(EDIT_PERMISSION, 'manage_addLDAPSchemaItem')
    def manage_addLDAPSchemaItem( self
                                , ldap_name
                                , friendly_name=''
                                , multivalued=''
                                , public_name=''
                                , REQUEST=None
                                ):
        """ Add a schema item to my list of known schema items """
        schema = self.getSchemaConfig()
        if ldap_name not in schema.keys():
            schema[ldap_name] = { 'ldap_name' : ldap_name
                                , 'friendly_name' : friendly_name
                                , 'public_name' : public_name
                                , 'multivalued' : multivalued
                                }

            self.setSchemaConfig(schema)
            msg = 'LDAP Schema item "%s" added' % ldap_name
        else:
            msg = 'LDAP Schema item "%s" already exists'  % ldap_name
 
        if REQUEST:
            return self.manage_ldapschema(manage_tabs_message=msg)


    security.declareProtected(EDIT_PERMISSION, 'manage_deleteLDAPSchemaItems')
    def manage_deleteLDAPSchemaItems(self, ldap_names=[], REQUEST=None):
        """ Delete schema items from my list of known schema items """
        if len(ldap_names) < 1:
            msg = 'Please select items to delete'
 
        else:
            schema = self.getSchemaConfig()
            removed = []

            for ldap_name in ldap_names:
                if ldap_name in schema.keys():
                    removed.append(ldap_name)
                    del schema[ldap_name]
 
            self.setSchemaConfig(schema)

            rem_str = ', '.join(removed)
            msg = 'LDAP Schema items %s removed.' % rem_str
 
        if REQUEST:
            return self.manage_ldapschema(manage_tabs_message=msg)


    security.declareProtected(manage_users, 'manage_addGroup')
    def manage_addGroup( self
                       , newgroup_name
                       , newgroup_type='groupOfUniqueNames'
                       , REQUEST=None
                       ):
        """ Add a new group in groups_base """
        if self._local_groups and newgroup_name:
            add_groups = self._additional_groups
            
            if newgroup_name not in add_groups:
                add_groups.append(newgroup_name)

            self._additional_groups = add_groups
            msg = 'Added new group %s' % (newgroup_name)

        elif newgroup_name:
            attributes = {}
            attributes['cn'] = [newgroup_name]
            attributes['objectClass'] = ['top', newgroup_type]

            if self._binduid:
                initial_member = self._binduid
            else:
                user = getSecurityManager().getUser()
                try:
                    initial_member = user.getUserDN()
                except:
                    initial_member = ''

            attributes[GROUP_MEMBER_MAP.get(newgroup_type)] = initial_member

            err_msg = self._delegate.insert( base=self.groups_base
                                           , rdn='cn=%s' % newgroup_name
                                           , attrs=attributes
                                           )
            msg = err_msg or 'Added new group %s' % (newgroup_name)

        else:
            msg = 'No group name specified'

        if REQUEST:
            return self.manage_grouprecords(manage_tabs_message=msg)


    security.declareProtected(manage_users, 'manage_addUserGroup')
    def manage_addUserGroup( self
                           , newusergroup_name
                           , newusergroup_type='groupOfUniqueNames'
                           , REQUEST=None
                           ):
        """ Add a new group in usergroups_base """
        if self._local_usergroups and newusergroup_name:
            add_usergroups = self._additional_usergroups

            if newusergroup_name not in add_usergroups:
                add_usergroups.append(newusergroup_name)

            self._additional_usergroups = add_usergroups
            msg = 'Added new user group %s' % (newusergroup_name)

        elif newusergroup_name:
            attributes = {}
            attributes['cn'] = [newusergroup_name]
            attributes['objectClass'] = ['top', newusergroup_type]

            if self._binduid:
                initial_member = self._binduid
            else:
                user = getSecurityManager().getUser()
                try:
                    initial_member = user.getUserDN()
                except:
                    initial_member = ''

            attributes[GROUP_MEMBER_MAP.get(newusergroup_type)] =initial_member

            err_msg = self._delegate.insert( base=self.usergroups_base
                                           , rdn='cn=%s' % newusergroup_name
                                           , attrs=attributes
                                           )
            msg = err_msg or 'Added new user group %s' % (newusergroup_name)

        else:
            msg = 'No user group name specified'

        if REQUEST:
            return self.manage_usergrouprecords(manage_tabs_message=msg)


    security.declareProtected(manage_users, 'manage_addUser')
    def manage_addUser(self, REQUEST=None, kwargs={}):
        """ Add a new user record to LDAP """
        base = self.users_base
        attr_dict = {}
        
        if REQUEST is None:
            source = kwargs
        else:
            source = REQUEST

        rdn_attr = self._rdnattr
        attr_dict[rdn_attr] = source.get(rdn_attr)
        rdn = '%s=%s' % (rdn_attr, source.get(rdn_attr))
        sub_loc = source.get('sub_branch', '')
        if sub_loc:
            base = '%s,%s' % (rdn, base)
        password = source.get('user_pw', '')
        confirm  = source.get('confirm_pw', '')
        
        if password != confirm or password == '': 
            msg = 'The password and confirmation do not match!'

        else:
            encrypted_pwd = _createLDAPPassword( password
                                               , self._pwd_encryption
                                               )
            attr_dict['userPassword'] = encrypted_pwd
            attr_dict['objectClass'] = self._user_objclasses

            for attribute, names in self.getSchemaConfig().items():
                attr_val = source.get(attribute, None)

                if attr_val:
                    attr_dict[attribute] = attr_val
                elif names.get('public_name', None):
                    attr_val = source.get(names['public_name'], None)

                    if attr_val:
                        attr_dict[attribute] = attr_val

            msg = self._delegate.insert( base=base
                                       , rdn=rdn
                                       , attrs=attr_dict
                                       )

        if msg:
            if REQUEST:
                return self.manage_userrecords(manage_tabs_message=msg)
            else:
                return msg
                

        if not msg:
            user_dn = '%s,%s' % (rdn, base)
            try:
                user_roles = source.get('user_roles', [])

                if self._local_groups:
                    self._groups_store[user_dn] = user_roles
                else:
                    if len(user_roles) > 0:
                        group_dns = []

                        for role in user_roles:
                            try:
                                exploded = explode_dn(role)
                                elements = len(exploded)
                            except:
                                elements = 1

                            if elements == 1:  # simple string
                                role = 'cn=%s,%s' % ( str(role)
                                                    , self.groups_base
                                                    )

                            group_dns.append(role)

                            try:
                                self.manage_editUserRoles(user_dn, group_dns)
                            except:
                                raise

                # CPS Groups

                user_usergroups = source.get('user_usergroups', [])

                if self._local_usergroups:
                    self._usergroups_store[user_dn] = user_usergroups
                else:
                    if len(user_usergroups) > 0:
                        usergroup_dns = []

                        for usergroup in user_usergroups:
                            try:
                                exploded = explode_dn(usergroup)
                                elements = len(exploded)
                            except:
                                elements = 1

                            if elements == 1:  # simple string
                                usergroup = 'cn=%s,%s' % (
                                    str(usergroup), self.usergroups_base)

                            usergroup_dns.append(usergroup)

                            try:
                                self.manage_editUserGroups(user_dn,
                                                           usergroup_dns)
                            except:
                                raise

                msg = 'New user %s added' % user_dn
            except Exception, e:
                msg = str(e)
                user_dn = ''

        if REQUEST:
            return self.manage_userrecords( manage_tabs_message=msg
                                          , user_dn='%s,%s' % (rdn, base)
                                          )


    security.declareProtected(manage_users, 'manage_deleteGroups')
    def manage_deleteGroups(self, dns=[], REQUEST=None):
        """ Delete groups from groups_base """
        msg = ''

        if len(dns) < 1:
            msg = 'You did not specify groups to delete!'

        else:
            if self._local_groups:
                add_groups = self._additional_groups
                for dn in dns:
                    if dn in add_groups:
                        del add_groups[add_groups.index(dn)]

                self._additional_groups = add_groups

            else:
                for dn in dns:
                    msg = self._delegate.delete(dn)

                    if msg:
                        break

            msg = msg or 'Deleted group(s):<br> %s' % '<br>'.join(dns)
            self._clearCaches()
 
        if REQUEST:
            return self.manage_grouprecords(manage_tabs_message=msg)


    security.declareProtected(manage_users, 'manage_deleteUserGroups')
    def manage_deleteUserGroups(self, dns=[], REQUEST=None):
        """ Delete user groups from usergroups_base """
        if len(dns) < 1:
            msg = 'You did not specify user groups to delete!'

        else:
            if self._local_usergroups:
                add_usergroups = self._additional_usergroups
                for dn in dns:
                    if dn in add_usergroups:
                        del add_usergroups[add_usergroups.index(dn)]

                self._additional_usergroups = add_usergroups
                msg = ''

            else:
                for dn in dns:
                    msg = self._delegate.delete(dn)

                    if msg:
                        break

            msg = msg or 'Deleted user group(s):<br> %s' % '<br>'.join(dns)
            self._clearCaches()

        if REQUEST:
            return self.manage_usergrouprecords(manage_tabs_message=msg)


    security.declareProtected(manage_users, 'manage_deleteUsers')
    def manage_deleteUsers(self, dns=[], REQUEST=None):
        """ Delete all users in list dns """
        if len(dns) < 1:
            msg = 'You did not specify users to delete!'

        elif self._delegate.read_only:
            msg = 'Running in read-only mode, deletion is disabled'
        
        else:
            for dn in dns:
                msg = self._delegate.delete(dn)

                if msg:
                    break

                user_groups = self.getGroups(dn=dn, attr='dn')

                if self._local_groups:
                    if dn in self._groups_store.keys():
                        del self._groups_store[dn]
                else:
                    for group in user_groups:
                        group_type = self.getGroupType(group)
                        member_type = GROUP_MEMBER_MAP.get(group_type)

                        msg = self._delegate.modify( dn=group
                                                   , mod_type=DELETE
                                                   , attrs={member_type : [dn]}
                                                   )

                        if msg:
                            break

                user_usergroups = self.getUserGroups(dn=dn, attr='dn')

                if self._local_usergroups:
                    if dn in self._usergroups_store.keys():
                        del self._usergroups_store[dn]
                else:
                    for usergroup in user_usergroups:
                        usergroup_type = self.getUserGroupType(usergroup)
                        member_type = GROUP_MEMBER_MAP.get(usergroup_type)

                        msg = self._delegate.modify( dn=usergroup
                                                   , mod_type=DELETE
                                                   , attrs={member_type : [dn]}
                                                   )

                        if msg:
                            break

            msg = 'Deleted user(s):<br> %s' % '<br>'.join(dns)
            self._clearCaches()

        if REQUEST:
            return self.manage_userrecords(manage_tabs_message=msg)


    security.declareProtected(manage_users, 'manage_editUserPassword')
    def manage_editUserPassword(self, dn, new_pw, REQUEST=None):
        """ Change a user password """
        hidden = '<input type="hidden" name="user_dn" value="%s">' % (dn)
        err_msg = msg = ''

        if new_pw == '':
            msg = 'The password cannot be empty!'

        else:
            ldap_pw = _createLDAPPassword(new_pw, self._pwd_encryption)
            err_msg = self._delegate.modify( dn=dn
                                           , attrs={'userPassword':[ldap_pw]}
                                           )
            if not err_msg:
                msg = 'Password changed for "%s"' % dn
                user_obj = self.getUserByDN(dn)
                self._expireUser(user_obj)

        if REQUEST:
            return self.manage_userrecords( manage_tabs_message=err_msg or msg
                                          , user_dn=dn
                                          )


    security.declareProtected(manage_users, 'manage_editUserRoles')
    def manage_editUserRoles(self, user_dn, role_dns=[], REQUEST=None):
        """ Edit the roles (groups) of a user """
        msg = ''
        all_groups = self.getGroups(attr='dn')
        cur_groups = self.getGroups(dn=user_dn, attr='dn')
        group_dns = []
        for group in role_dns:
            if group.find('=') == -1:
                group_dns.append('cn=%s,%s' % (group, self.groups_base))
            else:
                group_dns.append(group)

        if self._local_groups:
            if len(role_dns) == 0:
                del self._groups_store[user_dn]
            else:
                self._groups_store[user_dn] = role_dns

        else:
            for group in all_groups:
                member_attr = GROUP_MEMBER_MAP.get(self.getGroupType(group))

                if group in cur_groups and group not in group_dns:
                    msg = self._delegate.modify( group
                                               , DELETE
                                               , {member_attr : [user_dn]}
                                               )
                elif group in group_dns and group not in cur_groups:
                    msg = self._delegate.modify( group
                                               , ADD
                                               , {member_attr : [user_dn]}
                                               )

        msg = msg or 'Roles changed for %s' % (user_dn)
        user_obj = self.getUserByDN(user_dn)
        if user_obj is not None:
            self._expireUser(user_obj)

        if REQUEST:
            return self.manage_userrecords( manage_tabs_message=msg
                                          , user_dn=user_dn
                                          )


    security.declareProtected(manage_users, 'manage_editUserGroups')
    def manage_editUserGroups(self, user_dn, usergroup_dns=[], REQUEST=None):
        """ Edit the user groups of a user """
        msg = ''
        all_usergroups = self.getUserGroups(attr='dn')
        cur_usergroups = self.getUserGroups(dn=user_dn, attr='dn')
        group_dns = []
        for usergroup in usergroup_dns:
            if usergroup.find('=') == -1:
                group_dns.append('cn=%s,%s' % (usergroup, self.groups_base))
            else:
                group_dns.append(usergroup)

        if self._local_usergroups:
            if len(usergroup_dns) == 0:
                del self._usergroups_store[user_dn]
            else:
                self._usergroups_store[user_dn] = usergroup_dns

        else:
            for usergroup in all_usergroups:
                member_attr = GROUP_MEMBER_MAP.get(self.getUserGroupType(usergroup))

                if usergroup in cur_usergroups and usergroup not in group_dns:
                    msg = self._delegate.modify( usergroup
                                               , DELETE
                                               , {member_attr : [user_dn]}
                                               )
                elif usergroup in group_dns and usergroup not in cur_usergroups:
                    msg = self._delegate.modify( usergroup
                                               , ADD
                                               , {member_attr : [user_dn]}
                                               )

        msg = msg or 'User groups changed for %s' % (user_dn)
        user_obj = self.getUserByDN(user_dn)
        if user_obj is not None:
            self._expireUser(user_obj)

        if REQUEST:
            return self.manage_userrecords( manage_tabs_message=msg
                                          , user_dn=user_dn
                                          )


    security.declareProtected(manage_users, 'manage_setUserProperty')
    def manage_setUserProperty(self, user_dn, prop_name, prop_value):
        """ Set a new attribute on the user record """
        if isinstance(prop_value, StringType):
            prop_value = [x.strip() for x in prop_value.split(';')]

        for i in range(len(prop_value)):
            prop_value[i] = to_utf8(prop_value[i])

        cur_rec = self._delegate.search( base=user_dn
                                       , scope=BASE
                                       )

        if cur_rec['exception'] or cur_rec['size'] == 0:
            exc = cur_rec['exception']
            msg = 'manage_setUserProperty: No user "%s" (%s)' % (user_dn, exc)
            self.verbose > 1 and self._log.log(2, msg)
                                                                
            return

        user_rec = cur_rec['results'][0]
        cur_prop = user_rec.get(prop_name, [''])

        if cur_prop != prop_value:
            if prop_value != ['']:
                mod = REPLACE
            else:
                mod = DELETE

            err_msg = self._delegate.modify( dn=user_dn
                                           , mod_type=mod
                                           , attrs={prop_name:prop_value}
                                           )
            
            if not err_msg:
                user_obj = self.getUserByDN(user_dn)
                self._expireUser(user_obj)


    security.declareProtected(manage_users, 'manage_editUser')
    def manage_editUser(self, user_dn, REQUEST=None, kwargs={}):
        """ Edit a user record """
        msg = ''
        new_attrs = {}
        utf8_dn = to_utf8(user_dn)
        cur_user = self.getUserByDN(utf8_dn)

        if cur_user is None:
            return 'No user with DN "%s"' % user_dn

        if REQUEST is None:
            source = kwargs
        else:
            source = REQUEST

        for attr in self.getSchemaConfig().keys():
            if source.has_key(attr):
                new = source.get(attr, '')
                if isinstance(new, StringType):
                    new = [x.strip() for x in new.split(';')]

                new_attrs[attr] = new

        if new_attrs:
            msg = self._delegate.modify(user_dn, attrs=new_attrs)
        else:
            msg = 'No attributes changed'

        if msg:
            if REQUEST:
                return self.manage_userrecords( manage_tabs_message=msg
                                              , user_dn=user_dn
                                              )
            else:
                return msg

        rdn = self._rdnattr
        new_cn = source.get(rdn, '')
        new_dn = ''

        # This is not good, but explode_dn mangles non-ASCII
        # characters so I simply cannot use it.
        old_utf8_rdn = to_utf8('%s=%s' % (rdn, cur_user.getProperty(rdn)))
        new_rdn = '%s=%s' % (rdn, new_cn)
        new_utf8_rdn = to_utf8(new_rdn)

        if new_cn and new_utf8_rdn != old_utf8_rdn:
            old_dn = utf8_dn
            old_dn_exploded = explode_dn(old_dn)
            old_dn_exploded[0] = new_rdn
            new_dn = ','.join(old_dn_exploded)
            old_groups = self.getGroups(dn=user_dn, attr='dn')

            if self._local_groups:
                if self._groups_store.get(user_dn):
                    del self._groups_store[user_dn]

                self._groups_store[new_dn] = old_groups

            else:
                for group in old_groups:
                    group_type = self.getGroupType(group)
                    member_type = GROUP_MEMBER_MAP.get(group_type)

                    msg = self._delegate.modify( group
                                               , DELETE
                                               , {member_type : [user_dn]}
                                               )
                    msg = self._delegate.modify( group
                                               , ADD
                                               , {member_type : [new_dn]}
                                               )

            # CPS Groups

            old_usergroups = self.getUserGroups(dn=user_dn, attr='dn')

            if self._local_usergroups:
                if self._usergroups_store.get(user_dn):
                    del self._usergroups_store[user_dn]
                self._usergroups_store[new_dn] = old_usergroups
            else:
                for usergroup in old_usergroups:
                    usergroup_type = self.getUserGroupType(usergroup)
                    member_type = GROUP_MEMBER_MAP.get(usergroup_type)
                    msg = self._delegate.modify( usergroup
                                               , DELETE
                                               , {member_type : [user_dn]}
                                               )
                    msg = self._delegate.modify( usergroup
                                               , ADD
                                               , {member_type : [new_dn]}
                                               )

        self._expireUser(cur_user.getProperty(rdn))
        msg = msg or 'User %s changed' % (new_dn or user_dn)

        if REQUEST:
            return self.manage_userrecords( manage_tabs_message=msg
                                          , user_dn=new_dn or user_dn
                                          )

    security.declareProtected(manage_users, '_expireUser')
    def _expireUser(self, user):
        """ Purge user object from caches """
        user = user or ''

        if not isinstance(user, StringType):
            user = user.getId()

        self._authenticated_cache.remove(user)
        self._anonymous_cache.remove(user)


    security.declareProtected(manage_users, 'isUnique')
    def isUnique(self, attr, value):
        """ 
            Find out if any objects have the same attribute value.
            This method should be called when a new user record is
            about to be created. It guards uniqueness of names by 
            warning for items with the same name.
        """
        search_str = filter_format('(%s=%s)', (attr, str(value)))
        res = self._delegate.search( base=self.users_base
                                   , scope=self.users_scope
                                   , filter=search_str
                                   )

        if res['exception']:
            return res['exception']

        return res['size'] < 1


    def getEncryptions(self):
        """ Return the possible encryptions """
        if not crypt:
            return ('SHA', 'SSHA', 'clear')
        else:
            return ('crypt', 'SHA', 'SSHA', 'clear')


    def getLog(self):
        """ Get the log for displaying """
        return self._log.getLog()


    security.declareProtected(manage_users, 'getCacheTimeout')
    def getCacheTimeout(self, cache_type='anonymous'):
        """ Retrieve the cache timout value (in seconds) """
        if cache_type == 'authenticated':
            return getattr(self, '_authenticated_timeout', 600)
        else:
            return getattr(self, '_anonymous_timeout', 600)


    security.declareProtected(manage_users, 'setCacheTimeout')
    def setCacheTimeout( self
                       , cache_type='anonymous'
                       , timeout=600
                       , REQUEST=None
                       ):
        """ Set the cache timeout """
        if not timeout and timeout != 0:
            timeout = 600
        else:
            timeout = int(timeout)

        if cache_type == 'authenticated':
            self._authenticated_timeout = timeout
            self._authenticated_cache.setTimeout(timeout)
        elif cache_type == 'anonymous':
            self._anonymous_timeout = timeout
            self._anonymous_cache.setTimeout(timeout)

        if REQUEST is not None:
            msg = 'Cache timeout changed'
            return self.manage_cache(manage_tabs_message=msg)


def manage_addLDAPUserGroupsFolder( self, title, LDAP_server, login_attr
                            , users_base, users_scope, roles, groups_base
                            , groups_scope, usergroups_base, usergroups_scope
                            , binduid, bindpwd, binduid_usage=1
                            , rdn_attr='cn', local_groups=0
                            , local_usergroups=0, use_ssl=0
                            , encryption='SHA', read_only=0, REQUEST=None
                            ):
    """ Called by Zope to create and install an LDAPUserFolder """
    this_folder = self.this()

    if hasattr(aq_base(this_folder), 'acl_users') and REQUEST is not None:
        msg = 'This+object+already+contains+a+User+Folder'

    else:
        n = LDAPUserFolder( title, LDAP_server, login_attr, users_base, users_scope
                          , roles, groups_base, groups_scope, usergroups_base
                          , usergroups_scope, binduid, bindpwd
                          , binduid_usage, rdn_attr, local_groups=local_groups
                          , local_usergroups=local_usergroups
                          , use_ssl=not not use_ssl, encryption=encryption
                          , read_only=read_only, REQUEST=None
                          )

        this_folder._setObject('acl_users', n)
        this_folder.__allow_groups__ = self.acl_users
        
        msg = 'Added+LDAPUserGroupsFolder'
 
    # return to the parent object's manage_main
    if REQUEST:
        url = REQUEST['URL1']
        qs = 'manage_tabs_message=%s' % msg
        REQUEST.RESPONSE.redirect('%s/manage_main?%s' % (url, qs))


InitializeClass(LDAPUserFolder)
