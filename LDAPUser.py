######################################################################
#
# LDAPUser  The User object for the LDAP User Folder
#
# This software is governed by a license. See
# LICENSE.txt for the terms of this license.
#
######################################################################
__version__='$Revision$'[11:-2]

# General Python imports
import time
from types import StringType, UnicodeType

# Zope imports
from Acquisition import aq_inner, aq_parent
from AccessControl.User import BasicUser
from AccessControl.PermissionRole import _what_not_even_god_should_do
from AccessControl.Permissions import access_contents_information, manage_users
from DateTime import DateTime
from AccessControl import ClassSecurityInfo
from Globals import InitializeClass
from OFS.SimpleItem import SimpleItem

# LDAPUserFolder package imports
from utils import _verifyUnicode, encoding, to_utf8


class LDAPUser(BasicUser):
    """ A user object for LDAP users """
    security = ClassSecurityInfo()
    _properties = None

    def __init__( self
                , name
                , password
                , roles
                , usergroups
                , computedgroups
                , domains
                , user_dn
                , user_attrs
                , mapped_attrs
                , multivalued_attrs=()
                ):
        """ Instantiate a new LDAPUser object """
        self._properties = {}
        self.name = _verifyUnicode(name)
        self.__ = password
        self._dn = _verifyUnicode(user_dn)
        self.roles = roles
        self.usergroups = tuple(usergroups)
        self.computedgroups = tuple(computedgroups)
        self.domains = []
        self.RID = ''
        self.groups = ''
        now = time.time()
        self._created = now
        self._lastactivetime = now

        for key in user_attrs.keys():
            if key in multivalued_attrs:
                prop = user_attrs.get(key, [None])
            else:
                prop = user_attrs.get(key, [None])[0]

            if isinstance(prop, StringType):
                prop = _verifyUnicode(prop)

            self._properties[key] = prop

        for att_name, map_name in mapped_attrs:
            self._properties[map_name] = self._properties.get(att_name)

        self._properties['dn'] = user_dn


    ######################################################
    # User interface not implemented in class BasicUser
    #######################################################

    security.declarePrivate('_getPassword')
    def _getPassword(self):
        """ Retrieve the password """
        return self.__


    security.declarePublic('getUserName')
    def getUserName(self):
        """ Get the name associated with this user """
        if isinstance(self.name, UnicodeType):
            return self.name.encode(encoding)

        return self.name


    # CPS Groups (needed by NuxUserGroups' patch of BasicUser)
    security.declarePublic('getGroups')
    def getGroups(self):
        """ Return the user's groups """
        return self.usergroups


    security.declarePublic('getComputedGroups')
    def getComputedGroups(self):
        """Get all the user's groups.

        This includes groups of groups, and special groups
        like role:Anonymous and role:Authenticated.
        """
        return self.computedgroups


    security.declarePublic('getRoles')
    def getRoles(self):
        """ Return the user's roles """
        if self.name == 'Anonymous User':
            return tuple(self.roles)
        else:
            return tuple(self.roles) + ('Authenticated',)


    security.declarePublic('getDomains')
    def getDomains(self):
        """ The user's domains """
        return self.domains


    # CPS extension
    security.declarePublic('hasLocalRolesBlocking')
    def hasLocalRolesBlocking(self):
        """Test if local roles blocking is implemented in this user folder."""
        return 1

    #######################################################
    # Overriding these to enable context-based role
    # computation with the LDAPUserSatellite
    #######################################################

    # Basic version, derived from NuxUserGroups.
    def _getRolesInContext(self, object):
        """Get the list of roles assigned to the user.

        This includes local roles assigned in the context of
        the passed in object.

        Knows about local roles blocking (roles starting with '-').
        """
        name = self.getUserName()
        roles = self.getRoles()
        # deal with groups
        groups = self.getComputedGroups()
        # end groups
        local = {}
        stop_loop = 0
        object = aq_inner(object)
        while 1:
            # Collect all roles info
            lrd = {}
            local_roles = getattr(object, '__ac_local_roles__', None)
            if local_roles:
                if callable(local_roles):
                    local_roles = local_roles() or {}
                for r in local_roles.get(name, ()):
                    if r:
                        lrd[r] = None
            local_group_roles = getattr(object, '__ac_local_group_roles__', None)
            if local_group_roles:
                if callable(local_group_roles):
                    local_group_roles = local_group_roles() or {}
                for g in groups:
                    for r in local_group_roles.get(g, ()):
                        if r:
                            lrd[r] = None
            lr = lrd.keys()
            # Positive role assertions
            for r in lr:
                if r[0] != '-':
                    if not local.has_key(r):
                        local[r] = 1 # acquired role
            # Negative (blocking) role assertions
            for r in lr:
                if r[0] == '-':
                    r = r[1:]
                    if not r:
                        # role '-' blocks all acquisition
                        stop_loop = 1
                        break
                    if not local.has_key(r):
                        local[r] = 0 # blocked role
            if stop_loop:
                break
            if hasattr(object, 'aq_parent'):
                object = aq_inner(object.aq_parent)
                continue
            if hasattr(object, 'im_self'):
                object = aq_inner(object.im_self)
                continue
            break
        roles = list(roles)
        for r, v in local.items():
            if v: # only if not blocked
                roles.append(r)
        return roles

    def getRolesInContext(self, object):
        """Get the list of roles assigned to the user.

        This includes local roles assigned in the context of
        the passed in object.

        Knows about local roles blocking (roles starting with '-').
        """
        roles = self._getRolesInContext(object)

        acl_satellite = self._getSatellite(object)
        if acl_satellite and hasattr(acl_satellite, 'getAdditionalRoles'):
            satellite_roles = acl_satellite.getAdditionalRoles(self)
            roles = list(roles) + satellite_roles

        return roles


    # Basic version, derived from NuxUserGroups
    def _allowed(self, object, object_roles=None):
        """Check whether the user has access to object. The user must
           have one of the roles in object_roles to allow access."""

        if object_roles is _what_not_even_god_should_do:
            return 0

        # Short-circuit the common case of anonymous access.
        if object_roles is None or 'Anonymous' in object_roles:
            return 1

        # Provide short-cut access if object is protected by 'Authenticated'
        # role and user is not nobody
        if 'Authenticated' in object_roles and (
            self.getUserName() != 'Anonymous User'):
            return 1

        # Check for ancient role data up front, convert if found.
        # This should almost never happen, and should probably be
        # deprecated at some point.
        if 'Shared' in object_roles:
            object_roles = self._shared_roles(object)
            if object_roles is None or 'Anonymous' in object_roles:
                return 1

        # Check for a role match with the normal roles given to
        # the user, then with local roles only if necessary. We
        # want to avoid as much overhead as possible.
        user_roles = self.getRoles()
        for role in object_roles:
            if role in user_roles:
                if self._check_context(object):
                    return 1
                return None

        # Check local roles, calling getRolesInContext to avoid too much
        # complexity, at the expense of speed.
        for role in self._getRolesInContext(object):
            if role in object_roles:
                return 1

        return None


    def allowed(self, object, object_roles=None):
        """ Must override, getRolesInContext is not always called """
        if self._allowed(object, object_roles):
            return 1

        acl_satellite = self._getSatellite(object)
        if acl_satellite and hasattr(acl_satellite, 'getAdditionalRoles'):
            satellite_roles = acl_satellite.getAdditionalRoles(self)

            for role in object_roles:
                if role in satellite_roles:
                    if self._check_context(object):
                        return 1

        return 0


    security.declarePrivate('_getSatellite')
    def _getSatellite(self, object):
        """ Get the acl_satellite (sometimes tricky!) """
        while 1:
            acl_satellite = getattr(object, 'acl_satellite', None)
            if acl_satellite is not None:
                return acl_satellite

            parent = aq_parent(aq_inner(object))
            if parent:
                object = parent
                continue

            if hasattr(object, 'im_self'):
                object = aq_inner(object.im_self)
                continue

            break

        return None


    #######################################################
    # Interface unique to the LDAPUser class of user objects
    #######################################################

    security.declareProtected(access_contents_information, '__getattr__')
    def __getattr__(self, name):
        """ Look into the _properties as well... """
        my_props = self._properties

        if my_props.has_key(name):
            prop = my_props.get(name)

            if isinstance(prop, UnicodeType):
                prop = prop.encode(encoding)

            return prop

        else:
            raise AttributeError, name


    security.declareProtected(access_contents_information, 'getProperty')
    def getProperty(self, prop_name, default=''):
        """
            Return the user property referred to by prop_name,
            if the attribute is indeed public.
        """
        prop = self._properties.get(prop_name, default)
        if isinstance(prop, UnicodeType):
            prop = prop.encode(encoding)

        return prop


    security.declareProtected(access_contents_information, 'getUserDN')
    def getUserDN(self):
        """ Return the user's full Distinguished Name """
        if isinstance(self._dn, UnicodeType):
            return self._dn.encode(encoding)

        return self._dn


    def _updateActiveTime(self):
        """ Update the active time """
        self._lastactivetime = time.time()


    def getLastActiveTime(self):
        """ When was this user last active? """
        return DateTime(self._lastactivetime)


    def getCreationTime(self):
        """ When was this user object created? """
        return DateTime(self._created)

    #######################################################
    # CPS User properties extended API
    #######################################################
    security.declareProtected(access_contents_information, 'listProperties')
    def listProperties(self):
        """Lists all properties that are set on the user."""
        return self._properties.keys()

    security.declareProtected(access_contents_information, 'hasProperty')
    def hasProperty(self, id):
        """Check for a property"""
        return self._properties.has_key(id)

    # def getProperty(self, id, default=None):
    # Already defined above.

    security.declareProtected(access_contents_information, 'getProperties')
    def getProperties(self, ids):
        """Returns the values of list of properties"""
        res = {}
        for id in ids:
            res[id] = self.getProperty(id)
        return res

    security.declareProtected(manage_users, 'setProperty')
    def setProperty(self, prop_name, prop_value):
        """Sets the value of a property"""
        user_dn = self.getUserDN()
        aclu = self.acl_users
        aclu.manage_setUserProperty(user_dn, prop_name, prop_value)
        # Gotta set the new properties on myself too.
        # To make sure it's syncronized, get it from the LDAP db.
        user = aclu.getUserByDN(user_dn)
        self._properties = user._properties.copy()

    security.declareProtected(manage_users, 'setProperties')
    def setProperties(self, **kw):
        """Sets the values of a dictionary of properties"""
        user_dn = self.getUserDN()
        aclu = self.acl_users
        aclu.manage_editUser(user_dn, kwargs=kw)
        # Gotta set the new properties on myself too.
        # To make sure it's syncronized, get it from the LDAP db.
        user = aclu.getUserByDN(to_utf8(user_dn))
        self._properties = user._properties.copy()

InitializeClass(LDAPUser)


class CPSGroup(SimpleItem):
    """Very basic group object for CPS group behavior."""

    security = ClassSecurityInfo()

    def __init__(self, id, users, groups, **kw):
        self.id = id
        self.users = tuple(users)
        self.groups = tuple(groups)
        #self.users = [_verifyUnicode(u).encode(encoding)
        #              for u in users]

    security.declareProtected(manage_users, 'getUsers')
    def getUsers(self):
        """Get group users ids."""
        return self.users

    security.declareProtected(manage_users, 'getGroups')
    def getGroups(self):
        """Get group subgroups ids."""
        return self.groups

    security.declareProtected(manage_users, 'setGroups')
    def setGroups(self, groups):
        """Set group subgroups ids."""
        aclu = aq_parent(aq_inner(self))
        aclu._setGroupSubgroups(self.id, groups)

    security.declareProtected(manage_users, 'getTitle')
    def getTitle(self):
        """Get group title."""
        return self.id

    security.declareProtected(manage_users, 'setTitle')
    def setTitle(self):
        """Set group title."""
        pass

    security.declareProtected(manage_users, 'Title')
    def Title(self):
        """Get group title (old name)."""
        return self.getTitle()

InitializeClass(CPSGroup)
