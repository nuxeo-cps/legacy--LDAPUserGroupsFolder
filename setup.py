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

import re
from cgi import escape
from Products.LDAPUserGroupsFolder.LDAPUserFolder import LDAPUserFolder
from Products.LDAPUserGroupsFolder.LDAPUserFolder import \
     manage_addLDAPUserGroupsFolder
from Products.CPSUserFolder.setup.handlers import registerExportImport
from Products.CPSUserFolder.setup.handlers import registerImportMapping
from Products.CMFSetup.utils import CONVERTER, DEFAULT, KEY


LDAPURL_RE = re.compile('^(ldap|ldaps)://([^:/]*):?([0-9]*)')


exportScope = {
    0: 'base',
    1: 'onelevel',
    2: 'subtree',
    }.get

def importScope(v, elements):
    return {
        'base': 0,
        'onelevel': 1,
        'subtree': 2,
        }[v]

exportManagerUsage = {
    0: 'never',
    1: 'always',
    2: 'data',
    }.get

def importManagerUsage(v, elements):
    return {
        'never': 0,
        'always': 1,
        'data': 2,
        }[v]

def importBool(v, elements=None):
    return v.lower().strip() not in ('false', 'no', '0', '')

def importList(v, elements):
    return list(elements)

def importInt(v, elements):
    return int(v)

_TABLE = [
    # XML name, aclu attribute, export converter, import converter
    ('title', 'title', None, None),
    ('login-attr', '_login_attr', None, None),
    ('rdn-attr', '_rdnattr', None, None),
    ('users-base-dn', 'users_base', None, None),
    ('users-scope', 'users_scope', exportScope, importScope),
    ('roles-base-dn', 'groups_base', None, None),
    ('roles-scope', 'groups_scope', exportScope, importScope),
    ('roles-in-zodb', '_local_groups', bool, importBool),
    ('groups-base-dn', 'usergroups_base', None, None),
    ('groups-scope', 'usergroups_scope', exportScope, importScope),
    ('groups-in-zodb', '_local_usergroups', bool, importBool),
    ('manager-dn', '_binduid', None, None),
    ('manager-password', '_bindpwd', None, None),
    ('manager-usage', '_binduid_usage', exportManagerUsage,
                                        importManagerUsage),
    ('bind-read-only', 'read_only', bool, importBool),
    ('object-classes', '_user_objclasses', None, importList),
    ('password-encryption', '_pwd_encryption', None, None),
    ('default-user-roles', '_roles', None, importList),
    ('verbose-level', 'verbose', None, importInt),
    ]

_IMPORTS = {}
for name, attr, convexport, convimport in _TABLE:
    _IMPORTS[name] = (attr, convimport)


def exportLDAPUGF(configurator, aclu):
    prop_infos = []
    for name, attr, convexport, convimport in _TABLE:
        value = getattr(aclu, attr)
        if convexport is not None:
            value = convexport(value)
        if isinstance(value, list):
            elements = tuple(value)
            value = ''
        elif isinstance(value, tuple):
            elements = value
            value = ''
        else:
            elements = ()
        prop_info = {
            'id': name,
            'value': value,
            'elements': elements,
            'type': None,
            'select_variable': None,
            }
        prop_infos.append(prop_info)
    # Other xml
    otherXML = ['']
    # Servers
    for server in aclu.getServers():
        url = '%s://%s:%s' % (server['protocol'], server['host'],
                              server['port'])
        otherXML.append('<server url="%s" />' % escape(url, True))
    # Schema
    schema = aclu.getSchemaConfig()
    keys = schema.keys()
    keys.sort()
    for key in keys:
        info = schema[key]
        label = info['friendly_name']
        mapped = info['public_name']
        multivalued = info['multivalued']
        s = '<field id="%s" label="%s"' % (escape(key, True),
                                           escape(label, True))
        if mapped:
            s += ' mapped="%s"' % escape(mapped, True)
        if multivalued:
            s += ' multivalued="True"'
        s += ' />'
        otherXML.append(s)
    return prop_infos, '\n  '.join(otherXML)

def importLDAPUGF(configurator, aclu, info):
    for prop_info in info['properties']:
        id = prop_info['id']
        value = prop_info['value']
        elements = prop_info['elements']
        if id not in _IMPORTS:
            raise ValueError("Unknown property for LDAPUserGroupsFolder: %r"
                             % id)
        attr, convimport = _IMPORTS[id]
        if convimport is not None:
            value = convimport(value, elements)
        setattr(aclu, attr, value)
    # Import servers
    aclu.manage_deleteServers(range(len(aclu.getServers())))
    for server in info['servers']:
        url = server['url']
        match = LDAPURL_RE.match(url)
        if match is None:
            raise ValueError("Bad server %r" % url)
        scheme, host, port = match.groups()
        use_ssl = scheme == 'ldaps'
        if not port:
            if use_ssl:
                port = '636'
            else:
                port = '389'
        aclu.manage_addServer(host, port, use_ssl)
    # Import fields
    aclu.setSchemaConfig({})
    for field_info in info['fields']:
        aclu.manage_addLDAPSchemaItem(field_info['id'],
                                      field_info['label'],
                                      field_info['multivalued'],
                                      field_info['mapped'])
    # Fixups
    aclu._delegate.edit(aclu._login_attr, aclu.users_base, aclu._rdnattr,
                        aclu._user_objclasses, aclu._binduid, aclu._bindpwd,
                        aclu._binduid_usage, aclu.read_only)
    aclu._clearCaches()
    if aclu.verbose > 1:
        aclu._log.log(2, 'Properties changed')

##################################################
# Registrations

def constructLDAPUserGroupsFolder(container):
    from Products.LDAPUserGroupsFolder.LDAPDelegate import LDAPDelegate
    def connect(self):
        """Replaced during construction because the stupid constructor
        tries to connect to the server.
        """
        return True
    old_connect = LDAPDelegate.connect
    LDAPDelegate.connect = connect
    try:
        manage_addLDAPUserGroupsFolder(
            container,
            title='', LDAP_server='', login_attr='',
            users_base='', users_scope=0, roles=[],
            groups_base='', groups_scope=0,
            usergroups_base='', usergroups_scope=0,
            binduid='', bindpwd='')
    finally:
        LDAPDelegate.connect = old_connect

registerExportImport(LDAPUserFolder.meta_type, exportLDAPUGF,
                     constructLDAPUserGroupsFolder, importLDAPUGF)

registerImportMapping({
    'user-folder': {
        'field': {KEY: 'fields', DEFAULT: ()},
        'server': {KEY: 'servers', DEFAULT: ()},
        },
    'field': {
        'id': {},
        'label': {},
        'multivalued': {CONVERTER: importBool, DEFAULT: False},
        'mapped': {DEFAULT: ''},
        },
    'server': {
        'url': {},
        },
    })
