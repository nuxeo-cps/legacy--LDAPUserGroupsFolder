#####################################################################
#
# LDAPDelegate  A delegate that performs all LDAP-related operations
#
# This software is governed by a license. See
# LICENSE.txt for the terms of this license.
#
#####################################################################
__version__='$Revision$'[11:-2]

# General python imports
import sys, ldap
from types import DictType, StringType

# Zope imports
from Persistence import Persistent
from AccessControl.SecurityManagement import getSecurityManager

# LDAPUserFolder package imports
from utils import to_utf8, from_utf8

try:
    from ldapurl import LDAPUrl
except ImportError:
    LDAPUrl = None

ADD = ldap.MOD_ADD
DELETE = ldap.MOD_DELETE
REPLACE = ldap.MOD_REPLACE
BASE = ldap.SCOPE_BASE
ONELEVEL = ldap.SCOPE_ONELEVEL
SUBTREE = ldap.SCOPE_SUBTREE


def explode_dn(dn, notypes=0):
    """ Indirection to avoid need for importing ldap elsewhere """
    return ldap.explode_dn(dn, notypes)


class LDAPDelegate(Persistent):
    """ LDAPDelegate 

    This object handles all LDAP operations. All search operations will
    return a dictionary, where the keys are as follows:

    exception   - Contains a string representing exception information 
                  if an exception was raised during the operation.

    size        - An integer containing the length of the result set
                  generated by the operation. Will be 0 if an exception
                  was raised.

    results     - Sequence of results
    """

    def __init__( self, server='', login_attr='', users_base='', rdn_attr=''
                , use_ssl=0, bind_dn='', bind_pwd='', read_only=0
                ):
        """ Create a new LDAPDelegate instance """
        self._servers = []
        self.edit( login_attr, users_base, rdn_attr
                 , 'top,person', bind_dn, bind_pwd
                 , 1, read_only
                 )

        if server != '':
            if server.find(':') != -1:
                host = server.split(':')[0].strip()
                port = int(server.split(':')[1])
            else:
                host = server

                if use_ssl:
                    port = 636
                else:
                    port = 389

            self.addServer(host, port, use_ssl)


    def addServer(self, host, port='389', use_ssl=0):
        """ Add a server to our list of servers """
        servers = self.getServers()

        if use_ssl:
            protocol = 'ldaps'
        else:
            protocol = 'ldap'

        already_exists = 0
        for server in self._servers:
            if str(server['host']) == host and str(server['port']) == port:
                already_exists = 1
                break
        
        if not already_exists:
            servers.append( { 'host' : host
                            , 'port' : port
                            , 'protocol' : protocol
                            } )

        self._servers = servers


    def getServers(self):
        """ Return info about all my servers """
        servers = getattr(self, '_servers', [])

        if isinstance(servers, DictType):
            servers = servers.values()
            self._servers = servers

        return servers


    def deleteServers(self, position_list=()):
        """ Delete server definitions """
        old_servers = self.getServers()
        new_servers = []
        position_list = [int(x) for x in position_list]

        for i in range(len(old_servers)):
            if i not in position_list:
                new_servers.append(old_servers[i])

        self._servers = new_servers
        self._v_conn = None


    def edit( self, login_attr, users_base, rdn_attr, objectclasses
            , bind_dn, bind_pwd, binduid_usage, read_only
            ):
        """ Edit this LDAPDelegate instance """
        self.login_attr = login_attr
        self.rdn_attr = rdn_attr
        self.bind_dn = bind_dn
        self.bind_pwd = bind_pwd
        self.binduid_usage = int(binduid_usage)
        self.read_only = not not read_only
        self.u_base = users_base

        if isinstance(objectclasses, StringType):
            objectclasses = [x.strip() for x in objectclasses.split(',')]
        self.u_classes = objectclasses


    def connect(self, bind_dn='', bind_pwd=''):
        """ initialize an ldap server connection """
        conn = getattr(self, '_v_conn', None)

        if bind_dn != '':
            user_dn = bind_dn
            user_pwd = bind_pwd or '~'
        elif self.binduid_usage == 1:
            user_dn = self.bind_dn
            user_pwd = self.bind_pwd
        else:
            user = getSecurityManager().getUser()
            try:
                user_dn = user.getUserDN()
                user_pwd = user._getPassword()
            except AttributeError:  # User object is not a LDAPUser
                user_dn = user_pwd = ''

        if conn is not None:
            try:
                conn.simple_bind_s(user_dn, to_utf8(user_pwd))
                conn.search_s(self.u_base, BASE, '(objectClass=*)')
                return conn
            except (AttributeError, ldap.SERVER_DOWN, ldap.NO_SUCH_OBJECT):
                pass

        for server in self._servers:
            host = server.get('host')
            port = server.get('port')
            protocol = server.get('protocol')
            conn_str = '%s://%s:%s' % (protocol, host, port)

            try:
                connection = self._connect(conn_str, user_dn, user_pwd)
                self._v_conn = connection

                return connection

            except ldap.SERVER_DOWN:
                continue

        raise ldap.CONNECT_ERROR, 'Cannot connect to any server'


    def handle_referral(self, exception):
        """ Handle a referral specified in a exception """
        payload = exception.args[0]
        info = payload.get('info')
        ldap_url = info[info.find('ldap'):]

        if ldap.is_ldap_url(ldap_url):
            parsed_url = LDAPUrl(ldap_url)
            conn_str = '%s://%s' % ( parsed_url.urlscheme or 'ldap'
                                   , parsed_url.hostport
                                   )

            if self.binduid_usage == 1:
                user_dn = self.bind_dn
                user_pwd = self.bind_pwd
            else:
                user = getSecurityManager().getUser()
                try:
                    user_dn = user.getUserDN()
                    user_pwd = user._getPassword()
                except AttributeError:  # User object is not a LDAPUser
                    user_dn = user_pwd = ''

            return self._connect(conn_str, user_dn, user_pwd)

        else:
            raise ldap.CONNECT_ERROR, 'Bad referral "%s"' % str(e)


    def _connect(self, connection_string, user_dn, user_pwd):
        """ Factored out to allow usage by other pieces """
        # Connect to the server to get a raw connection object
        connection = ldap.initialize(connection_string)

        # Set the protocol version - version 3 is preferred
        try:
            connection.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
        except ldap.LDAPError: # Invalid protocol version, fall back safely
            connection.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION2)

        # Now bind with the credentials given. Let exceptions propagate out.
        connection.simple_bind_s(user_dn, to_utf8(user_pwd))

        # Deny auto-chasing of referrals to be safe, we handle them instead
        try:
            connection.set_option(ldap.OPT_REFERRALS, 0)
        except ldap.LDAPError: # Cannot set referrals, so do nothing
            pass

        try: # XXX Not sure if needed.
            connection.manage_dsa_it(0)
        except:
            pass

        return connection


    def search( self
              , base
              , scope
              , filter='(objectClass=*)'
              , attrs=[]
              , bind_dn=''
              , bind_pwd=''
              ):
        """ The main search engine """
        result = { 'exception' : ''
                 , 'size' : 0
                 , 'results' : []
                 }
        filter = to_utf8(filter)

        try:
            connection = self.connect(bind_dn=bind_dn, bind_pwd=bind_pwd)
            if connection is None:
                result['exception'] = 'Cannot connect to LDAP server'
                return result

            try:
                res = connection.search_s(base, scope, filter, attrs)
            except ldap.PARTIAL_RESULTS:
                res_type, res = connection.result(all=0)
            except ldap.REFERRAL, e:
                connection = self.handle_referral(e)

                try:
                    res = connection.search_s(base, scope, filter, attrs)
                except ldap.PARTIAL_RESULTS:
                    res_type, res = connection.result(all=0)

            for rec_dn, rec_dict in res:
                for key, value in rec_dict.items():
                    if not isinstance(value, StringType):
                        try:
                            for i in range(len(value)):
                                value[i] = from_utf8(value[i])
                        except:
                            pass

                rec_dict['dn'] = from_utf8(rec_dn)

                result['results'].append(rec_dict)
                result['size'] += 1

        except ldap.INVALID_CREDENTIALS:
            result['exception'] = 'Invalid authentication credentials'

        except ldap.NO_SUCH_OBJECT:
            result['exception'] = 'Cannot find %s under %s' % (filter, base)

        except ldap.SIZELIMIT_EXCEEDED:
            result['exception'] = 'Too many results for this query'

        except Exception, e:
            result['exception'] = str(e)

        return result


    def insert(self, base, rdn, attrs=None):
        """ Insert a new record """
        if self.read_only:
            return 'Running in read-only mode, insertion is disabled'

        msg = ''
        dn = to_utf8('%s,%s' % (rdn, base))
        attribute_list = []
        attrs = attrs and attrs or {}

        for attr_key, attr_val in attrs.items():
            if isinstance(attr_val, StringType):
                attr_val = [x.strip() for x in attr_val.split(';')]

            if attr_val != ['']:
                attr_val = map(to_utf8, attr_val)
                attribute_list.append((attr_key, attr_val))

        try:
            connection = self.connect()
            connection.add_s(dn, attribute_list)
        except ldap.INVALID_CREDENTIALS, e:
            e_name = e.__class__.__name__
            msg = '%s No permission to insert "%s"' % (e_name, dn)
        except ldap.ALREADY_EXISTS, e:
            e_name = e.__class__.__name__
            msg = '%s Record with dn "%s" already exists' % (e_name, dn)
        except ldap.REFERRAL, e:
            try:
                connection = self.handle_referral(e)
                connection.add_s(dn, attribute_list)
            except ldap.INVALID_CREDENTIALS:
                e_name = e.__class__.__name__
                msg = '%s No permission to insert "%s"' % (e_name, dn)
            except Exception, e:
                e_name = e.__class__.__name__
                msg = '%s LDAPDelegate.insert: %s' % (e_name, str(e))
        except Exception, e:
            e_name = e.__class__.__name__
            msg = '%s LDAPDelegate.insert: %s' % (e_name, str(e))

        return msg


    def delete(self, dn):
        """ Delete a record """
        if self.read_only:
            return 'Running in read-only mode, deletion is disabled'

        msg = ''

        try:
            connection = self.connect()
            connection.delete_s(dn)
        except ldap.INVALID_CREDENTIALS:
            msg = 'No permission to delete "%s"' % dn
        except ldap.REFERRAL, e:
            try:
                connection = self.handle_referral(e)
                connection.delete_s(dn)
            except ldap.INVALID_CREDENTIALS:
                msg = 'No permission to delete "%s"' % dn
            except Exception, e:
                msg = 'LDAPDelegate.delete: %s' % str(e)
        except Exception, e:
            msg = 'LDAPDelegate.delete: %s' % str(e)

        return msg


    def modify(self, dn, mod_type=None, attrs=None):
        """ Modify a record """
        if self.read_only:
            return 'Running in read-only mode, modification is disabled'

        utf8_dn = to_utf8(dn)
        res = self.search(base=utf8_dn, scope=BASE)
        attrs = attrs and attrs or {}

        if res['exception']:
            return res['exception']

        if res['size'] == 0:
            return 'LDAPDelegate.modify: Cannot find dn "%s"' % dn

        cur_rec = res['results'][0]
        mod_list = []
        msg = ''

        for key, values in attrs.items():
            values = map(to_utf8, values)

            if mod_type is None:
                if cur_rec.get(key, ['']) != values and values != ['']:
                    mod_list.append((REPLACE, key, values))
                elif cur_rec.has_key(key) and values == ['']:
                    mod_list.append((DELETE, key, None))
            else:
                mod_list.append((mod_type, key, values))

        try:
            connection = self.connect()

            new_rdn = attrs.get(self.rdn_attr, [''])[0]
            if new_rdn and new_rdn != cur_rec.get(self.rdn_attr)[0]:
                new_utf8_rdn = to_utf8('%s=%s' % (self.rdn_attr, new_rdn))
                connection.modrdn_s(utf8_dn, new_utf8_rdn)
                old_dn_exploded = explode_dn(utf8_dn)
                old_dn_exploded[0] = new_utf8_rdn
                utf8_dn = ','.join(old_dn_exploded)

            connection.modify_s(utf8_dn, mod_list)

        except ldap.INVALID_CREDENTIALS, e:
            e_name = e.__class__.__name__
            msg = '%s No permission to modify "%s"' % (e_name, dn)

        except ldap.REFERRAL, e:
            try:
                connection = self.handle_referral(e)
                connection.modify_s(dn, mod_list)
            except ldap.INVALID_CREDENTIALS, e:
                e_name = e.__class__.__name__
                msg = '%s No permission to modify "%s"' % (e_name, dn)
            except Exception, e:
                e_name = e.__class__.__name__
                msg = '%s LDAPDelegate.modify: %s' % (e_name, str(e))

        except Exception, e:
            e_name = e.__class__.__name__
            msg = '%s LDAPDelegate.modify: %s' % (e_name, str(e))

        return msg

