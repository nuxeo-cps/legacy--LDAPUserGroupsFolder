######################################################################
#
# utils     A collection of utility functions
#
# This software is governed by a license. See 
# LICENSE.txt for the terms of this license.
#
######################################################################
__version__='$Revision$'[11:-2]

from types import UnicodeType, StringType
import urllib, sha, SSHA, random, base64, codecs, string


#################################################
# "Safe" imports for use in the other modules
#################################################

try:
    import crypt
    HAVE_CRYPT = 1
except ImportError:
    crypt = None
    HAVE_CRYPT = 0

import ldap

#################################################
# Constants used in other modules
#################################################

HTTP_METHODS = ('GET', 'PUT', 'POST')

ldap_scopes = (ldap.SCOPE_BASE, ldap.SCOPE_ONELEVEL, ldap.SCOPE_SUBTREE)

GROUP_MEMBER_MAP = { 'groupOfUniqueNames' : 'uniqueMember'
                   , 'groupOfNames' : 'member'
                   , 'accessGroup' : 'member'
                   , 'group' : 'member'
                   }

encoding = 'latin1'


#################################################
# Helper methods for other modules
#################################################

def _verifyUnicode(st):
    """ Verify that the string is unicode """
    if type(st) is UnicodeType:
        return st
    else:
        try:
            return unicode(st)
        except UnicodeError:
            return unicode(st, encoding).encode(encoding)


def _createLDAPPassword(password, encoding='SHA'):
    """ Create a password string suitable for userPassword """
    if encoding == 'SSHA':
        pwd_str = '{SSHA}' + SSHA.encrypt(password)
    elif encoding == 'crypt':
        saltseeds = list('%s%s' % ( string.lowercase[:26]
                                  , string.uppercase[:26]
                                  ) )
        salt = ''
        for n in range(2):
            salt += random.choice(saltseeds)
        pwd_str = '{crypt}%s' % crypt.crypt(password, salt)
    elif encoding == 'clear':
        pwd_str = password
    else:
        sha_obj = sha.new(password)
        sha_dig = sha_obj.digest()
        pwd_str = '{SHA}' + base64.encodestring(sha_dig)

    return pwd_str.strip()


try:
    encodeLocal, decodeLocal, reader = codecs.lookup(encoding)[:3]
    encodeUTF8, decodeUTF8 = codecs.lookup('UTF-8')[:2]

    if getattr(reader, '__module__', '')  == 'encodings.utf_8':
        # Everything stays UTF-8, so we can make this cheaper
        to_utf8 = from_utf8 = str

    else:

        def from_utf8(s):
            return encodeLocal(decodeUTF8(s)[0])[0]

        def to_utf8(s):
            return encodeUTF8(decodeLocal(s)[0])[0]


except LookupError:
    raise LookupError, 'Unknown encoding "%s"' % encoding


#########################################################
# Stuff no longer needed with python-ldap 2.0.0pre14
#########################################################

try:
    import ldap.filter
    filter_format = ldap.filter.filter_format
    escape_filter_chars = ldap.filter.escape_filter_chars
except ImportError:
    def escape_filter_chars(assertion_value):
      """
      Replace all special characters found in assertion_value
      by quoted notation
      """
      s = assertion_value.replace('\\', r'\5c')
      s = s.replace(r'*', r'\2a')
      s = s.replace(r'(', r'\28')
      s = s.replace(r')', r'\29')
      s = s.replace('\x00', r'\00')
      return s
    
    
    def filter_format(filter_template,assertion_values):
      """
      filter_template
            String containing %s as placeholder for assertion values.
      assertion_values
            List or tuple of assertion values. Length must match
            count of %s in filter_template.
      """
      return filter_template % (tuple(map(escape_filter_chars,assertion_values)))
