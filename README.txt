README for the Zope LDAPUserGroupsFolder Product

  This product includes software developed by Jens Vagelpohl for use in
  the Z Object Publishing Environment (http://www.zope.org/).

  NOTE: This products is not LDAPUserFolder but LDAPUserGroupsFolder. In
  most of the documentation the name LDAPUserFolder has been kept, but
  it is in fact really LDAPUserGroupsFolder...

  For any question about LDAPUserGroupsFolder, contact Nuxeo
  (http://www.nuxeo.com/).

  LDAPUserGroupsFolder adds to the standard LDAPUserFolder a notion of
  user groups (not to be confused with what LDAPUserFolder calls
  "groups" which are simply mapped to roles).


  This product is a replacement for a Zope user folder. It 
  does not store its own user objects but builds them on the 
  fly after authenticating a user against the LDAP database.


  **How to upgrade**

    Upgrading entails not only unpacking the new code, you
    should also delete and recreate all LDAPUserFolder
    instances in your Zope installation to prevent errors.


  **Custom login page**

    If you want custom login pages instead of the standard authentication
    popup dialogs I recommend installing the CookieCrumbler product 
    alongside the LDAPUserFolder which provides cookie authentication
    functionality for user folders.


  **Why does the LDAPUserFolder not show all my LDAP groups?**

    According to feedback received from people who use Netscape
    directory products the way a new group is instantiated allows
    empty groups to exist in the system. However, according to 
    the canonical definition for group records groups must always
    have a group member attribute.
    The LDAPUserFolder looks up group records by looking for group 
    member entries. If a group record has no members then it will
    be skipped. As said above, this only seems to affect Netscape
    directory servers.
    To work around this (Netscape) phenomenon add one or more 
    members to the group in question using the tools that came with
    the directory server. It should appear in the LDAPUserFolder
    after that.


  **Why is my site dog-slow all of a sudden?**

    If you run the following configuration...
    
      o python-ldap2.0.0pre1-4

      o LDAP server and Zope on the same machine

    you might run into unexpected slowdowns. This is due to a bug in
    python-ldap. Consult the following URL for help::

      http://www.geocrawler.com/archives/3/1568/2002/6/0/9027164/


  **Note about multi-valued attributes**

    If you want your user objects to expose the full sequence of values
    for a multi-valued attribute field you need to explicitly "bless"
    that attribute as Multi-valued on the "LDAP Schema" management tab.
    Multi-valued attributes will show up as a semicolon-separated string
    in the Zope Management interface itself. The user object carries these
    attrinutes as a list.


  **Why use LDAP to store user records?**

    LDAP as a source of Zope user records is an excellent 
    choice in many cases, like...

    o You already have an existing LDAP setup that might store
      company employee data and you do not want to duplicate 
      any data into a Zope user folder

    o You want to make the same user database available to 
      other applications like mail, address book clients,
      operating system authenticators (PAM-LDAP) or other 
      network services that allow authentication against
      LDAP

    o You have several Zope installations that need to share
      user records or a ZEO setup

    o You want to be able to store more than just user name
      and password in your Zope user folder

    o You want to manipulate user data outside of Zope

    ... the list continues.


  **Requirements**

    In order for this product to run you will need to provide the 
    following items:

    * a working LDAP server (see http://www.openldap.org/)

    * the python-ldap module (see http://python-ldap.sourceforge.net/)


  **Tested Platforms**

    This version of the LDAPUserFolder has been written on and for 
    Zope 2.4.0 and up. I have run the LDAPUserFolder successfully on...

      - Zope 2.4-series
      - Zope 2.5-series
      - Zope 2.6-series
      - Zope 2.7-series

    This product is platform-independent except for its reliance on 
    the python-ldap module. If you cannot compile or find a python-
    ldap module suitable for your platform the LDAPUserFolder 
    will not work.


  **The LDAP Schema**

    Your LDAP server should contain records that can be used as user 
    records. Any object types like person, organizationalPerson, 
    or inetOrgPerson and any derivatives thereof should work. After a
    small code change records of type posixAccount should work
    correctly as well.
    The LDAPUserFolder expects your user records to have at least the 
    following attributes, most of which are required for the 
    abovementioned object classes, anyway:

    * cn (Canonical Name)

    * userPassword (the password field)

    * objectClass

    * whatever attribute you choose as the username attribute

    * typcial person-related attributes like sn (last name), 
      givenName (first name), uid or mail (email address) will make 
      working with the LDAPUserFolder nicer

    Zope users have certain roles associated with them, these roles
    determine what permissions the user have. In LDAPUserFolder-speak, 
    roles are embodied in Groups.

    Group records can be of any object type that accepts multiple 
    attributes of type "uniqueMember" and that has a "cn" attribute.
    One such type is "groupOfUniqueNames". The cn describes the 
    group / role name while the uniqueMember attributes point back 
    to all those user records that are part of this group.

    For examples of valid group- and user-records for LDAP please
    see the file SAMPLE_RECORDS.txt in this distribution. It has 
    samples for a user- and a group record in LDIF format.

    It is outside of the scope of this documentation to describe the 
    different object classes and attributes in detail, please see 
    LDAP documentation for a better treatment.


  **Things to watch out for**

    Since a user folder is one of these items that can lock users out 
    of your site if they break I suggest testing the settings in some 
    inconspicuous location before replacing a site's main acl_users folder 
    with a LDAPUserFolder.

    As a last resort you will always be able to log in and make changes 
    as the superuser (or in newer Zope releases called "emergency user") 
    who, as an added bonus, can delete and create user folders. This is 
    a breach of the standard "the superuser cannot create / own anything" 
    policy, but can save your skin in so many ways.


