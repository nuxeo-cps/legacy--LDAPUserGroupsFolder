##############################################################################
#
# __init__.py	Initialization code for the LDAPUserFolder
#
# This software is governed by a license. See
# LICENSE.txt for the terms of this license.
# 
##############################################################################

__doc__     = """ LDAPUserFolder initialization module """
__version__ = '$Revision$'[11:-2]

from AccessControl.Permissions import add_user_folders

from LDAPUserFolder import addLDAPUserFolderForm, \
                           manage_addLDAPUserGroupsFolder, \
                           LDAPUserFolder
from LDAPUserSatellite import addLDAPUserSatelliteForm, \
                              manage_addLDAPUserSatellite, \
                              LDAPUserSatellite

def initialize(context):
    context.registerClass( LDAPUserFolder
                         , permission=add_user_folders
                         , constructors=( addLDAPUserFolderForm
                                        , manage_addLDAPUserGroupsFolder
                                        )
                         , icon='www/ldapuserfolder.gif'
                         )

    context.registerClass( LDAPUserSatellite
                         , permission=add_user_folders
                         , constructors=( addLDAPUserSatelliteForm
                                        , manage_addLDAPUserSatellite
                                        )
                         , icon='www/ldapusersatellite.gif'
                         )

    context.registerHelp()

    # CMFSetup registration
    import setup
