#!/bin/sh
#####################################################################
#
# run_tests     Convenience script to run the LDAPUserrFolder
#               package unit tests. Will need adjustments for 
#               different environments.
#
# This software is governed by a license. See
# LICENSE.txt for the terms of this license.
#
#####################################################################
__version__='$Revision$'[11:-2]

# The Zope Instance home. Comment out if you do not use one.
export INSTANCE_HOME=/usr/local/zope/InstanceHome

# The Zope Software Home. This must point to the lib/python-directory
# inside your Zope installation.
export SOFTWARE_HOME=/usr/local/zope/opt/Zope-2_7-branch/lib/python

# The directory where the LDAPUserFolder software is installed
LUF_SOFTWARE_HOME=/usr/local/zope/Products/LDAPUserFolder

# The python binary
PYTHON=/usr/local/bin/python

#####################################################################
# The following lines do not need changing
#####################################################################
export PYTHONPATH="$SOFTWARE_HOME:$SOFTWARE_HOME/lib/python:$INSTANCE_HOME:$LUF_SOFTWARE_HOME"

echo
echo Testing LDAPUser:
$PYTHON $LUF_SOFTWARE_HOME/tests/testLDAPUser.py
echo

echo Testing LDAPUserFolder:
$PYTHON $LUF_SOFTWARE_HOME/tests/testLDAPUserFolder.py
echo

echo Testing LDAPUserSatellite:
$PYTHON $LUF_SOFTWARE_HOME/tests/testLDAPUserSatellite.py
echo

echo Testing SimpleLog:
$PYTHON $LUF_SOFTWARE_HOME/tests/testSimpleLog.py
echo

echo Testing SimpleCache:
$PYTHON $LUF_SOFTWARE_HOME/tests/testSimpleCache.py
echo
