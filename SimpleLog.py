#####################################################################
#
# SimpleLog     A simple logging module
#
# This software is governed by a license. See
# LICENSE.txt for the terms of this license.
#
#####################################################################

import time


class SimpleLog:
    """ A simple logging class """

    def __init__(self):
        """ Initialize a new instance """
        self._logbuffer = []


    def log(self, level, logline):
        """ Logs a single line and keeps log length at max. 500 lines.

        Level: 1 - Catastrophes
               2 - Major Events
               3 - Minor events
               4 - Login failures
               5 - Login Successes
               7 - Login success from cache
               9 - Debugging
        """
        time_str = time.strftime( '%b %d  %H:%M:%S'
                                , time.localtime(time.time())
                                )
        logged = '(%d)  %s:  %s' % (level, time_str, logline)

        self._logbuffer.append(logged)

        if len(self._logbuffer) > 500:
             self._logbuffer.pop(0)


    def clear(self):
        """ Clear the internal buffer """
        self._logbuffer = []
        self.log(0, 'Log buffer cleared')


    def getLog(self):
        """ Return the current log buffer """
        return self._logbuffer

