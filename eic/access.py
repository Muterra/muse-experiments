'''
LICENSING
-------------------------------------------------

pyEIC: A python library for EIC manipulation.
    Copyright (C) 2014-2015 Nicholas Badger
    badg@nickbadger.com
    nickbadger.com

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
    USA

------------------------------------------------------
'''

# Import the base package
from .core import AccessProvider

# Global dependencies that aren't here because I'm being lazy
import base64
import struct
from collections import deque

# This is a universal symmetric key for public identities. It is contained 
# within the EIC spec in "bootstraps".
PUBLIC_ID_SYMKEY = bytes(32)

class IndividualAccessProvider(AccessProvider):
    ''' Implements an access provider for directly-shared individual 
    content.
    '''
    pass