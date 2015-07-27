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
# Global dependencies that aren't here because I'm being lazy
import base64
import struct
from collections import deque
import abc

# This is a universal symmetric key for public identities. It is contained 
# within the EIC spec in "bootstraps".
PUBLIC_ID_SYMKEY = bytes(32)
PUBLIC_ID_PRIVKEY = bytes(512)
PUBLIC_ID_PUBKEY = bytes(512)
    
    
class IdentityProvider(metaclass=abc.ABCMeta):
    ''' An abstract base class for a mechanism that keeps track of 
    identity requirements.
    '''
    def __init__(self, storage_providers):
        ''' Blahblahblah.
        '''
        # How to check any of these?
        self._stores = storage_providers
        
    @property
    def storage_providers(self):
        ''' Read-only property returning the storage providers.
        '''
        return self._stores
        
    @abc.abstractmethod
    def fetch_pubkey(self, euid, cipher_suite):
        ''' Returns the pubkey associated with the given euid.
        '''
        pass
        
    @abc.abstractmethod
    def new_identity(self, pubkey):
        ''' Creates an identity from the pubkey, returning the euid.
        '''
        pass
        

class GenericIdentityProvider(IdentityProvider):
    ''' Implements an access provider solely tasked with unlocking 
    identities.
    '''
    def fetch_pubkey(self, euid):
        ''' Gets the public key from an euid at self's storage 
        providers.
        '''
        eics = EICs.fetch(euid, PUBLIC_ID_SYMKEY, self.storage_providers)
        
        