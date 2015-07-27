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
from .core import *

# Global dependencies that aren't here because I'm being lazy
import base64
import struct
import os
import errno
from collections import deque
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class MemoryStore(StorageProvider):
    ''' A storage provider contained within a python object. 
    '''
    def __init__(self):
        self.store = {}
        self._dynamic_bookie = {}

    def ping(self, address):
        ''' Checks self for the address (euid or dynamic reference).

        returns:
        b'd' if dynamic
        b's' if static
        False if not found
        '''
        # Is it an euid?
        if address in self.store:
            return b's'
        # Is it a dynamic reference?
        elif address in self._dynamic_bookie:
            return b'd'
        # It's neither?
        else:
            raise TypeError('Address appears to be neither an euid nor a '
                            'dynamic reference.')

    def upload(self, bites):
        ''' Stores the object.
        '''
        # Check the appropriate bytes for the magic number, then do some
        # checking before storing the file.
        if bites[EICa.header_bits['magic']] == EICa.magic:
            # It's an EICa. Verify what we can and extract the EUID.
            try:
                euid = EICa.verify_public(bites)['euid']
                # Cannot verify signature without the private key.
            except:
                raise RuntimeError('Failed to verify EICa.')

        elif bites[EICs.header_bits['magic']] == EICs.magic:
            # It's an EICs. Verify what we can and extract the EUID.
            try:
                euid = EICs.verify_public(bites)['euid']
            except:
                raise RuntimeError('Failed to verify EICs.')


        elif bites[EICd.header_bits['magic']] == EICd.magic:
            # It's a dynamic file. First verify.
            # This needs a serious refactor at some point.
            try:
                # Verify the public parts, returning dict
                partial = EICd.verify_public(bites)
                # Get the pubkey
                # Danger! This will be an issue if the pubkey format or crypto
                # API ever changes.
                pubkey = EICs.fetch(partial['author'], AUTHOR_BOOTSTRAP_SYMKEY,
                    [self])[b'pubkey']
                pubkey = serialization.load_pem_public_key(
                    pubkey,
                    backend=default_backend()
                )
                # Grab the euid
                euid = partial['euid']
                # Verify the signature
                if not EICBase.verify_signature(euid, pubkey, 
                        partial['signature']):
                    raise RuntimeError('Signature verficiation failed.')

                # Okay, everything looks good. Add it to self._dynamic_bookie

                # First find out how many buffer frames are requested
                buffer_req = partial['buffer_req']
                # Get the reference hash
                half_euid = partial['header_hash']

                # Todo:

                # WE NEED TO FIRST CHECK TO MAKE SURE THAT THE PREVIOUS HASH
                # MATCHES THE EXPECTED VALUE! Otherwise we're creating a 
                # vulnerability by updating the buffer size prematurely

                # WE NEED TO IMPLEMENT DELETION OF OLD EICD FILES IN THE STORE
                # UPON RESIZING THE BUFFER REQUEST. Currently any downsized
                # EICd files are left as rotting entropic orphans.

                # Check if it's already known to us
                try:
                    buffr = self._dynamic_bookie[half_euid]
                    # If the buffer request has changed, we need to copy the
                    # buffer deque
                    if buffr.maxlen != buffer_req:
                        buffr = deque(buffr, maxlen=buffer_req)
                    # Grab the last file hash for checking order
                    check_previous = buffr[len(buffr) - 1]

                # Can't find the key, so it doesn't exist, so create it.
                except KeyError:
                    check_previous = half_euid
                    buffr = deque(maxlen=buffer_req)

                # Make sure that the incoming EICd has the expected previous
                if partial['previous_hash'] != check_previous:
                    raise RuntimeError('Broken hash chain. Check parent EICd '
                                       'order.')

                # We've verified that this is, in fact, the next one up, so
                # let's have a go at recording it.
                # One last thing, before we go, go: if we're at the max length
                # we can also delete the corresponding file from the store.
                if len(buffr) == buffr.maxlen:
                    # The previous 
                    leftmost_euid = buffr.popleft() + half_euid
                    del self.store[leftmost_euid]
                buffr.appendleft(partial['file_hash'])
                self._dynamic_bookie[half_euid] = buffr

            except:
                raise RuntimeError('Failed to verify EICd.')

        else:
            # It's neither. Error.
            raise RuntimeError('Malformed EIC file: bad magic.')

        # Validation complete. Store it if we don't already have it.
        if euid not in self.store:
            self.store[euid] = bites

        # Return the euid as verification of success
        return euid

    def download(self, euid):
        ''' Retrieves an object. If the object does not exist, return None.
        Other errors will not be caught.
        '''
        try:
            return self.store[euid]
        except KeyError:
            return None

    def list_frames(self, dynamic_ref):
        '''Looks through the record of dynamic objects, finds the corresponding
        dynamic reference, and then returns a list of relevant frames, sorted
        from most recent [0] to oldest [n].
        '''
        # First make sure we have it.
        if not self.ping(dynamic_ref):
            raise RuntimeError('This store has no EICd files with a matching '
                               'dynamic reference.')

        # Now, like, do that shit.
        return list(self._dynamic_bookie[dynamic_ref])

    def write_to_disk(self, directory=None):
        ''' Writes the entire memory store to disk in the specified directory.
        If directory is None, stores in the current directory. Directory must
        contain a trailing slash.

        Note that this method currently does NOT wipe existing dynamic files 
        that have expired from the buffer. As such, it doesn't currently 
        natively support the deletion of old buffered frames.
        '''
        # If directory is unspecified, make it an empty string
        if not directory:
            directory = 'dump'
        # Make sure the directory exists
        try:
            os.makedirs(directory)
        except OSError as exception:
            if exception.errno != errno.EEXIST:
                raise RuntimeError('Failed to create directory.')
        # Verify the trailing slash
        if directory[len(directory) - 1] != '/':
            directory += '/'

        for euid, blob in self.store.items():
            # Does this smell fishy to you? Smells fishy to me.
            fname = directory + base64.urlsafe_b64encode(euid).decode()

            # Append the extension based on the type
            if blob[EICa.header_bits['magic']] == EICa.magic:
                fname += '.eica'
            elif blob[EICs.header_bits['magic']] == EICs.magic:
                fname += '.eics'
            elif blob[EICd.header_bits['magic']] == EICd.magic:
                fname += '.eicd'
            else:
                raise RuntimeError('This blob doesn\'t appear to be an eic.')

            with open(fname, 'wb') as outfile:
                outfile.write(blob)

    @classmethod
    def read_from_disk(cls, directory):
        ''' Loads all .eica, .eics, and .eic files within a directory and 
        returns a MemoryStore object with them.
        '''
        pass