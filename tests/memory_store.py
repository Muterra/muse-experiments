import sys
sys.path.append('../')

# Global dependencies that aren't here because I'm being lazy
import base64
from collections import deque
import struct

# Local dependencies
import pyeic as pk

class MemoryStore(pk.StorageProvider):
    ''' A storage provider contained within a python object. 
    '''
    def __init__(self):
        self.store = {}
        self._dynamic_reg = {}

    def upload(self, bites):
        ''' Stores the object.
        '''
        # Check the appropriate bytes for the magic number, then do some
        # checking before storing the file.
        if bites[pk.EICa.header_bits['magic']] == pk.EICa.magic:
            # It's an EICa. Verify what we can and extract the EUID.
            try:
                euid = pk.EICa.verify_public(bites)['euid']
                # Cannot verify signature without the private key.
            except:
                raise RuntimeError('Failed to verify EICa.')

        elif bites[pk.EICs.header_bits['magic']] == pk.EICs.magic:
            # It's an EICs. Verify what we can and extract the EUID.
            try:
                euid = pk.EICs.verify_public(bites)['euid']
            except:
                raise RuntimeError('Failed to verify EICs.')


        elif bites[pk.EICd.header_bits['magic']] == pk.EICd.magic:
            # It's a dynamic file. First verify.
            # This needs a serious refactor at some point.
            try:
                # Verify the public parts, returning dict
                partial = pk.EICd.verify_public(bites)
                # Get the pubkey
                pubkey = pk.EICs.fetch(partial['author'], pk.PUBLIC_ID_SYMKEY,
                    [self])['pubkey']
                # Grab the euid
                euid = partial['euid']
                # Verify the signature
                if not pk.EICd.verify_signature(euid, pubkey, 
                        partial['signature']):
                    raise RuntimeError('Signature verficiation failed.')

                # Okay, everything looks good. Add it to self._dynamic_reg

                # First find out how many buffer frames are requested
                buffer_req = partial['buffer_req']
                # Get the reference hash
                half_euid = partial['header_hash']

                # WE NEED TO FIRST CHECK TO MAKE SURE THAT THE PREVIOUS HASH
                # MATCHES THE EXPECTED VALUE! Otherwise we're creating a 
                # vulnerability by updating the buffer size prematurely

                # WE NEED TO IMPLEMENT DELETION OF OLD EICD FILES IN THE STORE
                # UPON RESIZING THE BUFFER REQUEST. Currently any downsized
                # EICd files are left as rotting entropic orphans.

                # Check if it's already known to us
                try:
                    buffr = self._dynamic_reg[half_euid]
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
                buffr.append(partial['file_hash'])
                self._dynamic_reg[half_euid] = buffr

            except:
                raise RuntimeError('Failed to verify EICd.')


        else:
            # It's neither. Error.
            raise RuntimeError('Malformed EIC file: bad magic.')

        # Validation complete. Store it.
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

    def list_dynamic(self, header_hash):
        pass

    def write_to_disk(self, directory=None):
        ''' Writes the entire memory store to disk in the specified directory.
        If directory is None, stores in the current directory. Directory must
        contain a trailing slash.
        '''
        # If directory is unspecified, make it an empty string
        if not directory:
            directory = ''

        for euid, blob in self.store.items():
            # Does this smell fishy to you? Smells fishy to me.
            fname = directory + base64.urlsafe_b64encode(euid).decode()

            # Append the extension based on the type
            if blob[pk.EICa.header_bits['magic']] == pk.EICa.magic:
                fname += '.eica'
            elif blob[pk.EICs.header_bits['magic']] == pk.EICs.magic:
                fname += '.eics'
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