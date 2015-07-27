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

todo: redo this in four files: core, eica, eicd, eics; make liberal use
of helper classes. In particular, _EicaBuilder, _EicdBuilder, etc, would
be very, very useful. Entirely separate the de/serialization aspect from 
the implementation aspect from the python object aspect.

todo: rewrite code to at least look at the cipher suite part of the 
version field.

TODO: ALL should have self.commit() that is different from push.

todo: CryptoProvider

DANGER DANGER DANGER: problem with Crypto on Windows. See:
http://stackoverflow.com/
    questions/24804829/another-one-about-pycrypto-and-paramiko
'''

# Global dependencies
import io
import struct
import collections
import abc
import json
import base64
import os
from warnings import warn
import hashlib
import zbg
# import Crypto
# import simpleubjson as ubj
# from Crypto.Random import random
# from Crypto.Hash import SHA256
# hasher = SHA256.new()
import cryptography
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from Crypto.Hash import SHA512
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

# Important constants for the headers
# padding_outer = 400 * struct.pack('>x')

AUTHOR_BOOTSTRAP = bytes(64)
AUTHOR_BOOTSTRAP_SYMKEY = bytes(32)
AUTHOR_BOOTSTRAP_PRIVKEY = b'''-----BEGIN RSA PRIVATE KEY-----
MIIJJwIBAAKCAgEAvIWqNMYCLGTIL2zUmrm7v6S4YlL39HlgqHaDsh1Kv8t7aYXn
sM6vrbPsz0OzVik2T3957H/mZIgtpeZd8w4ThIhD0re1EU3uRVQDI2Fsuhx2zVfM
6aNsB2IErvizDdt8JtT72ulHZth1EVxkdvzOjPrzUr5BPGEbQXkkmRgjpf9VcS4k
jIMTmZrKHVKbXhAOgSDMGgDvWexNXobzVtam4BSgFR6Nxgj5z76/yqme0NZy9ap8
wUNEDv9Yif5HcsDUfJdLsDCujeJ6MIJwMNS/tjAf2BnSLrtP4u4ZncO0Eirmy3q9
6nLtBD3MnR9PpIfB0UXfuFZtumTgevLsN8dDIBBb8OsUWAZjbLFn43z0zCNbTVMt
AbokEwaccATsKyuD8IWBUAKUnNiV16b/PvbExjwQcJUc8MgGmEuaxm0i2b+06/fK
ldiBe2iu9mTH0i77dWcX18DGBGz3ccYyFMpdu9Spb206JON2TsDPMc9QYIuAf0Z7
FRuJ1dbi6Jfd7uodIipAgNmz8VVkTsY2y2QUvn1cAm2IyD0LJC0v/yFbYfxqFqi6
1ToUnELgr+0dS9Hs3Tw7bylnqQQPZw1XznUuBNhszZtWF1oiuSOzlX0RCOwiSE0J
vIsGnG6HHoytcy2KEZpW5n9KEa96NvfGTBZ99dgClteD4ruruwTobeLuZPECAwEA
AQKCAgAjPPDVsHVTivsIMlWDHliDt+xnJI8IeW+hzZVMQ8FnHEfTL55hJCEeXNVU
4Jiy8D0gmvlVRYrxG6s8qVTCS81GJppW1tPXijORbeSwRlOmbg+ezlyVB2D3+FBb
zEzbuDz6nTD+eEBKbwdi2VxGCXcqTvYQb1OOT7BiipxWqXZwXsu/vhpC0XVmbtJ8
rKYx7NppNJIyAh67Njo4Aw2VG8ZReEl76Rwi+iaHuGXtIct3yb3vQZDUJxifnQcV
tBvyzSxqpXUWV+Mozj58tsT1u66iBVjOcfUhmw2Ro2PSY3RTOQWu3yCEpDq9YjfO
3r1qSZ3m2iK5OB6GiriTArk4q9xV3Vi/QGNTBzBrFGEHOLI3IdFXbQxH3zkLt8Q6
LCuXZ5WHBLODrbpO+xpqbKDDpa0G+7Eb5QBKGNrqJ1n+D/zDNDxj6glcXwXgabcf
PacC1eLYIQnB6wCV9GAJaLFpa+SfwrCb8iUjh25KLw/tnCxBlzVXySh+0bOtp4uZ
tZS+btaQcdgg2ZHkBfVQNYAi35y6aduqM2L8hBWSPQwWErn12eMEUmv/owANmpkh
9bc8PXQBPlnoNTOfX8bVs9C6K2eGAy0BVvnWk23dT5WXCwyN+wZSzzhrRABkCyqM
1ui6Wms8u4X08Vyhdn8CcANQT70KfTA1wGQ54UhT5YLqPfUXyQKCAQEA9ULa53g/
SZJB8vBs5jxcEylT/r6Xjrc26W2Q73KmW9+DwTrFoYA8DAIFmnvqhmnwXbNhvY2I
/BYtGTtosMtFCoiEDYh9Ig6HgvcixFdvAnfxY+DW/8wHlz7/HQ5/iXJRBkBhD16v
SEjfgjUAfryLKQsPK3ZfcddCFPqrAydPYaT8EoSLhLjGYt0hdMVsP0yNfLLGggzd
vKOZnkYyzEtIs9ROpDf3QvvDTm2HAdJ6qB+uZ4UCBL3LSzilwzhQJZ0VYkd7Z8AK
QvZ4Zzt4SgknUDpM84HJ7wl5yD6wJN5jQRVrAIIEXJLRGgb6vRGrnK8h1eqq1Msp
8Mhz+ZKYiQPJ2wKCAQEAxMbRsiMxeFM68bTJRE+ImMY9aD+q7ABr6rHccUNxmipz
qIMNl6pTurONsNRofeHypqXKoPiKgU/xcI/R4xHXJHFTAhjV33zJW4zskAy8WP3E
txCn9qHHO35l2xwZYpB5/hd/vkH92VTwkxx/jfp9P4ol3ZKQwMIuNafZPvsAQfBT
ua5xmPe1C1OuUzudQfbAZGJuOF0dTZQsK46+RZkCl2+TUx9kPBEaRK6/yN6GVY6E
K7UpKO4mCqEO5BcXvam7iU8Qf6wA3BBxcKHwTBMvu//EZcsahAFQYi9ahZ5NQY+L
FVL4zaDVGlnt4eT6W1orxlo7fnAd3YZByAbi1UUkIwKCAQBtB3Fk4PHRdPFYXEUs
/Lw50G+EmZmqWgxRLOH3cFJAGVbq+YONzgHjnKp9CIUzh7jRDsNujpLM7dbSlrRt
k493pUR+96QZFbhsIg0Ul4HD6SooKnWpdTwSonCqrB1KLsWSL+B2ArONQMgLjCBS
NuLuNfpiadb4NqcryFtppXoGgF+Go+GZ+MJIhOEwlesPIKrtOlRA0BNqnpfV4oMG
ipkhSEpFepOy9VTXcp1H1Beu0Zaoclp5XR4YrHAUHt6SOgidjgVwE9D7/7F6wtcw
om0VnzVCMvpgByhaOnP3j90zu5+7tBDYTnQiS+P/VPGjT7+M5ytWOZLFdXcJBYBF
uKdtAoIBAETumRrcNUI/ddCiUjc53VIXb/+K/ic6ZpOKxvxuceddo7KOZj6RDk/D
AonFfu1KL6StQ3RsXKi8Boo194KiB0ne4QNFC/cEUc1eaqhzra9HBphSn2RIe/Cd
cLT2/PWIQxP9y2Qs3e46USRXwV9NNn8BuA4Mf+TmoSVurS3g49A1jj7nmyfI7oUP
RWwm4AnxlKgVyyK3i8JXe7mugX0EAuJl1agywPxByX/x74FAYrKqACcHiWmrM2xZ
y0ufw1NPmECbj94JtStiHzsjn3gm6HvlNzmpkppXk38xs3ZHZCzpSgGoVTxDcSOQ
CUMu4X0K83bCuUCrqeqmU3js4J1xYR0CggEAEeY3FCuShhi2/iSTd5mcUDegDipV
kAfZjKGwWF1x0xzp+emm+aGjPvGmUGdzE7k8vDN3izFLMZObYgNPP8hNmBCkIQGf
0cYEjuLvd/qSECu6/CycvsHo21/eMxZrZ/z3wpda6KI0f8iHGJz1vUkJtJgTWoJ9
2jhUia01jHz6yD2psIE+I7VH8EvHJt1V7S2/h9q6q8VT0odvlVx1e8RnXAAIu26m
xlbge5TAqDmZy4adKGvfPwX4Ohd9EYjTSB19pmRbA/jFr9fds2dduvLnutchsjGp
Hf5oksq1UHAmKz76qp5rmLpz4Zv/GdHHR2x2vVpECoi1pAZYKzPpjDHIBQ==
-----END RSA PRIVATE KEY-----
'''
_AUTHOR_BOOTSTRAP_PRIVKEY = serialization.load_pem_private_key(
    AUTHOR_BOOTSTRAP_PRIVKEY,
    password=None,
    backend=default_backend()
)

AUTHOR_BOOTSTRAP_PUBKEY = b'''-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvIWqNMYCLGTIL2zUmrm7
v6S4YlL39HlgqHaDsh1Kv8t7aYXnsM6vrbPsz0OzVik2T3957H/mZIgtpeZd8w4T
hIhD0re1EU3uRVQDI2Fsuhx2zVfM6aNsB2IErvizDdt8JtT72ulHZth1EVxkdvzO
jPrzUr5BPGEbQXkkmRgjpf9VcS4kjIMTmZrKHVKbXhAOgSDMGgDvWexNXobzVtam
4BSgFR6Nxgj5z76/yqme0NZy9ap8wUNEDv9Yif5HcsDUfJdLsDCujeJ6MIJwMNS/
tjAf2BnSLrtP4u4ZncO0Eirmy3q96nLtBD3MnR9PpIfB0UXfuFZtumTgevLsN8dD
IBBb8OsUWAZjbLFn43z0zCNbTVMtAbokEwaccATsKyuD8IWBUAKUnNiV16b/PvbE
xjwQcJUc8MgGmEuaxm0i2b+06/fKldiBe2iu9mTH0i77dWcX18DGBGz3ccYyFMpd
u9Spb206JON2TsDPMc9QYIuAf0Z7FRuJ1dbi6Jfd7uodIipAgNmz8VVkTsY2y2QU
vn1cAm2IyD0LJC0v/yFbYfxqFqi61ToUnELgr+0dS9Hs3Tw7bylnqQQPZw1XznUu
BNhszZtWF1oiuSOzlX0RCOwiSE0JvIsGnG6HHoytcy2KEZpW5n9KEa96NvfGTBZ9
9dgClteD4ruruwTobeLuZPECAwEAAQ==
-----END PUBLIC KEY-----
'''
_AUTHOR_BOOTSTRAP_PUBKEY = serialization.load_pem_public_key(
    AUTHOR_BOOTSTRAP_PUBKEY,
    backend=default_backend()
)
           
# ###############################################
# Implementation details
# ###############################################


class TrackingDeque(collections.deque):
    ''' Gives the deque the ability to keep track of a particular item, 
    if desired.
    '''
    def __init__(self, *args, **kwargs):
        ''' Sets the self._index and calls super.
        '''
        self.__index = None
        super().__init__(*args, **kwargs)
        
    def __update_index(self, value):
        ''' Moves the index the specified amount, ex: -1 moves it 1 
        left, 1 moves it 1 right, etc.
        '''
        if self.__index != None:
            self.__index += value
            # Don't forget to wrap around if necessary.
            self.__index %= len(self)
        else:
            raise RuntimeError('Not currently tracking an index.')
        
    def track(self, index):
        ''' Starts tracking.
        '''
        # Make sure both that it's a valid index and that the index exists
        try:
            __ = self[index]
        except TypeError:
            raise TypeError('Invalid index for tracking.')
        except IndexError:
            raise ValueError('Can\'t track an index that hasn\'t been set '
                             'yet.')
        # Okay, we're good, set it.
        self.__index = index
        
    def untrack(self):
        ''' Stops tracking. Does NOT warn if already untracked.
        '''
        self.__index = None
        
    def appendleft(self, *args, **kwargs):
        ''' Appends left, handling index.
        '''
        super().appendleft(*args, **kwargs)
        if self.position != None:
            self.__update_index(1)
        
    def clear(self, *args, **kwargs):
        super().clear(*args, **kwargs)
        self.untrack()
        
    def extendleft(self, iterable, *args, **kwargs):
        super().extendleft(iterable, *args, **kwargs)
        self.__update_index(len(iterable))
        
    def pop(self, *args, **kwargs):
        # Don't forget to shift length. If we're being popped, untrack.
        if self.position == (len(self) - 1):
            self.untrack()
        return super().pop(*args, **kwargs)
        
    def popleft(self, *args, **kwargs):
        # Check that we're not being popped
        if self.position == 0:
            self.untrack()
        elif self.position != None:
            self.__update_index(-1)
        return super().popleft(*args, **kwargs)
            
    def remove(self, value, *args, **kwargs):
        ''' Bypasses default behavior in its entirety to avoid potential
        conflicts with __delitem__ depending on cython implementation, 
        and also to avoid code rewriting.
        '''
        # Get the index we're deleting.
        index = None
        for ii in range(len(self)):
            if self[ii] == value:
                index = ii
                break
        if index == None:
            raise ValueError('deque.remove(x): x not in deque')
        
        # And go ahead and delete it using delitem.
        del self[index]
        
    def reverse(self, *args, **kwargs):
        # Don't forget to offset length.
        super().reverse(*args, **kwargs)
        if self.position != None:
            self.__update_index(len(self) - 2 * self.position - 1)
        
    def rotate(self, n, *args, **kwargs):
        super().rotate(n, *args, **kwargs)
        if self.position != None:
            self.__update_index(n)
        
    def copy(self):
        ''' Overrides default copy behavior to handle tracking.
        '''
        c = self.__class__(self)
        if self.position != None:
            c.track(self.position)
        return c
        
    def __delitem__(self, index):
        ''' Modifies normal deletion to preserve index tracking.
        If the item to track is being deleted, untracks it.
        
        Note that the default behavior of delitem only allows deleting 
        one item at a time, so we don't need to worry about the length.
        '''
        # First call super. This should catch all issues with deletion,
        # and not affect the index.
        super().__delitem__(index)
        # Now handle the possible state change.
        if index == self.position:
            self.untrack()
        # Index is less than ours. Shift left one.
        elif index < self.position:
            self.__update_index(-1)
        # Index is greater than ours, so we're unaffected.
        elif index > self.position:
            pass
        
    def __setitem__(self, index, value):
        ''' Modifies default behavior of setitem to untrack the position 
        if the tracked object just got overridden.
        '''
        # Call super first to deal with all of the error handling
        super().__setitem__(index, value)
        
        # Check if the index was ours
        if index == self.position:
            self.untrack()
        
    @property
    def position(self):
        ''' Read-only property that returns the index of the tracked
        item. If not tracking, returns None.
        '''
        return self.__index
        
    @property
    def tracked(self):
        ''' Returns the tracked object, if any. If not tracking, raises.
        '''
        if self.position != None:
            return self[self.position]
        else:
            raise RuntimeError('Not currently tracking an item.')
        
    def __repr__(self):
        ''' Appends tracking information to the default repr.
        '''
        return super().__repr__() + '; tracking: ' + str(self.position)
            

class TrackingChainMap(collections.ChainMap):
    ''' Takes the default ChainMap behavior, and makes it such that it
    modifies the zeroth mapping by default, but when a different mapping
    is tracked (TrackingChainMap.track(index)), it will only act on the
    tracked map. Search order, etc, remain unaffected, just mutation 
    methods.
    
    Also makes it cheap to do double-ended operations on the list of 
    maps (like popleft, appendleft, etc) -- but this does not affect the
    mappings themselves, only the list of them.
    '''
    def __init__(self, *maps):
        ''' Initializes with a TrackingDeque.
        '''
        super().__init__(*maps)
        self.maps = TrackingDeque(self.maps)
        
    def track(self, index):
        ''' Starts tracking.
        '''
        # Let the TrackingDeque handle all of this.
        self.maps.track(index)
        
    def untrack(self):
        ''' Stops tracking. Does NOT warn if already untracked.
        '''
        # Let the TrackingDeque handle all of this.
        self.maps.untrack()
        
    @property
    def tracked(self):
        ''' Returns a copy of the bare tracked mapping. Note: doesn't 
        create a TrackingChainMap, it just exposes the internal mapping.
        '''
        return self.maps.tracked
        
    def copy(self):
        ''' Returns a new ChainMap with all dicts copied. DOES preserve
        tracking information.
        '''
        tcm = self.__class__([mapping.copy() for mapping in self.maps])
        # Check if we're tracking, and if needed, apply the tracking
        if self.tracked != None:
            tcm.track(self.position)
        return tcm
        
    def new_child(self, m=None):
        ''' Returns a copied TrackingChainMap with a new map (m) at the
        beginning of the deque. Because of the copy, behavior may be
        subtly different from the stock collections.ChainMap behavior.
        Preserves tracking information.
        '''
        tcm = self.copy()
        tcm.maps.appendleft(m or {})
        return tcm
        
    @property
    def position(self):
        ''' Read-only property for the tracking position (None if 
        untracked.)
        '''
        return self.maps.position
        
    @property
    def parents(self):
        ''' Returns a copy of the current TrackingChainMap with the 
        first map removed. Preserves tracking information. The removed 
        map is the zeroth map, NOT necessarily the same as the tracked
        map.
        '''
        tcm = self.copy()
        del tcm.maps[0]
        return tcm
        
    def __setitem__(self, key, value):
        ''' Sets to the currently tracked mapping, or the zeroth 
        mapping (if currently untracked).
        '''
        self.maps[self.maps.position or 0][key] = value
        
    def __delitem__(self, key):
        ''' Removes the key from the currently tracked mapping, or the
        zeroth mapping (if currently untracked). This can create odd 
        situations where, for example:
        + I'm tracking maps[3] 
        + maps[0]['foo'] = 'bar'
        + maps[3]['foo'] = 'bear'
        + del self['foo']
        >>> self['foo']
        'bar'
        >>> del self['foo']
        >>> self['foo']
        'bar'        
        '''
        try:
            del self.maps[self.maps.position or 0][key]
        except KeyError:
            raise KeyError('Key not found in the tracked mapping (or, if '
                           'untracked, the zeroth mapping).')
            
    def popitem(self):
        ''' Remove and return an item pair from the appropriate mapping.
        Raise KeyError if empty.
        '''
        try:
            return self.maps[self.maps.position or 0].popitem()
        except KeyError:
            raise KeyError('No keys found in the tracked mapping (or, if '
                           'untracked, the zeroth mapping).')
            
    def pop(self, key, *args):
        ''' Remove the item pair associated with key and return its 
        value. Looks in the tracked mapping, or if untracked, looks in
        the zeroth mapping.
        '''
        try:
            return self.maps[self.maps.position or 0].pop(key, *args)
        except KeyError:
            raise KeyError('Key not found in the tracked mapping (or, if '
                           'untracked, the zeroth mapping).')
                           
    def clear(self):
        ''' Clears only the tracked mapping, or, if untracked, the 
        zeroth mapping.
        '''
        self.maps[self.maps.position or 0].clear()
        
    def __repr__(self):
        ''' Appends tracking information to the default repr.
        '''
        return super().__repr__() + '; tracking: ' + str(self.maps.position)


class SplitHashMap(collections.MutableMapping):
    ''' Creates a key: value store from a hash map using a specified 
    hash algorithm. 
    
    This seems a bit redundant, I suppose, given that python dicts *are*
    hash maps. However, the point of this class is to support more 
    complex use cases, for examples:
    1. Chain maps with reused content but different key structures
    2. Parallel key dictionaries
    3. Hash maps using secure hash functions (useful for content-based
       addressing)
    (that is actually everything I can think of at this moment).
    I'd be happy to hear of cleverer ways of doing this!
    '''
    def __init__(self, d=None, hasher=hash):
        ''' Creates a SecureHashMap, optionally from an existing dict d.
        Uses hash algorithm "hasher", which must be a callable, and 
        should take one positional argument (the object to hash) and 
        return the finalized hash. The type compatibility of the hasher
        will determine the type compatibility of the split hash map. 
        Also worth noting: there is no built-in handling of hash 
        collisions, so plan accordingly. If the splitting method 
        encounters a collision, it will raise a ValueError.
        
        This DOES support nested containers, but they must be either
        dict-like or list-like.
        
        The output of hasher *must* be usable as a dictionary key. In
        general, int is most efficient?
        '''
        # First, some error traps.
        # Ensure hasher is callable.
        if not callable(hasher):
            raise TypeError('hasher must be callable.')
        # Turn d into a dictionary so we have items()
        try:
            d = dict(d or {})
        except TypeError:
            raise TypeError('d must be dict-like.')
            
        # Call super
        super().__init__()
        # Initialize the content dict
        self._split_values = {}
        # Split the input dictionary accordingly.
        self._split_keys = self._recursive_split(d, self._split_values, hasher)
        # Add in the hasher
        self._hasher = hasher

    def __getitem__(self, key):
        ''' Returns the chained byte value, instead of simply the 
        content's hash address.
        '''
        # Get the address (or the mapping) from the key.
        address = self._split_keys[key]
        # Recombine it (note we need to use recursive join because otherwise
        # nested mappings are unsupported)
        return self._recursive_join(address, self._split_values)

    def __setitem__(self, key, value):
        ''' Overrides default chainmap behavior, separating the key: value into
        a key: hash, hash: value dictionary, to allow for more robust internal
        manifest manipulation (and robust inheritance / anteheritance).
        '''
        # Do a recursive split of any content from the value, in case it's 
        # a container.
        stripped_mapping = self._recursive_split(value, self._split_values, 
                                                 self._hasher)
        
        # That will automagically mutate the self._split_values to include the
        # stripped value.
        self._split_keys[key] = stripped_mapping

    def __delitem__(self, key):
        ''' Smarter delete mechanism that garbage collects the self.content
        dictionary in addition to deleting the key from the mapping.

        todo: consider adding a method to delete content based on the content,
        thereby removing all the keys that point to it as well.
        
        todo: this is going to have a weird effect if you delete keys 
        from nested mappings. That should probably be figured out, but
        it can't be handled here. Well, I guess the only side effect 
        would be persistence in the content dictionary. Other than that,
        it should work just fine. But it would be orphaned content.
        '''
        # Actually, uh, this is pretty easy. Delete the key or mapping from the
        # keys dict
        del self._split_keys[key]
        # And garbage collect. Note that deleting a toplevel key might delete
        # lower-level mappings, so we can't just abandon if orphan.
        self.garbage_collect()

    def __len__(self):
        ''' Returns the length of the keys.
        '''
        return len(self._split_keys)
        
    def __iter__(self):
        ''' Returns the split keys iter.
        '''
        return self._split_keys.__iter__()

    def garbage_collect(self):
        ''' Checks every address in _split_values, removing it if not 
        found.
        '''
        # Note that we need to create a separate set of keys for this to avoid
        # "dictionary changed size during iteration"
        for address in set(self._split_values):
            self._abandon_if_orphan(address)

    def clear(self):
        ''' Ensures content is also cleared when the SHM is.
        '''
        self._split_values.clear()
        self._split_keys.clear()

    def _abandon_if_orphan(self, address):
        ''' Recursively checks the mapping for the address, removing it
        from values if not found.
        '''
        # Look at every mapping in _split_keys
        if not self._recursive_check(self._split_keys, address):
            del self._split_values[address]
        
    @classmethod
    def _recursive_join(cls, mapping, content):
        ''' Inspects every key: value pair in mapping, and then replaces
        any hash with its content. If the value is a container, 
        recurses.
        '''
        # Create a new instance of the mapping to copy things to.
        if isinstance(mapping, collections.Mapping):
            joined = mapping.__class__()
            for key, value in mapping.items():
                joined[key] = cls._recursive_join(value, content)
        elif isinstance(mapping, collections.MutableSequence):
            joined = mapping.__class__()
            for value in mapping:
                joined.append(cls._recursive_join(value, content))
        # Not a container. Process the value.
        else:
            # In this case, mapping is actually an address.
            joined = content[mapping]
            
        return joined

    @classmethod
    def _recursive_split(cls, mapping, content, hasher):
        ''' Inspects every key: value pair in mapping, and then replaces
        any content with its hash. If the value is a container, 
        recurses.
        
        Returns the stripped mapping.
        '''
        # Create a new instance of the mapping to copy things to.
        if isinstance(mapping, collections.Mapping):
            stripped = mapping.__class__()
            for key, value in mapping.items():
                stripped[key] = cls._recursive_split(value, content, hasher)
        elif isinstance(mapping, collections.MutableSequence):
            stripped = mapping.__class__()
            for value in mapping:
                stripped.append(cls._recursive_split(value, content, hasher))
        # Not a container. Process the value.
        else:
            # Let's split this shit. Get the has/address
            stripped = hasher(mapping)
            # Add it to external (outside of recursion) content if needed.
            if stripped not in content:
                content[stripped] = mapping
            # Ensure non-collision, and if collision, error.
            elif content[stripped] != mapping:
                raise ValueError('Hash collision. Sorry, not currently '
                                 'handled. Choose a different hash function, '
                                 'a different value, or implement a custom '
                                 'subclass with proper collision handling.')
                
        # And return whatever we did.
        return stripped
        
    @classmethod
    def _recursive_check(cls, mapping, address):
        ''' Inspects every key: value pair in mapping, and looks to see
        if any of the mappings point to the address. If the mapping is
        a container, recurses.
        
        A note on design decisions:
        Significant issues were encountered trying to implement this 
        class in a properly duck-typed way. The problem is that non-
        container iterable types like bytes and strings present huge
        challenges. In order to accomodate as many container types
        as possible, whilst simultaneously allowing for arbitrary
        content, I decided to limit the container types to those that
        are detected as either collections.Mapping or
        collections.MutableSequence. That means tuples will be ignored.
        
        Also, readability counts.
        '''
        found = False
        # In for a penny, in for a pound.
        if isinstance(mapping, collections.Mapping):
            for value in mapping.values():
                found |= cls._recursive_check(value, address)
        elif isinstance(mapping, collections.MutableSequence):
            for value in mapping:
                found |= cls._recursive_check(value, address)
        else:
            found |= (mapping == address)
        # Return.
        return found


def _pack_version(s):
    ''' Generates the appropriate 32-bit field for the version, given 
    the input string s. Input should be formatted as "1.2.3", as defined 
    in the EIC spec. Returns bytes.
    '''
    # How many bits for each field?
    major_size = 8
    minor_size = 8
    patch_size = 16

    # Convert the string into a series of integers
    major, minor, patch = [int(ss) for ss in s.split('.')]

    # Error traps:
    if major >= 2^major_size:
        raise ValueError('Major version too large.')
    if minor >= 2^minor_size:
        raise ValueError('Minor version too large.')
    if patch >= 2^patch_size:
        raise ValueError('Patch version too large.')

    # Perform some bitwise operations to move them around
    # Don't need to shift cipher
    minor = minor << patch_size
    major = major << (patch_size + minor_size)
    packed_int = patch | minor | major

    # Pack it into 32 bits and return
    return struct.pack('>I', packed_int)


def _unpack_version(bites):
    ''' Unpacks the version binary representation into a string formatted as 
    "1.2.3:A", as defined in the EIC.
    '''
    raise NotImplementedError('Sorry, haven\'t gotten around to this yet.')


# ###############################################
# Storage, access, and identity layers
# ###############################################


class StorageProvider(metaclass=abc.ABCMeta):
    ''' An abstract base class for storage providers for .eic files.

    At some point in the far distant future this functionality may be defined
    within a proper protocol spec, as an alternative to http/https. That, 
    however, is a very long way off.
    '''
    # Note: should add a "trusted peers" attribute for verification methods 
    # that need to look around for a pubkey

    @abc.abstractmethod
    def ping(self, address):
        ''' Queries the storage provider about whether it has a copy of the 
        address. Address may be either an euid or a dynamic reference.

        returns:
        b'd' if dynamic
        b's' if static
        False if not found
        '''
        pass

    @abc.abstractmethod
    def upload(self, bites):
        ''' Pushes an eic file to the storage provider. If unsuccessful, raise
        an error. If successful, returns the EUID (by convention, out of 
        convenience.)
        '''
        pass

    @abc.abstractmethod
    def download(self, euid):
        ''' Gets an eic file from the storage provider. If the provider was 
        successfully reached, but does not have the object, return None. If 
        the provider was not successfully reached, throw an error.
        '''
        pass

    @abc.abstractmethod
    def list_frames(self, dynamic_ref):
        ''' Returns a list of the full EUIDs associated with a specified EICd
        header hash, in "chronological" order from most recent frame [0] to 
        oldest frame [n].
        '''
        pass

    @staticmethod
    def ping_multi(euid, storage_providers):
        ''' Rather stupidly iterates through storage providers, pinging each
        one until one responds that the address (euid or dynamic ref) is found.

        Returns true if found and false if not.
        '''
        # Stupid first-come-first-serve
        for storage_provider in storage_providers:
            status = storage_provider.ping(euid)
            if status:
                return status

        # 404: your princess is in another castle
        return False

    @staticmethod
    def poll_euid(euid, storage_providers):
        ''' Requests the euid from the storage providers and returns the bites
        received. If no storage provider has the file, raises an error.
        '''
        # Dead simple first-come-first-serve at the moment
        # providers for an euid
        for storage_provider in storage_providers:
            bites = storage_provider.download(euid)
            if bites:
                return bites

        raise RuntimeError('Failed to find the given euid at any of the '
                           'given storage providers.')

    @staticmethod
    def poll_frames(reference, storage_providers):
        ''' Requests the dynamic reference from the storage providers and 
        returns the "best" record received. This does **not** return bytes; it
        produces an ordered list (from most recent to oldest) of the euids of
        the frames in the dynamic buffer.
        '''
        # Dead simple first-come-first-serve ATM
        for storage_provider in storage_providers:
            framelist = storage_provider.list_frames(reference)
            if framelist:
                return framelist

        raise RuntimeError('Failed to find the given dynamic reference at any '
                           'of the given storage providers.')

    @staticmethod
    def distribute(bites, storage_providers, euid=None):
        ''' Uploads the bytes object to the storage providers, optionally 
        verifying their success with the provied euid.
        '''
        for storage_provider in storage_providers:
            status = storage_provider.upload(bites)
            # Check that the euids match
            if euid and status != euid:
                raise RuntimeError('Unsuccessful upload. EUID verification '
                                   'mismatch.')


class AccessProvider(metaclass=abc.ABCMeta):
    ''' An abstract base class for something that returns symmetric keys 
    for specified euids.
    
    private accessproviders, public accessproviders, etc
    
    Should this also handle anteheritance?
    '''
    def __init__(self, identity_provider):
        ''' Need private key for decrypting stuff. Do also need author 
        euid? Storage providers are for looking up the eicas.
        
        Multiple identity providers?
        
        This will be overridden without identity_provider for the public
        identity access provider.
        '''
        pass
    
    @abc.abstractmethod
    def request(self, euid):
        ''' Request a symmetric key for an euid.
        '''
        pass
    
    @abc.abstractmethod
    def grant(self, symkey, recipient):
        ''' Creates an access record with symkey for recipient.
        '''
        pass
    
    
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
    def fetch_pubkey(self, euid):
        ''' Returns the pubkey associated with the given euid.
        '''
        pass
        
    @abc.abstractmethod
    def new_identity(self, pubkey):
        ''' Creates an identity from the pubkey, returning the euid.
        '''
        pass
    

class Agent():
    ''' Agents have private keys, as well as preferred storage providers
    and access providers.
    
    Agents keep track of what's been shared with them as well, and they
    handle anteheritance (make decisions, apply, etc).
    '''
    pass
    
    
# ###############################################
# EIC files
# ###############################################


class EICBase(metaclass=abc.ABCMeta):
    ''' Abstract base class for all EIC objects. Contains requirements 
    for common methods, as well as some universal definitions like 
    _unpack_public.
    '''
    BACKEND = cryptography.hazmat.backends.default_backend()
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Check the key_resolver
        # if not isinstance(key_resolver, IdentityProvider):
            # raise ValueError('Key resolver must be an identity provider.')
        # self.key_resolver = key_resolver
    
    @classmethod
    def _unpack_public(cls, bites):
        ''' Extracts the public parts of the EICd from a bytes object.

        Returns a dictionary of the stripped objects.
        '''
        # Preinitialize output dict
        delivery = {}
        # Parse that shit
        for key, address in cls.header_bits.items():
            delivery[key] = bites[address]

        return delivery

    @staticmethod
    @abc.abstractmethod
    def verify_signature(bites, pubkey, signature):
        ''' Verifies an author's signature against bites. Errors out if 
        unsuccessful. Returns True if successful.
        '''
        # This bit needs to be actually implemented.
        # return rsa2048verify(bites, pubkey, signature)
        verifier = pubkey.verifier(
            signature,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
        verifier.update(bites)
        verifier.verify()
        
        # Success!
        return True

    @staticmethod
    def _hash(bites):
        ''' Man, this bites.'''
        # Create the hash. This may move to cryptography.io in the future.
        h = hashlib.sha512()
        # Give it the bytes
        h.update(bites)

        # Finalize that shit and return
        return h.digest()

    @staticmethod
    def _sign(bites, key):
        ''' Placeholder signing method.

        '''
        signer = key.signer(
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
        signer.update(bites)
        signature = signer.finalize()
        del signer, key, bites
        
        return signature

    @staticmethod
    def check_euid(euid, fatal=True):
        ''' Checks that the object forms a valid EUID. If desired, can also 
        check for corresponding objects at the specified StorageProviders.

        Returns True if everything checks out. Otherwise, either:
        1. returns False if fatal=False
        2. raises RuntimeError if fatal=True
        '''
        if not isinstance(euid, bytes) or len(euid) != 64:
            # It needs to be a bytes object of length 64.
            if fatal:
                raise RuntimeError('EUID check failed, is this actually an '
                                   'EUID?')
            else:
                return False

        # No problems? return True
        return True

    @staticmethod
    def check_symkey(sym_key):
        ''' Checks a symmetric key for validity. Returns True if valid, errors 
        out if invalid. Also checks strength, integrity, etc? Well it might at 
        some point, anyways.
        '''
        if not isinstance(sym_key, bytes) or len(sym_key) != 32:
            raise RuntimeError('Does not appear to be a valid symmetric key.')
        else:
            return True

    @classmethod
    @abc.abstractmethod
    def verify_public(cls, bites, *args, **kwargs):
        ''' Verifies the public parts of an EIC as best as possible. Returns 
        a dictionary of the public parts of the object if successful, 
        including the euid.
        '''
        # Unload everything
        unloaded = cls._unpack_public(bites)

        # Check the magic
        if bites[cls.header_bits['magic']] != cls.magic:
            raise RuntimeError('Mismatched magic numbers while loading.')
        # Check the version
        if bites[cls.header_bits['version']] != cls.version:
            raise RuntimeError('Mismatched EIC versions while loading.')

        # Verify the file hash
        if unloaded['file_hash'] != cls._hash(bites[cls.file_hash_bytes]):
            raise RuntimeError('Mismatched hashes, check EIC integrity.')

        return unloaded

    @abc.abstractmethod
    def push(self, sig_key, storage_providers):
        ''' Assembles the .EICa file, signs it, and pushes it to all of the 
        listed storage providers.
        '''
        pass

    @classmethod
    @abc.abstractmethod
    def fetch(cls, euid, key, storage_providers):
        ''' Factory classmethod to produce an EIC object from the listed
        storage providers.

        fetch()
        =====================================================================

        Arguments
        ----------

        euid:               The object to load                      bytes
        key:                The decryption key.                     bytes
        storage_providers   A list of StorageProvider objects       []

        Returns
        ----------

        Unlocked and verified EIC object
        '''        
        # Okay, so we have a single euid for a single file. Get it.
        bites = StorageProvider.poll_euid(euid, storage_providers)

        # Load the public parts and verify them thus far
        unpacked_public = cls.verify_public(bites, euid=euid)

        # Unlock and unpack the payload
        payload = cls._unlock_payload(unpacked_public['payload'], key)
        unpacked_payload = cls._unpack_payload(payload)

        return unpacked_public, unpacked_payload

    @classmethod
    def _unpack_payload(cls, payload):
        ''' Boilerplate to unpack an unlocked payload.
        '''
        unpacked = {}
        for key, value in cls.payload_bits.items():
            unpacked[key] = payload[value]

        # Return the parts!
        return unpacked

    @classmethod
    def _lock_payload(cls, payload, sym_key):
        ''' Performs symmetric encryption of the supplied payload using the 
        supplied symmetric key.
        '''
        #self.check_symkey(sym_key)
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(sym_key), modes.CTR(nonce), 
                        backend=cls.BACKEND)
        del sym_key
        encryptor = cipher.encryptor()
        # Note that update returns value immediately, but finalize should (at 
        # least in CTR mode) return nothing.
        ct = encryptor.update(payload) + encryptor.finalize()
        # Don't forget to prepend the nonce
        payload = nonce + ct
        # Delete these guys for some reassurrance
        del cipher, encryptor, nonce, ct
        return payload

    @classmethod
    def _unlock_payload(cls, payload, sym_key):
        ''' Performs symmetric decryption of the supplied payload using the 
        supplied symmetric key.

        Currently just a placeholder.
        '''
        nonce = payload[0:16]
        payload = payload[16:]
        cipher = Cipher(algorithms.AES(sym_key), modes.CTR(nonce), 
                        backend=cls.BACKEND)
        del sym_key
        decryptor = cipher.decryptor()
        payload = decryptor.update(payload) + decryptor.finalize()
        del decryptor, cipher, nonce
        return payload


class EICa(EICBase):
    ''' Generates an asymmetric .eic file for a key, target, author 
    combination.

    This may need serious refactoring; it was the first of the EIC_ classes I
    wrote and the module's internal structure has changed significantly since
    then.
    '''
    magic = b'eica'
    version_str = '0.0.5'
    version = _pack_version(version_str)
    # 616 bytes for the header, 512 bytes for the payload
    final_size = 1164
    file_hash_bytes = slice(584, None)

    header_bits = {}
    header_bits['magic'] = slice(0, 4)
    header_bits['cipher'] = slice(4, 8)
    header_bits['signature'] = slice(8, 520)
    header_bits['file_hash'] = slice(520, 584)
    header_bits['version'] = slice(584, 588)
    header_bits['recipient'] = slice(588, 652)
    header_bits['payload'] = slice(652, None)

    payload_bits = {}
    payload_bits['inner_hash'] = slice(0, 64)
    payload_bits['author'] = slice(64, 128)
    payload_bits['target'] = slice(128, 192)
    payload_bits['class'] = slice(192, 256)
    payload_bits['key'] = slice(256, 288)

    def __init__(self, recipient, target, author, sym_key, net_class=None,
        inner_hash=None, 
        signature=None, 
        file_hash=None, 
        euid=None):
        ''' Creates an EICa object.

        __init__()
        =====================================================================

        Arguments
        ---------

        target:     the associated EICs eUID                        bytes
        recipient:  the euid of the person to share with            bytes
        author:     the eUID of the person creating the EICa        bytes
        sym_key:    the symmetric key of the EICs                   bytes

        Returns
        --------

        The object, as expected
        '''
        # Don't forget to call super()!
        super().__init__()

        # Predeclare self._signature for State control
        # Is this redundant with below?
        self._signature = None

        # Verify and assign recipient
        self.check_euid(recipient)
        self.recipient = recipient

        # Verify and assign target
        self.check_euid(target)
        self.target = target
        # Verify and assign author. Since the signing key is always directly
        # passed, we don't need it here.
        self.check_euid(author)
        self.author = author
        # Verify and assign key
        self.check_symkey(sym_key)
        self.sym_key = sym_key

        # Class is optional, though highly recommended. If undefined, fill it
        # with zeros.
        if not net_class:
            net_class = bytes(64)
        self.net_class = net_class

        # These bits should only be used during init when loading an existing
        # eica.
        self._inner_hash = inner_hash
        self._signature = signature
        self._file_hash = file_hash
        self.euid = euid

    def push(self, sig_key, storage_providers):
        ''' Assembles the .EICa file, signs it, and pushes it to all of the 
        listed storage providers.
        '''
        # Warning trap if it's already been built
        if self._signature:
            warn(RuntimeWarning('You\'re building an already-signed EICa. '
                                'This will overwrite the parsed file in '
                                'memory, and likely error out.'))

        # Don't need to do further error checking, since __init__ already did.

        # We do, however, need to get the pubkey from the storage_proviers
        pubkey = EICs.fetch(self.recipient, AUTHOR_BOOTSTRAP_SYMKEY, 
                            storage_providers)[b'pubkey']
        pubkey = serialization.load_pem_public_key(pubkey, 
                                                   backend=self.BACKEND)

        # Preinitialize build_array. Note that this only works because the
        # final EICa size is determined by the spec.
        build_array = bytearray(self.__class__.final_size)
        # Grab the class definitions
        build_map = self.__class__.header_bits

        # Build the payload
        pkg = self.author + self.target + self.net_class + self.sym_key
        self._inner_hash = self._hash(pkg)
        pkg = self._inner_hash + pkg 
        # Encrypt the payload and delete the pkg
        payload = self._lock_payload(pkg, pubkey)
        del pkg

        # Assemble everything else needed for hashing
        build_array[build_map['version']] = self.__class__.version 
        build_array[build_map['recipient']] = self.recipient
        build_array[build_map['payload']] = payload

        # Hash the prebuilt bit for the file hash, concatenate with payload
        # hash for the euid. Note that conversion to bytes must be explicit
        self._file_hash = self._hash(bytes(
            build_array[self.__class__.file_hash_bytes]))
        self.euid = self._file_hash

        # Get the signature
        self.signature = \
            self._sign(self._file_hash + self._inner_hash, sig_key)

        # # Verify self before continuing
        # if not _verify(self._file_hash + self._inner_hash, 
        #     self.author.pubkey, self.signature):
        #         raise RuntimeError('Loaded eica failed verification. Try '
        #             'again, check your bytes, or check your object source.')
        # For extra caution, delete the key now that we're done with it
        del sig_key

        # We've signed and verified the completed eic. Finish the build
        build_array[build_map['magic']] = self.__class__.magic
        build_array[build_map['signature']] = self.signature
        build_array[build_map['file_hash']] = self._file_hash
        built = bytes(build_array)

        # Send it to every storage provider.
        StorageProvider.distribute(built, storage_providers, euid=self.euid)

        # If successful, return the EUID (note that in this case, all of
        # them should match).
        return self.euid

    @classmethod
    def verify_public(cls, bites, euid=None):
        ''' Verifies the public parts of an EICa as best as possible. 
        If successful, returns:
            euid, recipient euid, signature, file hash, encrypted payload,
            payload hash
        '''
        # Check the length first
        if len(bites) != cls.final_size:
            raise RuntimeError('EICa file of improper length.')

        # Call super to unload and verify magic number and version
        unloaded = super().verify_public(bites)

        # Get the payload hash
        payload_hash = cls._hash(unloaded['payload'])

        # Verify the euid or construct it if not given
        if euid:
            if euid != unloaded['file_hash']:
                raise RuntimeError('EUID doesn\'t match contents, check EICa '
                                   'integrity.')
        # No euid supplied; we'll want it later.
        else:
            euid = unloaded['file_hash']
        # Regardless, add it to the return
        unloaded['euid'] = euid

        # We've gotten to the end. Return everything.
        return unloaded

    def verify_signature(self, storage_providers):
        ''' Convenience wrapper for ABC signature verification, to give it the
        appropriate bytes.
        '''
        # Error trap if missing definitions
        if not (self._file_hash and self._inner_hash):
            raise RuntimeError('Cannot verify EICa signature without first '
                               'unlocking the container.')

        # EICa signatures are constructed thusly...
        bites = self._file_hash + self._inner_hash
        # Get pubkey from the storage providers
        pubkey = EICs.fetch(self.author, AUTHOR_BOOTSTRAP_SYMKEY, 
                            storage_providers)[b'pubkey']
        pubkey = serialization.load_pem_public_key(pubkey, 
                                                   backend=self.BACKEND)

        return super().verify_signature(bites, pubkey, self._signature)

    @classmethod
    def fetch(cls, euid, prv_key, storage_providers):
        ''' Factory classmethod to produce an EICa object from the listed
        storage providers.

        fetch()
        =====================================================================

        Arguments
        ----------

        bites:              The bytes object to load                bytes
        prv_key:            The decryption key.                     bytes
        storage_providers   A list of StorageProvider objects       []

        Returns
        ----------

        tuple:      (EICa object, stripped payload to verify)
        '''
        unpacked_public, unpacked_payload = super().fetch(euid, prv_key, 
                                                          storage_providers)
        
        # Build the eica
        eica = cls(unpacked_public['recipient'], unpacked_payload['target'], 
                   unpacked_payload['author'], unpacked_payload['key'], 
                   net_class=unpacked_payload['class'],
                   inner_hash=unpacked_payload['inner_hash'],
                   signature=unpacked_public['signature'],
                   file_hash=unpacked_public['file_hash'],
                   euid=euid)

        # For a bit of added reassurance, delete stuff explicitly right meow
        del prv_key

        # Finally, verify the signature (we could not do this before, as it 
        # requires unlocking and unpacking the payload)
        eica.verify_signature(storage_providers)

        # finally, return the eica
        return eica

    @staticmethod
    def _unlock_payload(bites, prv_key):
        ''' Implements the EICa standard to unencrypt the payload, then 
        immediately deletes the key.
        '''
        cipher = PKCS1_OAEP.new(prv_key, hashAlgo=SHA512)
        del prv_key
        return cipher.decrypt(bites)

    @staticmethod
    def _lock_payload(payload, pubkey):
        # Okay, super hacktastic right now.
        pem = pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pubkey = RSA.importKey(pem)
        cipher = PKCS1_OAEP.new(pubkey, hashAlgo=SHA512)
        del pubkey
        return cipher.encrypt(payload)

class EICd(EICBase):
    ''' A dynamic eic file.

    Todo: refactor "content" deque to be left-handed (access is mostly LIFO)
    Todo: think about whether or not this should contain a self.sym_key or an
    internal HMAC to verify key consistency
    '''
    magic = b'eicd'
    version_str = '0.0.4'
    version = _pack_version(version_str)
    header_size = 856
    file_hash_bytes = slice(584, None)
    header_hash_bytes = slice(648, 652), slice(728, 856)

    header_bits = {}
    header_bits['magic'] = slice(0, 4)
    header_bits['cipher'] = slice(4, 8)
    header_bits['signature'] = slice(8, 520)
    header_bits['file_hash'] = slice(520, 584)
    header_bits['header_hash'] = slice(584, 648)
    header_bits['version'] = slice(648, 652)
    header_bits['buffer_req'] = slice(652, 656)
    header_bits['previous_hash'] = slice(656, 720)
    header_bits['payload_length'] = slice(720, 728)
    header_bits['author'] = slice(728, 792)
    header_bits['zeroth_hash'] = slice(792, 856)
    header_bits['payload'] = slice(header_size, None)

    def __init__(self, author, buffer_req, content=None, history=None, 
        euid=None, dynamic_ref=None, zeroth_hash=None, signature=None):
        ''' Creates an EICd object.

        __init__()
        =====================================================================

        Arguments
        ---------

        author:             the associated author's eUID                bytes
        buffer_req:         the requested number of buffer frames       int

        content:            Content.                                    bytes
        history:            ordered iterable containing previous        [{}]
                            frames' file hashes, previous hashes,
                            and content.
        euid:               the most current euid                       bytes
        dynamic_ref:    as defined by the EICd spec                 bytes
        zeroth_hash:        the payload hash of the first frame         bytes

        Returns
        --------

        The object, as usual

        '''
        # Don't forget to call super()!
        super().__init__()


        # Predeclare self._signature for state control
        self._signature = signature

        # Verify and assign author. Since the signing key is always directly
        # passed, we don't need it here.
        self.check_euid(author)
        self.author = author

        # Verify size of buffer_req based on max size and then set
        if buffer_req < 0 or buffer_req > 2^32 - 1:
            raise RuntimeError('Buffer request is out of bounds.')
        self.buffer_req = buffer_req

        # Error trap for dynamic ref, then assign it (if undefined = None)
        if dynamic_ref:
            self.check_reference(dynamic_ref)
        self.dynamic_ref = dynamic_ref

        # These will be supplied for either 1. loading an existing EICd, or 2. 
        # creating a new revision of an existing EICd. If not supplied, will be
        # defaulted to None
        self.zeroth_hash = zeroth_hash

        # Check and assign history
        if not history:
            # Create history, inserting an empty dictionary as the first item
            self.history = collections.deque(maxlen=buffer_req)
            # Note that a content of None will be automatically converted to
            # an empty bytes object.
            self.content = content
        # History is defined. Check if it's properly formed.
        elif isinstance(history, collections.Iterable):
            # Immediately make sure the ref and zeroth hash are defined
            # Todo: think about this, since dynamic_ref can be constructed
            # from the zeroth hash.
            if not (dynamic_ref and zeroth_hash):
                raise RuntimeError('An EICd file with an existing history '
                                   'must be constructed with a dynamic '
                                   'referece and zeroth hash.')
            # Grab the most recent frame
            recent_frame = history[len(history) - 1]
            # Try assigning attributes from the most recent frame
            try:
                recent_hash = recent_frame['file_hash']
                previous_hash = recent_frame['previous_hash']
                # todo: at some point, add some verification of the correct
                # construction of the history beyond just the most recent frame
                self.history = collections.deque(history, maxlen=buffer_req)
            # Catch errors associated with bad historical records
            except (KeyError, TypeError):
                raise RuntimeError('Content is an iterable, but it lacks the '
                                   'proper keys.')
                
            # Okay, now if it's defined we should check the euid
            if euid:
                if euid != recent_hash:
                    # euid should be identical to the file hash + reference
                    raise RuntimeError('euid does not match history.')
            # If it isn't defined, define it
            else:
                euid = recent_hash

            # Verify the zeroth hash and adress
            verify_header = self.__class__.version + author + zeroth_hash
            if self._hash(verify_header) != dynamic_ref:
                raise RuntimeError('The provided reference does not match the '
                                   'author and zeroth hash.')
        # We'll only get here if history was malformed.
        else:
            raise RuntimeError('Malformed history.')

    def commit(self, sym_key, sig_key):
        ''' 
        Finalizes the value in self.content, pre-building the file, but
        not signing it.

        DANGER: if you commit without pushing to a storage provider, previous
        versions will be lost if the number of commits exceeds the buffer! 
        This is super danger zone territory!
        '''
        # First things first: we need to encrypt the payload before we can
        # generate a file hash.
        locked_content = self._lock_payload(self.content, sym_key)
        del sym_key
        # Get the payload length
        payload_length = len(locked_content)
        # Now create a mutable bytearray for constructing the frame
        packed = bytearray(self.__class__.header_size + payload_length)
        # And get the EICd map
        bit_map = self.__class__.header_bits

        # First verify that we have a dynamic reference. If not, it's a new 
        # EICd and we need to create one.
        if not self.zeroth_hash:
            self.zeroth_hash = self._hash(locked_content)
        # And set it in the bytearray while we're at it.
        packed[bit_map['zeroth_hash']] = self.zeroth_hash

        # Add in the author and version
        packed[bit_map['author']] = self.author
        packed[bit_map['version']] = self.__class__.version

        # Check for the dynamic reference and then set it in the output
        # Usually a missing zeroth will also always result in a missing header
        # hash, but treat them as separate for the time being.
        if not self.dynamic_ref:
            to_hash = bytes()
            for component in self.header_hash_bytes:
                to_hash += packed[component]
            self.dynamic_ref = self._hash(to_hash)
        packed[bit_map['header_hash']] = self.dynamic_ref

        # Similarly, check to see if we don't have a previous hash, and then 
        # copy over the header_hash
        if not self._previous_hash:
            self.history[self._index]['previous_hash'] = self.dynamic_ref

        # Finish loading the wagon
        packed[bit_map['magic']] = self.__class__.magic
        packed[bit_map['buffer_req']] = struct.pack('>I', self.buffer_req)
        packed[bit_map['previous_hash']] = self._previous_hash
        packed[bit_map['payload_length']] = struct.pack('>Q', payload_length)
        packed[bit_map['payload']] = locked_content

        # Build the file hash, load it into self.history, and pack it in
        file_hash = self._hash(bytes(packed[self.__class__.file_hash_bytes]))
        self.history[self._index]['file_hash'] = file_hash
        packed[bit_map['file_hash']] = file_hash

        # Get the file hash, generate a signature, and finalize the file
        euid = file_hash
        packed[bit_map['signature']] = self._sign(euid, sig_key)
        del sig_key
        self.history[self._index]['built'] = bytes(packed)
        self.history[self._index]['euid'] = euid

    @classmethod
    def _unpack_public(cls, bites):
        ''' Do some post-processing of the unloaded public values.
        '''
        raw = super()._unpack_public(bites)

        # Unpack numeric values
        raw['buffer_req'] = struct.unpack('>I', raw['buffer_req'])[0]
        raw['payload_length'] = struct.unpack('>Q', raw['payload_length'])[0]

        # Return
        return raw

    @classmethod
    def verify_public(cls, bites, euid=None):
        ''' Verifies the public parts of an EICd as best as possible.
        '''
        unloaded = super().verify_public(bites)

        # Check the length
        if len(unloaded['payload']) != unloaded['payload_length']:
            raise RuntimeError('Payload length doesn\'t match payload.')

        # Verify the header hash
        to_hash = bytes()
        for component in cls.header_hash_bytes:
            to_hash += bites[component]
        if unloaded['header_hash'] != cls._hash(to_hash):
            raise RuntimeError('Mismatched header hash. This doesn\'t appear '
                'to be the correct dynamic file.')

        # Verify the euid or construct it if not given
        if euid:
            if euid != unloaded['file_hash']:
                raise RuntimeError('EUID doesn\'t match contents, check EIC '
                    'integrity.')
        # No euid supplied; we'll want it later.
        else:
            euid = unloaded['file_hash']
        # Regardless, add the euid to the unloaded bit
        unloaded['euid'] = euid

        # We've gotten to the end. Return everything.
        return unloaded

    def verify_signature(self, storage_providers):
        ''' The necessary / convenient wrapper for ABC signature verification, 
        to give it the appropriate bytes.

        Are we, in fact, assured that verifying ONLY the most recent signature
        does, in fact, ensure the veracity of the entire chain?
        '''
        # Get pubkey from the storage providers
        pubkey = EICs.fetch(self.author, AUTHOR_BOOTSTRAP_SYMKEY, 
                            storage_providers)[b'pubkey']
        pubkey = serialization.load_pem_public_key(pubkey, 
                                                   backend=self.BACKEND)

        return super().verify_signature(self.euid, pubkey, self._signature)
        # Don't need to verify each frame, as they are all uploaded separately.

    @classmethod
    def fetch(cls, address, sym_key, storage_providers, parse_history=False):
        ''' Factory classmethod to produce an EICd object from the listed
        storage providers.

        fetch()
        =====================================================================

        Arguments
        ----------

        address:            An euid or a dynamic reference          bytes
        sym_key:            The decryption key.                     bytes
        storage_providers:  A list of StorageProvider objects       []
        history:            Controls whether the entire object      bool
                            history is loaded (True), or just the
                            most recent frame (False).

        Returns
        ----------

        tuple:      (EICa object, stripped payload to verify)
        '''
        # First we need to figure out if "address" is an euid or a dynamic ref
        # Both euids and references look the same
        cls.check_euid(address)
        status = StorageProvider.ping_multi(address, storage_providers)
        # Dynamic reference?
        if status == b'd':
            # Load the most recent euids.
            dynamic_ref = address
            euids = StorageProvider.poll_frames(address, storage_providers)
        # Not a dynamic reference. Euid?
        elif status == b's':
            # Use it as the euid.
            euids = [address]

            # Except first raise an error if it wants the history because we 
            # aren't there yet.
            if parse_history:   
                raise NotImplementedError('Can\'t yet fetch the history for a '
                                          'specific euid.')
        # Anything else?
        else:
            # That's a problem.
            raise RuntimeError('Unable to find the euid at the listed '
                               'storage providers.')

        # If we're not getting the entire history, get rid of everything else
        # to save a bit of time.
        if not parse_history:
            euids = [euids[0]]

        # Predeclare history
        history = []
        # Use super to get, well, pretty much everything
        for euid in euids:
            unpacked_public, unpacked_payload = \
                super().fetch(euid, sym_key, storage_providers)
            history.append({'content': unpacked_payload, 
                    'file_hash': unpacked_public['file_hash'],
                    'previous_hash': unpacked_public['previous_hash']})

        # Construct the object.
        eicd = cls(unpacked_public['author'], 
                   unpacked_public['buffer_req'], history=history,
                   euid=euid, dynamic_ref=unpacked_public['header_hash'], 
                   zeroth_hash=unpacked_public['zeroth_hash'],
                   signature=unpacked_public['signature'])

        # For a bit of added reassurance, delete stuff explicitly right meow
        del sym_key, unpacked_public, unpacked_payload

        # Verify the signature
        eicd.verify_signature(storage_providers)
        # finally, return the eica
        return eicd

    def push(self, storage_providers):
        ''' Brings all storage providers up-to-date with the EICd object, 
        uploading any missing frames.
        '''
        # Poll providers for each of the EICd references. Upload all missing 
        # revisions contained in the buffer.
        for frame in self.history:
            # Only do anything if we've personally built the frame
            try:
                euid = frame['euid']
                built = frame['built']

                # Send it to every storage provider.
                StorageProvider.distribute(built, storage_providers, 
                                           euid=euid)
            # If either euid or built are missing, skip it and move ahead.
            except KeyError:
                continue

        # Don't forget to return the euid as verification
        # Todo: think about this, since it's a crazy awkward verification
        return euid

    @staticmethod
    def check_reference(dynamic_ref, fatal=True):
        ''' Tests validity of a dynamic reference. Returns True if it appears 
        valid. If it appears invalid, it will either
        1. raise RuntimeError if fatal=True
        2. return False if fatal=False
        '''
        # Check that it is a bytes object or descendant and has len()==32
        if (isinstance(dynamic_ref, bytes) and len(dynamic_ref) == 64):
            return True
        else:
            if fatal:
                raise RuntimeError('Dynamic address does not appear to be a '
                                   'valid dynamic reference.')
            else:
                return False

    def terminate(self, sig_key, storage_providers):
        ''' Generates a "close" operation and circulates it to the storage 
        providers.
        '''
        raise NotImplementedError('Haven\'t gotten around to this yet...')
        self.history = collections.deque(maxlen=1)
        self.push(sig_key, storage_providers)
        del sig_key

    @classmethod
    def _unpack_payload(cls, bites, *args, **kwargs):
        ''' Overrides everything about the stock unpack payload, since by EICd
        definition, the payload needs no unpacking.
        '''
        return bites

    @property
    def _index(self):
        ''' Read-only property that returns the index of the most recent bufer
        frame.
        '''
        return len(self.history) - 1

    @property
    def content(self):
        ''' Getter for self.content.
        Accesses the most recent line in the history dictionary. If the frame 
        exists, but content is None, returns an empty bytes object. If no frame
        has been defined (should be impossible), raises an error.
        '''
        # First, error trap for the impossible
        if self._index < 0:
            raise RuntimeError('You\'ve somehow reached an "impossible" state '
                               'where you have access to the content property '
                               'before the EICd object has been initialized.')
        # Try to grab the appropriate key
        try:
            c = self.history[self._index]['content']
        # Again, this shouldn't be possible (currently), but catch it just in
        # case, and treat it like empty content.
        except KeyError:
            c = None

        # If, for whatever reason, c tests to False, return empty bytes
        if not c:
            c = bytes()

        return c

    @content.setter
    def content(self, c):
        ''' Looks at the current state of the dynamic object (new, updated, or
        committed) and assigns content accordingly.
        '''
        # First, check if the content input is not empty:
        if c and not isinstance(c, bytes):
            raise TypeError('Content must be bytes, or empty.')
        elif not c:
            c = bytes()

        # If history is empty, we need to create it.
        if self._index < 0:
            self.history.append({'content': c})
        # If it isn't empty, but the last frame is already committed
        elif self._file_hash:
            self.history.append({'content': c, 
                                 'previous_hash': self._file_hash})
        # History is not empty, and the last frame has not been committed.
        else:
            self.history[self._index]['content'] = c

    @property
    def _file_hash(self):
        ''' Read only property that references the most recent file hash.
        '''
        try:
            return self.history[self._index]['file_hash']
        except KeyError:
            return None

    @property
    def _previous_hash(self):
        ''' Read-only property corresponding to most recent previous hash.
        '''
        try:
            return self.history[self._index]['previous_hash']
        except KeyError:
            return None

    @property
    def euid(self):
        ''' Read-only property for the most recent euid.
        '''
        # Make sure we actually have one
        if self._file_hash:
            return self._file_hash
        else:
            # No? Okay, error
            raise RuntimeError('EICd must have at least one commit to have an '
                               'euid or dynamic reference address.')


class EICs(EICBase, SplitHashMap):
    ''' Represents a static .eic file.

    todo: need to use the internal Mapping class for the individual 
    maps, since just a dict doesn't give me a good enough description of
    what's going on with heritage (and which mapping corresponds to the 
    active one).

    todo: probably get rid of the chainmap base class; this is just 
    specialized enough to warrant it in the future (for example, pop and
    clear behave in an unexpected way).

    See https://docs.python.org/3/library/
                collections.html#chainmap-examples-and-recipes
    for examples of deeper chainmap operations that may, at some point, 
    be written in.

    todo: BROKEN FROM STANDARD! Need to fix MRO. Current MRO is like 
    old-style classes; needs to be implemented as C3.

    todo: anteheritance isn't really working correctly; need to properly
    track which of the mappings are actually mine.
    
    Note that the funky way that content is being split from the main
    dict is necessary for two reasons:
    
    1. Anteheritance and inheritance may access the existing hash pool
       in unexpected ways.
    2. Allowing lists nested within dicts makes the construct not "just"
       a hash table.
       
       
    Strategy:
    This subclasses SplitHashMap.
    Use TrackingChainmap for the _split_keys and _split_values dicts
    Because we're tracking current, we shouldn't be able to modify other
    mappings, which means we should always have keys pointing to old 
    hash addresses -- and they therefore should never be garbage 
    collected. That should also let us track our own contributions just
    fine. 
    This will, however, create a bug: if I add an inheritance, 
    create a new key in the active EICs that points at content within
    the inheritance, and then delete the inheritance, I will now be 
    pointing to content that does not exist. I'll error out during build
    (presumably), but that's much later than desireable.
    
    Todo: when fixing MRO, split the chainmap up and resolve the mro on
    a key-by-key basis? Eh, no that shouldn't make a difference, you 
    should be able to do C3 on the eics themselves and then search up 
    the tree.
    
    Notes for the future:
      + Anything operating on this should subclass EICs, or use an EICs
        to create a file. This will only do bytes <-> bytes; it won't,
        for example, parse a json file or carve up your sequence of 32-
        bit ints into actual 32-bit ints.
    '''

    magic = b'eics'
    version_str = '0.0.7'
    version = _pack_version(version_str)
    header_size = 660
    file_hash_bytes = slice(584, None)
    payload_bits = slice(header_size, None)

    heritage_row_length = 64
    toc_row_length = 80
    inner_fixed_offset = 16

    header_bits = {}
    header_bits['magic'] = slice(0, 4)
    header_bits['cipher'] = slice(4, 8)
    header_bits['signature'] = slice(8, 520)
    header_bits['file_hash'] = slice(520, 584)
    header_bits['version'] = slice(584, 588)
    header_bits['author'] = slice(588, 652)
    header_bits['payload_length'] = slice(652, header_size)
    header_bits['payload'] = slice(header_size, None)

    payload_bits = {}
    payload_bits['inheritance_length'] = slice(0, 4)
    payload_bits['anteheritance_length'] = slice(4, 8)
    payload_bits['manifest_length'] = slice(8, 12)
    payload_bits['toc_length'] = slice(12, 16)
    # If these change, might need to modify _unpack_payload() or 
    # _unpack_inner_header()
    
    # TODO: write generator function that handles the meaningful payload bits

    def __init__(self, author, d=None, euid=None, mutable=True, signature=None, 
        **kwargs):
        ''' Creates an EICs object.

        Inheriting and anteheriting are completely transparent; the 
        attributes exist only to keep track of which euids need to be 
        referenced during packing. If a user expects to see any 
        particular key within the final resolved EICs, then it should be
        accessible here.

        The aggregate method deals with heritage (at least for the time 
        being), though it does not currently properly form the MRO. Need
        to get experimenting first.
        '''
        # Call super, overriding the default hasher with the EIC one.
        super().__init__(d=d, hasher=self._hash, **kwargs)
        # And now replace the default SplitHashMap dictionaries with 
        # TrackingChainMaps
        self._split_values = TrackingChainMap(self._split_values)
        self._split_values.track(0)
        self._split_keys = TrackingChainMap(self._split_keys)
        self._split_keys.track(0)

        # Predeclare self._signature for state control
        self._signature = signature
        # Add euid if we have one
        if euid:
            self.euid = euid

        # Verify and assign author. Since the signing key is always directly
        # passed, we don't need it here.
        self.check_euid(author)
        self.author = author
        
        # Quick fix to track inheritance and anteheritance
        self._inheritance = collections.deque()
        self._anteheritance = collections.deque()

    def push(self, sym_key, sig_key, storage_providers):
        ''' Assembles the .EICs file, signs it, and pushes it to all of the 
        listed storage providers.
        '''
        # Warning trap if it's already been built
        if self._signature:
            warn(RuntimeWarning('You\'re building an already-signed EICs. '
                                'This will overwrite the parsed file in '
                                'memory, and likely error out.'))

        # Don't need to do further error checking, since __init__ already did.

        # Build the payload
        pkg = self._pack_payload() 
        # Encrypt the payload and delete the pkg
        payload = self._lock_payload(pkg, sym_key)
        del pkg

        # Preinitialize build_array. Note that this only works because the
        # final EICa size is determined by the spec.
        build_array = bytearray(self.header_size + len(payload))
        # Grab the class definitions
        build_map = self.__class__.header_bits

        # Assemble everything else needed for hashing
        build_array[build_map['version']] = self.__class__.version 
        build_array[build_map['author']] = self.author
        build_array[build_map['payload_length']] = struct.pack('>Q', 
                                                               len(payload))
        build_array[build_map['payload']] = payload

        # Hash the prebuilt bit for the file hash, concatenate with payload
        # hash for the euid. Note that conversion to bytes must be explicit
        self._file_hash = self._hash(bytes(
            build_array[self.__class__.file_hash_bytes]))
        self.euid = self._file_hash

        # Get the signature
        self.signature = \
            self._sign(self._file_hash, sig_key)

        # # Verify self before continuing
        # if not _verify(self._file_hash + self._inner_hash, 
        #     self.author.pubkey, self.signature):
        #         raise RuntimeError('Loaded eica failed verification. Try '
        #             'again, check your bytes, or check your object source.')
        # For extra caution, delete the key now that we're done with it
        del sig_key

        # We've signed and verified the completed eic. Finish the build
        build_array[build_map['magic']] = self.__class__.magic
        build_array[build_map['signature']] = self.signature
        build_array[build_map['file_hash']] = self._file_hash
        built = bytes(build_array)

        # Send it to every storage provider.
        StorageProvider.distribute(built, storage_providers, euid=self.euid)

        # If successful, return the EUID (note that in this case, all of
        # them should match).
        return self.euid

    @classmethod
    def verify_public(cls, bites, euid=None):
        ''' Verifies shit.
        '''
        unloaded = super().verify_public(bites)

        # Check the length
        if len(unloaded['payload']) != unloaded['payload_length']:
            raise RuntimeError('Payload length doesn\'t match payload.')

        # Todo: refactor into ABC
        # Verify the euid or construct it if not given
        if euid:
            if euid != unloaded['file_hash']:
                raise RuntimeError('EUID doesn\'t match contents, check EIC '
                    'integrity.')
        # No euid supplied; we'll want it later.
        else:
            euid = unloaded['file_hash']
        # Regardless, add the euid to the unloaded bit
        unloaded['euid'] = euid

        # We've gotten to the end. Return everything.
        return unloaded

    @classmethod
    def _unpack_public(cls, bites):
        ''' Do some post-processing of the unloaded public values.
        '''
        raw = super()._unpack_public(bites)

        # Unpack numeric values
        raw['payload_length'] = struct.unpack('>Q', raw['payload_length'])[0]

        # Return
        return raw

    @classmethod
    def fetch(cls, euid, sym_key, storage_providers):
        ''' Loads an existing .eics file from an ordered list of storage 
        providers using the specified key.
        '''
        # Check the euid
        cls.check_euid(euid)
        # Call super to get the party rollin'.
        unpacked_public, unpacked_payload = \
            super().fetch(euid, sym_key, storage_providers)
        del sym_key
        # Okay, grab a few things from the unpacked payload
        d = unpacked_payload['content']
        anteherits = unpacked_payload['anteherits']
        inherits = unpacked_payload['inherits']

        # Construct the object.
        eics = cls(unpacked_public['author'], d=d, 
                   euid=unpacked_public['euid'], mutable=False, 
                   signature=unpacked_public['signature'])
        # Verify the signature
        eics.verify_signature(storage_providers)

        # Now, and only now, resolve the file.
        # First get the parents.
        for parent in unpacked_payload['inherits']:
            # Note that this won't work once encryption is actually implemented
            # as the symmetric keys will differ. Needs to use an access 
            # provider.
            unpacked_parent = eics.fetch(parent, sym_key, storage_providers)
            eics.aggregate(unpacked_parent, prepend=True)
        # Any anteheriting EICs will need to individually call aggregate().

        # For a bit of added reassurance, delete stuff explicitly right meow
        del unpacked_public, unpacked_payload

        # finally, return the eics
        return eics
        
    def _resolve_ante(self):
        ''' WARNING: DEPRECATED. AND BROKEN. THIS WILL NOT WORK.
        
        Heritage resolution order implementation needs to be figured
        out, but the current depth-first resolution should be good 
        enough to get some demos out.
        
        For posterity:
        ---------------
        
        This is a... worrisome hack to collapse all anteheritances. It will 
        look at the self.maps and the position of the tracker, and applies all 
        upstream keys to a copy of the tracked map. Then it moves all of that
        into a new TrackingDeque and returns that, treating everything as an
        inheritance chain.
        
        This is definitely violating HRO.
        '''
        resolved = TrackingDeque()
        index = self.maps.tracked
        # Get each of the maps ahead of index
        for mapping in self.maps[(index + 1):]:
            resolved.append(mapping)
            
        # Figure out the search order and create a temporary dictionary for 
        # updating keys to. Don't forget it needs to be an inclusive list.
        search_order = list(range(index + 1))
        search_order.reverse()
        applied = {}
        for ii in range(index):
            applied.update(self.maps[ii])
            
        # Now turn that into an inherited mapping and then track that.
        resolved.appendleft(self.Mapping(applied, heritage='inherits'))
        resolved.track(0)
        
        # It's very gross, but we're done.
        return resolved

    def aggregate(self, eics, prepend=False):
        ''' Resolves heritage. Applies the specified eics UPON self. 
        Call this to anteherit FROM eics UPON self, or with 
        prepend=True, to inherit FROM eics UPON self.
        
        This IGNORES the spec-defined "correct" resolution order, and
        instead goes depth-first for simplicity (for the time being).
        '''
        # Make sure the eics has an euid, since we can't really aggregate an
        # unfinalized EICs (if it isn't finalized, we can't reference it!)
        try:
            __ = eics.euid
        except AttributeError:
            raise ValueError('Cannot aggregate an un-finalized EICs. We need '
                             'an euid to be able to reference in heritage.')
        # todo: Should first ping to make sure it's a static file
        # Rather hackedly get the TrackingDeques to add.
        keys_to_add = eics._split_keys.copy().maps
        keys_to_add.untrack()
        values_to_add = eics._split_values.copy().maps
        values_to_add.untrack()
        
        # Are we prepending to the map?
        if prepend:
            self._split_keys.maps.extend(keys_to_add)
            self._split_values.maps.extend(values_to_add)
            self._inheritance.append(eics.euid)
        # Nope, we're appending.
        else:
            # Note that we need to reverse it to extendleft in correct order.
            # We don't reaaally need to reverse the values TrackingDeque, but
            # let's do it anyways.
            keys_to_add.reverse()
            values_to_add.reverse()
            self._split_keys.maps.extendleft(keys_to_add)
            self._split_values.maps.extendleft(values_to_add)
            self._anteheritance.appendleft(eics.euid)

    def verify_signature(self, storage_providers):
        ''' The necessary / convenient wrapper for ABC signature verification, 
        to give it the appropriate bytes.

        Are we, in fact, assured that verifying ONLY the most recent signature
        does, in fact, ensure the veracity of the entire chain?
        '''
        # Get pubkey from the storage providers
        # pubkey = self.key_resolver.fetch_pubkey(self.author, storage_providers)
        
        # Catch any time we're an identity and need to bootstrap.
        if self.author == AUTHOR_BOOTSTRAP:
            pubkey = AUTHOR_BOOTSTRAP_PUBKEY
        # Not an identity; proceed as usual.
        else:
            pubkey = EICs.fetch(self.author, AUTHOR_BOOTSTRAP_SYMKEY, 
                                storage_providers)[b'pubkey']
        # Whatever it is, load it up into a format we can use.
        pubkey = serialization.load_pem_public_key(pubkey, 
                                                backend=self.BACKEND)
            
        # pubkey = EICs.fetch(self.author, access.IdentityAccessProvider(), 
                            # storage_providers)[b'pubkey']

        return super().verify_signature(self.euid, pubkey, self._signature)

    def _pack_payload(self):
        ''' Generates unencrypted payload bytes from self.
        '''
        # First create a bytearray and dict to push lengths into.
        lengths = {}
        packed_lengths = bytearray(self.inner_fixed_offset)
        # Extract MY (and only MY) manifest, and MY (and only my) content.
        distilled_manifest = self._split_keys.tracked
        distilled_contents = self._split_values.tracked
        # Aight, now let's ship off the contents to be packed
        toc, packed_contents = self._pack_contents(distilled_contents)
        lengths['toc'] = len(toc)
        # Same with the manifest
        manifest = self._pack_manifest(distilled_manifest)
        lengths['manifest'] = len(manifest)
        # And the heritage.
        inheritance = self._pack_heritage(self._inheritance)
        lengths['inheritance'] = len(inheritance)
        anteheritance = self._pack_heritage(self._anteheritance)
        lengths['anteheritance'] = len(anteheritance)
        
        # Okay, now string it all together and return
        for key, value in lengths.items():
            partition = self.payload_bits[key + '_length']
            packed_lengths[partition] = struct.pack('>L', value)
        packed = bytes(packed_lengths) + inheritance + anteheritance + \
                 manifest + toc + packed_contents
        # Should we verify anything?
        return packed

    @classmethod
    def _unpack_payload(cls, bites):
        ''' Turns the payload into a handy dictionary.
        '''
        # Predeclare unpacked; get the various lengths and process them.
        unpacked = {}
        lengths = super()._unpack_payload(bites)

        # Unpack numeric values
        lengths = {key: struct.unpack('>I', value)[0] for key, value in 
                   lengths.items()}
        lengths['payload'] = None
        
        # print(lengths)
        # print(bites)
        
        # Verify the lengths
        if lengths['inheritance_length'] % cls.heritage_row_length or \
                lengths['anteheritance_length'] % cls.heritage_row_length:
            raise ValueError('Malformed heritage declaration in inner header.')
        if lengths['toc_length'] % cls.toc_row_length:
            raise ValueError('Malformed TOC declaration in inner header.')

        # This has waaaay, waaay too much typing of dictionary keys.
        # Turn them into slices
        lenlist = [lengths['inheritance_length'], 
                   lengths['anteheritance_length'],
                   lengths['manifest_length'],
                   lengths['toc_length'],
                   lengths['payload']]
        # Iterate over all but the first entry
        # Good lord this is messy
        offsets = [cls.inner_fixed_offset]
        slices = []
        for length in lenlist:
            # First get the lengths
            my_start = offsets[len(offsets) - 1]
            if length != None:
                my_end = my_start + length
            else:
                my_end = None
            slices.append(slice(my_start, my_end))
            offsets.append(my_end)
        # Convert to a dict
        slices = {'inheritance': slices[0],
                  'anteheritance': slices[1],
                  'manifest': slices[2],
                  'toc': slices[3],
                  'payload': slices[4]}

        # Okay, now actually extract the content
        split_inner_header = {key: bites[value] for 
                              key, value in slices.items()}

        # And process it appropriately
        unpacked['inherits'] = \
            cls._unpack_heritage(split_inner_header['inheritance'])
        unpacked['anteherits'] = \
            cls._unpack_heritage(split_inner_header['anteheritance'])
        # Get the manifest
        manifest = cls._unpack_manifest(split_inner_header['manifest'])

        # Turn the ToC into the payload
        payload = {}
        toc = cls._unpack_toc(split_inner_header['toc'])
        # For every hash: slice pair
        for address, partition in toc.items():
            # Get the binary blob associated with this item on the toc
            blob = split_inner_header['payload'][partition]
            # Verify that the hash matches the toc
            if cls._hash(blob) != address:
                raise ValueError('Blob hash doesn\'t match the ToC hash. '
                                 'Check data integrity.')
            # Matches? Add to payload.
            payload[address] = blob
        # Okay, now join payload and the manifest into a single dict with key:
        # content pairs
        payload = cls._recursive_join(manifest, payload)
        # Add it to unpacked
        unpacked['content'] = payload

        return unpacked

    @classmethod
    def _unpack_toc(cls, bites):
        ''' Converts ToC bytes into a hash: slice dictionary.
        '''
        # Split table of contents into rows.
        toc_list = []
        for ii in range(0, len(bites), cls.toc_row_length):
            toc_list.append(bites[ii: ii + cls.toc_row_length])

        # Split off the first 64 bytes for the hash, then 8 bytes for the 
        # offset, then 8 bytes for the length.
        toc = {}
        for row in toc_list:
            address = row[0:64]
            offset = struct.unpack('>Q', row[64:72])[0]
            length = struct.unpack('>Q', row[72:80])[0]
            toc[address] = slice(offset, offset + length)

        return toc

    @classmethod
    def _pack_contents(cls, contents):
        ''' Packs the contents and returns a tuple of: (toc, packed)
        
        contents should be a singular mapping.
        '''
        # Initialize the outputs
        toc = bytearray()
        content = bytearray()
        # Sort the addresses.
        ordered_addresses = sorted(list(contents))
        # Operate on the sorted addresses
        for address in ordered_addresses:
            # Don't need to add 1 because we're zero-addressed
            offset = struct.pack('>Q', len(content))
            length = struct.pack('>Q', len(contents[address]))
            toc.extend(address)
            toc.extend(offset)
            toc.extend(length)
            content.extend(contents[address])
            
        # Done, return them in bytes form
        return bytes(toc), bytes(content)

    @classmethod
    def _unpack_heritage(cls, bites):
        ''' Takes bytes, unpacking each heritage row into a deque of euids.
        '''
        # Preinitialize
        heritage = collections.deque()
        # Iterate over each "row" based on the class "row" length
        for ii in range(0, int(len(bites) / cls.heritage_row_length)):
            offset = ii * cls.heritage_row_length
            partition = slice(offset, offset + heritage_row_length)
            heritage.append(bites[partition])

        # Might need to reverse them at some point?
        return heritage

    @classmethod
    def _pack_heritage(cls, euids):
        ''' Packs the heritage in order into a single heritage blob.
        '''
        heritage = bytearray()

        # Might need to reverse at some point?
        for euid in euids:
            cls.check_euid(euid)
            heritage.extend(euid)

        return bytes(heritage)

    @classmethod
    def _unpack_manifest(cls, bites):
        ''' Strips the payload bytes of the manifest.
        '''
        # Load that shit up
        return zbg.load(bites)

    @classmethod
    def _pack_manifest(cls, manifest):
        ''' Turns the manifest into a properly-encoded json blob.
        '''
        # Smack that shit down
        return zbg.dump(manifest)
        