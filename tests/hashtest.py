from cryptography.hazmat.backends import default_backend

import time

from cryptography.hazmat.primitives import hashes

# Warm up the library in case any initializeation needs to be done first.
warmup = hashes.Hash(hashes.SHA256(), backend=default_backend())

ex_bites = b'some_bytes'
nn_range = range(10000)

_start = time.process_time()
def _hash1(bites):
    ''' Man, this bites.'''
    # Create the hash
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    # Give it the bytes
    digest.update(bites)

    # Finalize that shit and return
    return digest.finalize()
for ii in nn_range:
    _hash1(ex_bites)
_end = time.process_time()

print('Full reset')
print(_end - _start)

_start = time.process_time()
    
digest = hashes.Hash(hashes.SHA256(), backend=default_backend())

def _hash2(bites):
    ''' Man, this bites.'''
    # Create the hash
    # Give it the bytes
    dg = digest.copy()
    dg.update(bites)

    # Finalize that shit and return
    return dg.finalize()
for ii in nn_range:
    _hash2(ex_bites)
_end = time.process_time()

print('Copy')
print(_end - _start)


import hashlib
_start = time.process_time()
    
def _hash3(bites):
    ''' Man, this bites.'''
    # Create the hash
    digest = hashlib.sha256()
    # Give it the bytes
    digest.update(bites)
    return digest.digest()

for ii in nn_range:
    _hash3(ex_bites)
_end = time.process_time()

print('Hashlib')
print(_end - _start)
