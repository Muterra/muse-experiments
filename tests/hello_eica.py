import sys
sys.path.append('../')
import eic as pk
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Create a fake storage layer in memory.
memstore = pk.stores.MemoryStore()

# Get the relevant private keys.
with open("key1_private.pem", "rb") as key_file:
    privkey1 = key_file.read()
    private_1 = serialization.load_pem_private_key(
        privkey1,
        password=None,
        backend=default_backend()
    )
    private_1_pc = RSA.importKey(privkey1)
with open("key2_private.pem", "rb") as key_file:
    privkey2 = key_file.read()
    private_2 = serialization.load_pem_private_key(
        privkey2,
        password=None,
        backend=default_backend()
    )
    private_2_pc = RSA.importKey(privkey2)
# Get the relevant public keys.
with open("key1_public.pem", "rb") as key_file:
    pubkey1 = key_file.read()
    public_1 = serialization.load_pem_public_key(
        pubkey1,
        backend=default_backend()
    )
    public_1_pc = RSA.importKey(pubkey1)
with open("key2_public.pem", "rb") as key_file:
    pubkey2 = key_file.read()
    public_2 = serialization.load_pem_public_key(
        pubkey2,
        backend=default_backend()
    )
    public_2_pc = RSA.importKey(pubkey1)

# Create a fake EUID.
target = b'targetEUID' + bytes(54)

# Author for bootstrapping identities.
AUTHOR_BOOTSTRAP = bytes(64)
AUTHOR_BOOTSTRAP_SYMKEY = bytes(32)
AUTHOR_BOOTSTRAP_PRIVKEY = b'''-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
'''
_AUTHOR_BOOTSTRAP_PRIVKEY = serialization.load_pem_private_key(
    AUTHOR_BOOTSTRAP_PRIVKEY,
    password=None,
    backend=default_backend()
)
_AUTHOR_BOOTSTRAP_PRIVKEY2 = RSA.importKey(AUTHOR_BOOTSTRAP_PRIVKEY)

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
_AUTHOR_BOOTSTRAP_PUBKEY2 = RSA.importKey(AUTHOR_BOOTSTRAP_PUBKEY)

# Create a fake symmetric key.
fake_symmetric = b'symmetric_key' + bytes(19)

# Create a fake class.
fake_class = b'classdef' + bytes(56)

# Create fake dynamic content
fake_d_content = b'arbitrary dynamic content, frame 1'

# Buffer request
buffer_req = 10

# Create an author.
author_eics = pk.EICs(AUTHOR_BOOTSTRAP)
author_eics[b'pubkey'] = pubkey1
author_eics[b'noise'] = b'author'
author = author_eics.push(AUTHOR_BOOTSTRAP_SYMKEY, _AUTHOR_BOOTSTRAP_PRIVKEY, 
                          [memstore])
# Create a recipient.
recip_eics = pk.EICs(AUTHOR_BOOTSTRAP)
recip_eics[b'pubkey'] = pubkey2
recip_eics[b'noise'] = b'recipient'
recipient = recip_eics.push(AUTHOR_BOOTSTRAP_SYMKEY, _AUTHOR_BOOTSTRAP_PRIVKEY, 
                            [memstore])

# Create a fake eica using the above, and push it to the memstore.
eica = pk.EICa(recipient, target, author, fake_symmetric)
euid = eica.push(private_1, [memstore])
# Try reloading it from the store and repushing it.
eica_reload = pk.EICa.fetch(euid, private_2_pc, [memstore])
euid = eica_reload.push(private_1, [memstore])

# Create a fake eics and push it
a = pk.EICs(author)
a[b'1'] = b'one'
a[b'2'] = b'two'
a[b'3'] = b'three'
euid = a.push(fake_symmetric, private_1, [memstore])
# Try reloading the fake eics
eics = pk.EICs.fetch(euid, fake_symmetric, [memstore])
# Test aggregation
b = pk.EICs(author)
b[b'4'] = b'four'
b[b'5'] = b'five'
b.euid = b'fakeEUID' + bytes(56)
b.aggregate(eics, prepend=True)
# Try pushing that one back.
euid = b.push(fake_symmetric, private_1, [memstore])

# Create a fake eicd
eicd = pk.EICd(author, buffer_req, content=fake_d_content)
eicd.commit(fake_symmetric, private_1)
# Try pushing the fake eicd and reloading it
euid = eicd.push([memstore])
eicd_reload = pk.EICd.fetch(euid, fake_symmetric, [memstore])
# Try adding new content to the reloaded eicd
eicd_reload.content = b'arbitrary content, frame 2'
eicd_reload.commit(fake_symmetric, private_1)
eicd_reload.push([memstore])

memstore.write_to_disk()