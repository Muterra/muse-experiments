import sys
sys.path.append('../')
import pyeic as pk

obj = b'Hello world'
mystore = pk.StorageProvider()

with pk.Author(euid, pubkey, key) as me:
    foo, foo_key = me.build(obj)
    mystore.upload(foo)
    bar = me.share(foo, me, foo_key)
    mystore.upload(bar)

# isinstance(obj, collections.Iterable)