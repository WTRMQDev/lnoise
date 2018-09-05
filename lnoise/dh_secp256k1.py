try:
    from secp256k1_zkp import PrivateKey, PublicKey
except ImportError:
    try:
        from secp256k1 import PrivateKey, PublicKey
    except ImportError:
        raise ImportError("libsecp256k1 should be installed")

from .noisetypes import SHA256


class Key:
    def __init__(self, key=None):
        if not key:
            self.key = PrivateKey()
        else:
            if isinstance(key, type(PrivateKey())):
                self.key = key
            elif isinstance(key, type(Key())):
                self.key = key.key
            else:
                raise

    def ecdh(self, public_key):
        pk = public_key.serialize()
        if not pk[0] in [2, 3, 4]:
            raise Exception('Unknown pubkey format')
        pub = PublicKey(pk, raw=True)
        return pub.ecdh(self.key.private_key)

    def pubkey(self):
        return self.key.pubkey.serialize(compressed=True)

    def public_key(self):
        return self.pubkey()

    def public(self):
        return self.pubkey()

    def uncompressed_key(self):
        return self.key.pubkey


class DiffieHellmanSecp256k1:
    NAME = b"secp256k1"
    DHLEN = 32
    Key = Key
    PublicKey = PublicKey

    def __init__(self):
        pass

    @staticmethod
    def generate_keypair():
        return Key()

    @staticmethod
    def DH(key_pair, public_key):
        dh = Key(key_pair).ecdh(public_key)
        return dh
