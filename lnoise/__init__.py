from .noisetypes import *
from .dh_secp256k1 import *
from .state import HandshakeState as HS
from .state import *

name = "lnoise"


def HandshakeState():
    return HS(DiffieHellmanSecp256k1(), ChaChaPoly, SHA256)
