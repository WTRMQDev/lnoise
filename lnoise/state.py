from enum import Enum

from .patterns import HSPatterns
from .noisetypes import empty
from .error import HandshakeError


class PartialData(Exception):
    pass


class CipherState(object):
    def __init__(self, cipher, key=empty):
        self.cipher = cipher
        self.initialize_key(key)

    def initialize_key(self, key):
        self.k = key
        self.n = 0

    def drop_nonce(self):
        self.n = 0

    @property
    def has_key(self):
        return self.k is not empty

    def encrypt_with_ad(self, ad, plaintext, external_nonce=None):
        if self.k is empty:
            return plaintext
        nonce = external_nonce if external_nonce else self.n
        ret = self.cipher.encrypt(
            self.k,
            b"\x00" * 4 + nonce.to_bytes(8, 'little'),
            ad,
            plaintext)
        self.n += 0 if external_nonce else 1
        return ret

    def decrypt_with_ad(self, ad, ciphertext, external_nonce=None):
        if self.k is empty:
            return ciphertext
        nonce = external_nonce if external_nonce else self.n
        ret = self.cipher.decrypt(
            self.k,
            b"\x00" * 4 + nonce.to_bytes(8, 'little'),
            ad,
            ciphertext)
        self.n += 0 if external_nonce else 1
        return ret

    def decrease_nonce(self):
        self.n-=1


class SymmetricState(object):
    def __init__(self, dh, cipher, hasher, protocol_name=None):
        self.dh = dh
        self.hasher = hasher
        self.cipherstate = CipherState(cipher)
        if protocol_name is not None:
            self.initialize_symmetric(protocol_name)

    def initialize_symmetric(self, protocol_name):
        diff = self.hasher.HASHLEN - len(protocol_name)
        if diff >= 0:
            self.h = protocol_name + bytes(diff)
        else:
            self.h = self.hasher.hash(protocol_name)
        self.ck = self.h
        self.cipherstate.initialize_key(empty)

    def mix_key(self, input_key_material):
        self.ck, temp_k = self.hasher.hkdf(self.ck, input_key_material,
                                           dhlen=self.dh.DHLEN)
        self.cipherstate.initialize_key(temp_k)

    def mix_hash(self, data):
        self.h = self.hasher.hash(self.h + data)

    def encrypt_and_hash(self, plaintext, external_nonce=None):
        ciphertext = self.cipherstate.encrypt_with_ad(
            self.h, plaintext, external_nonce=external_nonce)
        self.mix_hash(ciphertext)
        return ciphertext

    def decrypt_and_hash(self, ciphertext, external_nonce=None):
        plaintext = self.cipherstate.decrypt_with_ad(
            self.h, ciphertext, external_nonce=external_nonce)
        self.mix_hash(ciphertext)
        return plaintext

    def drop_nonce(self):
        self.cipherstate.drop_nonce()

    def split(self):
        temp_k1, temp_k2 = self.hasher.hkdf(self.ck, b'')
        if self.hasher.HASHLEN == 64:
            temp_k1, temp_k2 = temp_k1[:32], temp_k2[:32]
        c1 = CipherState(self.cipherstate.cipher, temp_k1)
        c2 = CipherState(self.cipherstate.cipher, temp_k2)
        return c1, c2


class HandshakeState(object):
    class STATES(Enum):
        NOT_STARTED = 0
        WAITING_TO_READ = 1
        WAITING_TO_WRITE = 2
        ESTABLISHED = 3
        CLOSED = 4

    def __init__(self, dh, cipher, hasher):
        self.dh = dh
        self.cipher = cipher
        self.hasher = hasher
        self.version = b'\x00'
        self.allowed_versions = [self.version]
        self.state = self.STATES.NOT_STARTED

    def initialize(self, handshake_pattern, prologue=b'', initiator=False,
                   s=empty, e=empty, rs=empty, re=empty):
        protocol_name = b'_'.join(
            (handshake_pattern.encode('utf-8'),
             self.dh.NAME,
             self.cipher.NAME,
             self.hasher.NAME))
        self.symmetricstate = SymmetricState(self.dh, self.cipher, self.hasher,
                                             protocol_name)
        self.symmetricstate.mix_hash(prologue)
        self.s = s
        self.e = e
        self.rs = rs
        self.re = re

        pattern = HSPatterns[handshake_pattern]
        if initiator:
            if pattern.i_pre not in ('', 's', 'e', 'se'):
                raise HandshakeError("Invalid initiator pre-message")
            for token in pattern.i_pre:
                if token == 's':
                    if self.s is empty:
                        raise HandshakeError(
                            "No static public key (initiator)")
                    self.symmetricstate.mix_hash(self.rs.serialize())
                elif token == 'e':
                    if self.e is empty:
                        raise HandshakeError(
                            "No ephemeral public key (initiator)")
                    self.symmetricstate.mix_hash(self.re.serialize())
        else:
            for token in pattern.r_pre:
                if token == 's':
                    if self.rs is empty:
                        raise HandshakeError(
                            "No static public key (responder)")
                    self.symmetricstate.mix_hash(self.s.pubkey())
                elif token == 'e':
                    if self.re is empty:
                        raise HandshakeError(
                            "No ephemeral public key (responder)")
                    self.symmetricstate.mix_hash(self.e.pubkey())

        self.message_patterns = list(pattern.message_patterns)
        self.handshake_established = False
        self.session_ciphers = None
        self.session = None
        self.state = self.STATES.WAITING_TO_WRITE if initiator else self.STATES.WAITING_TO_READ

    def write_message(self, payload):
        message_buffer = []
        if not self.state == self.STATES.WAITING_TO_WRITE:
            raise HandshakeError(
                "Unexpected handshake actions. Handshake in state %s, trying to write" %
                (self.state))
        handshake_process = bool(len(self.message_patterns))
        if handshake_process and len(payload):
            raise HandshakeError("During handshake payload should be empty")
        message_buffer.append(self.version)
        message_pattern = self.message_patterns.pop(0)
        for token in message_pattern:
            if token == 'e':
                message_buffer.append(self.e.public_key())
                self.symmetricstate.mix_hash(self.e.public_key())
            elif token == 's':
                msg = self.symmetricstate.encrypt_and_hash(
                    self.s.public_key(), external_nonce=1)
                message_buffer.append(msg)
            elif token[:2] == 'dh':
                try:
                    x = {'e': self.e, 's': self.s}[token[2]]
                    y = {'e': self.re, 's': self.rs}[token[3]]
                except KeyError:
                    raise HandshakeError("Invalid pattern: " + token)
                self.symmetricstate.mix_key(self.dh.DH(x, y))
            else:
                raise HandshakeError("Invalid pattern: " + token)
        message_buffer.append(self.symmetricstate.encrypt_and_hash(
            payload, external_nonce=0 if handshake_process else None))
        if handshake_process and not len(self.message_patterns):
            self.symmetricstate.drop_nonce()
        if len(self.message_patterns) == 0:
            self.session_ciphers = self.symmetricstate.split()
            self.handshake_established = True
            self.session = Session(
                self.session_ciphers[0],
                self.session_ciphers[1],
                self.symmetricstate.ck,
                self.hasher)
            self.state = self.STATES.ESTABLISHED
        else:
            self.state = self.STATES.WAITING_TO_READ
        return b"".join(message_buffer)

    def read_message(self, message, payload_buffer):
        if not self.state == self.STATES.WAITING_TO_READ:
            raise HandshakeError(
                "Unexpected handshake actions. Handshake in state %s, trying to read" %
                (self.state))
        try:
            handshake_process = bool(len(self.message_patterns))
            version_byte, message = message[:1], message[1:]
            if version_byte not in self.allowed_versions:
                raise HandshakeError(
                    "Message on transport level has unknown version byte: %s"%version_byte)
            message_pattern = self.message_patterns.pop(0)
            for token in message_pattern:
                if token == 'e':
                    if len(message) < self.dh.DHLEN + 1:
                        raise HandshakeError(
                            "Message too short, processing token %s" % token)
                    self.re = self.dh.PublicKey(
                        message[:self.dh.DHLEN + 1], raw='True')
                    message = message[self.dh.DHLEN + 1:]
                    self.symmetricstate.mix_hash(self.re.serialize())
                elif token == 's':
                    has_key = self.symmetricstate.cipherstate.has_key
                    nbytes = self.dh.DHLEN + 16 + 1 if has_key else self.dh.DHLEN + 1
                    if len(message) < nbytes:
                        raise HandshakeError(
                            "Message too short, processing token %s" % token)
                    temp, message = message[:nbytes], message[nbytes:]
                    if has_key:
                        self.rs = self.dh.PublicKey(
                            bytes(
                                self.symmetricstate.decrypt_and_hash(
                                    temp,
                                    external_nonce=1)),
                            raw=True)
                    else:
                        self.rs = self.dh.PublicKey(bytes(temp), raw=True)
                elif token[:2] == 'dh':
                    try:
                        x = {'e': self.e, 's': self.s}[token[3]]
                        y = {'e': self.re, 's': self.rs}[token[2]]
                    except KeyError:
                        raise HandshakeError("Invalid pattern: " + token)
                    self.symmetricstate.mix_key(self.dh.DH(x, y))
                else:
                    raise HandshakeError("Invalid pattern: " + token)
            payload_buffer.append(self.symmetricstate.decrypt_and_hash(
                message, external_nonce=0 if handshake_process else None))
            if handshake_process and not len(self.message_patterns):
                self.symmetricstate.drop_nonce()
            if len(self.message_patterns) == 0:
                self.session_ciphers = self.symmetricstate.split()
                self.handshake_established = True
                self.session = Session(
                    self.session_ciphers[1],
                    self.session_ciphers[0],
                    self.symmetricstate.ck,
                    self.hasher)
                self.state = self.STATES.ESTABLISHED
            else:
                self.state = self.STATES.WAITING_TO_WRITE
        except BaseException:
            self.state = self.STATES.CLOSED
            raise


class Session:
    def __init__(self, encoder, decoder, ck, hasher):
        self.e = encoder
        self.e_ck = ck
        self.d = decoder
        self.d_ck = ck
        self.hasher = hasher
        self.open = True

    def encode(self, payload):
        if not self.open:
            raise SessionError("Trying to encode message for closed session")
        if len(payload) > 65536:
            raise SessionError(
                "Trying to encode message bigger than 65536bytes (message len: %s)" %
                len(payload))
        l = len(payload)
        l = l.to_bytes(2, 'big')
        lc = self.e.encrypt_with_ad(b'', l)
        c = self.e.encrypt_with_ad(b'', payload)
        self.check_e_rotate()
        return lc + c

    def decode(self, message):
        if not self.open:
            raise SessionError("Trying to decode message from closed session")
        try:
            if len(message) < 18:
                raise PartialData()
            lc, message = message[:18], message[18:]
            l = self.d.decrypt_with_ad(b'', lc)
            l = int.from_bytes(l, 'big')
            if len(message) < l + 16:
                self.d.decrease_nonce() #When full message arrive we need same nonce to read it
                raise PartialData()
            c, residue = message[:l + 16], message[l + 16:]
            payload = self.d.decrypt_with_ad(b'', c)
            self.check_d_rotate()
            return payload, residue
        except PartialData as e:
            raise
        except Exception as e:
            self.open = False
            raise

    def check_e_rotate(self):
        if self.e.n >= 1000:
            self.rotate_e_key()

    def rotate_e_key(self):
        (self.e_ck, k), old_ck = self.hasher.hkdf(
            self.e_ck, self.e.k), self.e_ck
        self.e.initialize_key(k)

    def check_d_rotate(self):
        if self.d.n >= 1000:
            self.rotate_d_key()

    def rotate_d_key(self):
        (self.d_ck, k), old_ck = self.hasher.hkdf(
            self.d_ck, self.d.k), self.d_ck
        self.d.initialize_key(k)
