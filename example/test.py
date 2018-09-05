'''
Example of lnoise:

Simulate handshake and sending/receiving messages.
Test vectors are from lightning-rfc/08-transport.md
'''

import os 
from lnoise import HandshakeState, Key
try:
 from secp256k1_zkp import PrivateKey, PublicKey
except:
  try:
    from secp256k1 import PrivateKey, PublicKey
  except:
    raise ImportError("libsecp256k1 should be installed")


import logging
logging.basicConfig(level=logging.INFO)
logger=logging.getLogger(__name__)

def _(x):
  return "0x"+"".join(["%02x"%i for i in x])

def successfull_handshake():
    HS_initiator=HandshakeState()
    rspriv=0x2121212121212121212121212121212121212121212121212121212121212121
    rspub=0x028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7
    lspriv=0x1111111111111111111111111111111111111111111111111111111111111111
    lepriv=0x1212121212121212121212121212121212121212121212121212121212121212

    rs=PublicKey(rspub.to_bytes(33,'big'), raw=True)
    re=None
    logger.debug("rs.pub: %s"%hex(rspub))
    logger.debug("ls.priv: %s"%hex(lspriv))
    s=Key(key=PrivateKey(lspriv.to_bytes(32,'big'), raw=True))
    assert(int.from_bytes(s.pubkey(),'big')==0x034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa)
    logger.debug("ls.pub: %s"%_(s.pubkey()))
    logger.debug("e.priv: %s"%hex(lepriv))
    e=Key(key=PrivateKey(lepriv.to_bytes(32,'big'), raw=True))
    assert(int.from_bytes(e.pubkey(),'big')==0x036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7)
    logger.debug("e.pub: %s"%_(e.pubkey()))

    # Initiator send first message
    HS_initiator.initialize('Noise_XK', prologue=b'lightning', s=s, e=e, rs=rs, re=None, initiator=True)
    message = HS_initiator.write_message(b"")
    #print(mb)
    logger.info("Act one, initiator's message composed %s"%_(message))
    msg="0x00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a"
    logger.info((msg, _(message)))
    assert(len(message)==50)
    assert(msg==_(message))

    # Receiver read first message
    HS_receiver=HandshakeState()
    repriv=0x2222222222222222222222222222222222222222222222222222222222222222
    re=Key(key=PrivateKey(repriv.to_bytes(32,'big'), raw=True))
    rs=Key(key=PrivateKey(rspriv.to_bytes(32,'big'), raw=True))
    ls_pub=PublicKey(s.pubkey(), raw=True)
    assert(int.from_bytes(re.pubkey(),'big')==0x02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27)
    ls=PublicKey(s.pubkey(), raw=True)
    HS_receiver.initialize('Noise_XK', prologue=b'lightning', s=rs, e=re, rs=None, re=None, initiator=False)
    payload=[]
    HS_receiver.read_message(message, payload)
    assert(int.from_bytes(HS_receiver.symmetricstate.h,'big')==0x9d1ffbb639e7e20021d9259491dc7b160aab270fb1339ef135053f6f2cebe9ce)

    # Receivier sends message
    message = HS_receiver.write_message(b"")
    logger.info("Act two, receiver's message composed %s"%_(message))
    msg="0x0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae"
    assert(msg==_(message))
    assert(len(message)==50)

    # Initiator reads message
    payload=[]
    HS_initiator.read_message(message, payload)
    assert(int.from_bytes(HS_initiator.symmetricstate.h,'big')==0x90578e247e98674e661013da3c5c1ca6a8c8f48c90b485c0dfa1494e23d56d72)

    #Initiator sends message
    message = HS_initiator.write_message(b"")
    logger.info("Act three, initiator's second message composed %s"%_(message))
    msg="0x00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba"
    assert(msg==_(message))
    assert(len(message)==66)
    assert(HS_initiator.handshake_established)
    rk,sk=HS_initiator.session_ciphers[0].k, HS_initiator.session_ciphers[1].k
    assert((_(rk),_(sk))==("0x969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9","0xbb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442"))

    #Receiver reads message
    payload=[]
    HS_receiver.read_message(message, payload)
    assert(HS_receiver.handshake_established)
    rk,sk=HS_receiver.session_ciphers[0].k, HS_receiver.session_ciphers[1].k
    assert((_(rk),_(sk))==("0x969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9","0xbb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442"))
    return HS_initiator, HS_receiver


def failed_handshaked():
    HS_initiator=HandshakeState()
    rspriv=0x2121212121212121212121212121212121212121212121212121212121212121
    rspub=0x028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7
    lspriv=0x1111111111111111111111111111111111111111111111111111111111111111
    lepriv=0x1212121212121212121212121212121212121212121212121212121212121212

    rs=PublicKey(rspub.to_bytes(33,'big'), raw=True)
    re=None
    logger.debug("rs.pub: %s"%hex(rspub))
    logger.debug("ls.priv: %s"%hex(lspriv))
    s=Key(key=PrivateKey(lspriv.to_bytes(32,'big'), raw=True))
    assert(int.from_bytes(s.pubkey(),'big')==0x034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa)
    logger.debug("ls.pub: %s"%_(s.pubkey()))
    logger.debug("e.priv: %s"%hex(lepriv))
    e=Key(key=PrivateKey(lepriv.to_bytes(32,'big'), raw=True))
    assert(int.from_bytes(e.pubkey(),'big')==0x036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7)
    logger.debug("e.pub: %s"%_(e.pubkey()))

    # Initiator send first message
    HS_initiator.initialize('Noise_XK', prologue=b'lightning', s=s, e=e, rs=rs, re=re, initiator=True)
    message = HS_initiator.write_message(b"")
    logger.info("Act one, initiator's message composed %s"%_(message))
    msg="0x00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a"
    assert(msg==_(message))
    assert(len(message)==50)

    # Receiver read first message
    HS_receiver=HandshakeState()
    repriv=0x2222222222222222222222222222222222222222222222222222222222222222
    re=Key(key=PrivateKey(repriv.to_bytes(32,'big'), raw=True))
    rs=Key(key=PrivateKey(rspriv.to_bytes(32,'big'), raw=True))
    ls_pub=PublicKey(s.pubkey(), raw=True)
    assert(int.from_bytes(re.pubkey(),'big')==0x02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27)
    ls=PublicKey(s.pubkey(), raw=True)
    HS_receiver.initialize('Noise_XK', prologue=b'lightning', s=rs, e=re, rs=ls_pub, re=None, initiator=False)
    payload=[]
    HS_receiver.read_message(message, payload)
    assert(int.from_bytes(HS_receiver.symmetricstate.h,'big')==0x9d1ffbb639e7e20021d9259491dc7b160aab270fb1339ef135053f6f2cebe9ce)

    # Receivier sends message
    message = HS_receiver.write_message(b"")
    logger.info("Act two, receiver's message composed %s"%_(message))
    msg="0x0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae"
    assert(msg==_(message))
    assert(len(message)==50)
    message=message[:-2]
    payload=[]
    HS_initiator.read_message(message, payload)
    



def messages_sending():
    HS_initiator=HandshakeState()
    rspriv=0x2121212121212121212121212121212121212121212121212121212121212121
    rspub=0x028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7
    lspriv=0x1111111111111111111111111111111111111111111111111111111111111111
    lepriv=0x1212121212121212121212121212121212121212121212121212121212121212

    rs=PublicKey(rspub.to_bytes(33,'big'), raw=True)
    re=None
    s=Key(key=PrivateKey(lspriv.to_bytes(32,'big'), raw=True))
    assert(int.from_bytes(s.pubkey(),'big')==0x034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa)
    e=Key(key=PrivateKey(lepriv.to_bytes(32,'big'), raw=True))
    assert(int.from_bytes(e.pubkey(),'big')==0x036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7)

    # Initiator send first message
    HS_initiator.initialize('Noise_XK', prologue=b'lightning', s=s, e=e, rs=rs, re=re, initiator=True)
    message = HS_initiator.write_message(b"")
    #print(mb)
    msg="0x00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a"
    assert(msg==_(message))
    assert(len(message)==50)

    # Receiver read first message
    HS_receiver=HandshakeState()
    repriv=0x2222222222222222222222222222222222222222222222222222222222222222
    re=Key(key=PrivateKey(repriv.to_bytes(32,'big'), raw=True))
    rs=Key(key=PrivateKey(rspriv.to_bytes(32,'big'), raw=True))
    ls_pub=PublicKey(s.pubkey(), raw=True)
    assert(int.from_bytes(re.pubkey(),'big')==0x02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27)
    ls=PublicKey(s.pubkey(), raw=True)
    HS_receiver.initialize('Noise_XK', prologue=b'lightning', s=rs, e=re, rs=ls_pub, re=None, initiator=False)
    payload=[]
    HS_receiver.read_message(message, payload)
    assert(int.from_bytes(HS_receiver.symmetricstate.h,'big')==0x9d1ffbb639e7e20021d9259491dc7b160aab270fb1339ef135053f6f2cebe9ce)

    # Receivier sends message
    message = HS_receiver.write_message(b"")
    msg="0x0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae"
    assert(msg==_(message))
    assert(len(message)==50)

    # Initiator reads message
    payload=[]
    HS_initiator.read_message(message, payload)
    assert(int.from_bytes(HS_initiator.symmetricstate.h,'big')==0x90578e247e98674e661013da3c5c1ca6a8c8f48c90b485c0dfa1494e23d56d72)

    #Initiator sends message
    message = HS_initiator.write_message(b"")
    msg="0x00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba"
    assert(msg==_(message))
    assert(len(message)==66)
    assert(HS_initiator.handshake_established)
    rk,sk=HS_initiator.session_ciphers[0].k, HS_initiator.session_ciphers[1].k
    assert((_(rk),_(sk))==("0x969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9","0xbb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442"))

    #Receiver reads message
    payload=[]
    HS_receiver.read_message(message, payload)
    assert(HS_receiver.handshake_established)
    rk,sk=HS_receiver.session_ciphers[0].k, HS_receiver.session_ciphers[1].k
    assert((_(rk),_(sk))==("0x969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9","0xbb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442"))
    logger.info("Handshake is finished successfully") 
    session_i, session_r = HS_initiator.session, HS_receiver.session

    test_vector = {0:"0xcf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95",
                    1:"0x72887022101f0b6753e0c7de21657d35a4cb2a1f5cde2650528bbc8f837d0f0d7ad833b1a256a1",
                    500:"0x178cb9d7387190fa34db9c2d50027d21793c9bc2d40b1e14dcf30ebeeeb220f48364f7a4c68bf8",
                    501:"0x1b186c57d44eb6de4c057c49940d79bb838a145cb528d6e8fd26dbe50a60ca2c104b56b60e45bd",
                    1000:"0x4a2f3cc3b5e78ddb83dcb426d9863d9d9a723b0337c89dd0b005d89f8d3c05c52b76b29b740f09",
                    1001:"0x2ecd8c8a5629d0d02ab457a0fdd0f7b90a192cd46be5ecb6ca570bfc5e268338b1a16cf4ef2d36",
                    }
    plaintext=b'hello'
    for i in range(2000):
      msg=session_i.encode(plaintext)
      if i in test_vector:
        assert(_(msg)==test_vector[i])
      decoded = session_r.decode(msg)
      assert( bytes(decoded[0])==plaintext)
    #and sending back
    plaintext=os.urandom(100)
    msg=session_r.encode(plaintext)
    assert(bytes(session_i.decode(msg)[0])==plaintext)



def exception_if_no_exception(func):
    try:
        func()
        raise Exception("Exception expected but not raised")
    except:
        return True

successfull_handshake()
exception_if_no_exception(failed_handshaked)
messages_sending()
