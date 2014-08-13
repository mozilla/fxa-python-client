#!/usr/bin/env python
# -*- coding: utf-8 -*-
# this should work with both python2.7 and python3.3

from hashlib import sha256
import hmac
from .hkdf import HKDF
import itertools, binascii, time, sys
from six import binary_type, print_, int2byte, b

# get scrypt-0.6.1 from PyPI, run this with it in your PYTHONPATH
# https://pypi.python.org/pypi/scrypt/0.6.1
import scrypt

# PyPI has four candidates for PBKDF2 functionality. We use "simple-pbkdf2"
# by Armin Ronacher: https://pypi.python.org/pypi/simple-pbkdf2/1.0 . Note
# that v1.0 has a bug which causes segfaults when num_iterations is greater
# than about 88k.
from .pbkdf2 import pbkdf2_bin

# other options:
# * https://pypi.python.org/pypi/PBKDF/1.0
#   most mature, but hardwired to use SHA1
#
# * https://pypi.python.org/pypi/pbkdf2/1.3
#   doesn't work without pycrypto, since its hashlib fallback is buggy
#
# * https://pypi.python.org/pypi/pbkdf2.py/1.1
#   also looks good, but ships in multiple files

def HMAC(key, msg):
    return hmac.new(key, msg, sha256).digest()


def printheader(name):
    print_("### %s" % name)
    print_()


def printhex(name, value, groups_per_line=1):
    #print_("%s:" % name)
    assert isinstance(value, binary_type), type(value)
    h = binascii.hexlify(value).decode("ascii")
    groups = [h[i:i+16] for i in range(0, len(h), 16)]
    if 0:
        for i in range(0, len(groups), 4):
            if i==0:
                print_("' %s'" % " ".join(groups[i:i+4]))
            else:
                print_("       +'%s'" % " ".join(groups[i:i+4]))
        print_()
        return
    lines = [" ".join(groups[i:i+groups_per_line])
             for i in range(0, len(groups), groups_per_line)]
    print_("%s:" % name)
    for line in lines:
        print_(line)
    print_()


def split(value):
    assert len(value)%32 == 0
    return [value[i:i+32] for i in range(0, len(value), 32)]


def KW(name):
    return b"identity.mozilla.com/picl/v1/" + b(name)


def KWE(name, emailUTF8):
    return b"identity.mozilla.com/picl/v1/" + b(name) + b":" + emailUTF8


def xor(s1, s2):
    assert isinstance(s1, binary_type), type(s1)
    assert isinstance(s2, binary_type), type(s2)
    assert len(s1) == len(s2)
    return b"".join([int2byte(ord(s1[i:i+1])^ord(s2[i:i+1])) for i in range(len(s1))])


def fakeKey(start):
    return b"".join([int2byte(c) for c in range(start, start+32)])


def main():
    printheader("client stretch-KDF")
    emailUTF8 = u"andré@example.org".encode("utf-8")
    passwordUTF8 = u"pässwörd".encode("utf-8")
    printhex("email", emailUTF8)
    printhex("password", passwordUTF8)

    # stretching
    quickStretchedPW = pbkdf2_bin(passwordUTF8, KWE("quickStretch", emailUTF8),
                                  1000, keylen=1*32, hashfunc=sha256)
    printhex("quickStretchedPW", quickStretchedPW)
    authPW = HKDF(SKM=quickStretchedPW,
                  XTS="",
                  CTXinfo=KW("authPW"),
                  dkLen=1*32)
    printhex("authPW", authPW)
    authSalt = b"\x00"+b"\xf0"+b"\x00"*(32-2)
    printhex("authSalt (normally random)", authSalt)
    bigStretchedPW = scrypt.hash(authPW, authSalt, N=64*1024, r=8, p=1, buflen=1*32)
    printhex("bigStretchedPW", bigStretchedPW)
    verifyHash = HKDF(SKM=bigStretchedPW,
                      XTS="",
                      CTXinfo=KW("verifyHash"),
                      dkLen=1*32)
    printhex("verifyHash", verifyHash)

    kA = fakeKey(1*32)
    wrapwrapkB = fakeKey(2*32)
    authToken = fakeKey(3*32)
    keyFetchToken = fakeKey(4*32)
    sessionToken = fakeKey(5*32)
    accountResetToken = fakeKey(6*32)

    if 1:
        printheader("/account/keys")

        wrapwrapKey = HKDF(SKM=bigStretchedPW,
                           XTS="",
                           CTXinfo=KW("wrapwrapKey"),
                           dkLen=1*32)
        printhex("wrapwrapKey", wrapwrapKey)
        wrapkB = xor(wrapwrapKey, wrapwrapkB)

        unwrapBkey = HKDF(SKM=quickStretchedPW,
                          XTS="",
                          CTXinfo=KW("unwrapBkey"),
                          dkLen=1*32)
        printhex("unwrapBkey", unwrapBkey)

        x = HKDF(SKM=keyFetchToken,
                 dkLen=3*32,
                 XTS=None,
                 CTXinfo=KW("keyFetchToken"))
        tokenID = x[0:32]
        reqHMACkey = x[32:64]
        keyRequestKey = x[64:96]
        y = HKDF(SKM=keyRequestKey,
                 dkLen=3*32,
                 XTS=None,
                 CTXinfo=KW("account/keys"))
        respHMACkey = y[0:32]
        respXORkey = y[32:96]
        printhex("keyFetchToken", keyFetchToken)
        printhex("tokenID (keyFetchToken)", tokenID)
        printhex("reqHMACkey", reqHMACkey)
        printhex("keyRequestKey", keyRequestKey)
        printhex("respHMACkey", respHMACkey)
        printhex("respXORkey", respXORkey)

        printhex("kA", kA)
        printhex("wrapkB", wrapkB)
        plaintext = kA+wrapkB
        printhex("plaintext", plaintext)

        ciphertext = xor(plaintext, respXORkey)
        printhex("ciphertext", ciphertext)
        mac = HMAC(respHMACkey, ciphertext)
        printhex("MAC", mac)
        printhex("response", ciphertext+mac)

        printhex("wrapkB", wrapkB)
        printhex("unwrapBkey", unwrapBkey)
        kB = xor(wrapkB, unwrapBkey)
        printhex("kB", kB)


    if 1:
        printheader("use session (certificate/sign, etc)")
        tokenID,reqHMACkey = split(HKDF(SKM=sessionToken,
                                        XTS=None,
                                        dkLen=2*32,
                                        CTXinfo=KW("sessionToken")))
        printhex("sessionToken", sessionToken)
        printhex("tokenID (sessionToken)", tokenID)
        printhex("reqHMACkey", reqHMACkey)


if __name__ == "__main__":
    main()
