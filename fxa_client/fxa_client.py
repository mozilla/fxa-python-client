#!/usr/bin/env python

import os, urlparse, argparse # argparse requires py2.7/py3.2
import time
import fxa_crypto
from fxa_crypto import (
    FXA_GET, printhex, binary_type, FXA_POST, resendForgotPassword,
    stretch, verifyForgotPassword, HKDF, KW, split,
    HAWK_POST, getRestmailVerifyUrl, RESTMAILURL,
    verifyUrl, changePassword, getEmailStatus,
    fetchKeys, createKeypair, signCertificate, dumpCert, HOST,
    destroySession, WebError)

class UnknownCommand(Exception):
    pass

def command(args, emailUTF8, passwordUTF8, acceptLang):
    FXA_GET("__heartbeat__", versioned="")
    command = args.command

    # emailUTF8 and passwordUTF8 are provided with --email and --password,
    # but are not needed by all commands
    if command in ("create", "login", "login-with-keys", "destroy"):
        assert emailUTF8
        assert passwordUTF8
        assert len(args.args) == 0
        print "email='%s', password='%s'" % (emailUTF8, passwordUTF8)
    elif command == "change-password":
        assert emailUTF8
        assert passwordUTF8
        assert len(args.args) == 1
        newPasswordUTF8 = args.args[0]
        printhex("newpassword", newPasswordUTF8)
    elif command == "forgotpw-send":
        assert emailUTF8
        assert len(args.args) == 0
    elif command == "forgotpw-resend":
        assert emailUTF8
        assert len(args.args) == 1
        passwordForgotToken_hex = args.args[0]
        passwordForgotToken = passwordForgotToken_hex.decode("hex")
    elif command == "forgotpw-submit":
        assert emailUTF8
        # use --password to provide the new password
        assert passwordUTF8
        assert len(args.args) == 2
        passwordForgotToken_hex,code = args.args
        passwordForgotToken = passwordForgotToken_hex.decode("hex")
    elif command in ("verify", "get-token-code"):
        assert len(args.args) == 0
    else:
        raise UnknownCommand("unknown command '%s'" % command)

    assert isinstance(emailUTF8, binary_type)

    if command == "forgotpw-send":
        r = FXA_POST("password/forgot/send_code",
                     {"email": emailUTF8})
        print r
        passwordForgotToken = r["passwordForgotToken"]
        return

    if command == "forgotpw-resend":
        r = resendForgotPassword(passwordForgotToken, emailUTF8)
        print r
        return

    if command == "forgotpw-submit":
        newAuthPW = stretch(emailUTF8, passwordUTF8)[0]
        accountResetToken = verifyForgotPassword(passwordForgotToken, code)
        x = HKDF(SKM=accountResetToken,
                 XTS=None,
                 CTXinfo=KW("accountResetToken"),
                 dkLen=2*32)
        tokenID, reqHMACkey = split(x)
        r = HAWK_POST("account/reset", tokenID, reqHMACkey,
                      {"authPW": newAuthPW.encode("hex"),
                       })
        print r
        assert r == {}, r
        return

    if command == "verify":
        verify_url = None
        retry_count = 10

        inbox_url = urlparse.urljoin(RESTMAILURL, emailUTF8)
        while True:
            verify_url = getRestmailVerifyUrl(inbox_url)
            if verify_url:
                break;

            # If email with verification code hasn't been arrived yet,
            # retry retrieving the email a couple of times
            time.sleep(1)
            retry_count -= 1

            if retry_count == 0:
                return

        print 'Verify URL: ', verify_url
        r = verifyUrl(verify_url)
        assert r.code == 200
        print 'Verified Acct'
        return

    if command == "get-token-code":
        forgot_url = getRestmailVerifyUrl(urlparse.urljoin(RESTMAILURL, emailUTF8))
        if not forgot_url:
            return
        token_code = urlparse.parse_qs(urlparse.urlparse(forgot_url).query)
        print token_code['token'][0], token_code['code'][0]
        return

    assert command in ("create", "login", "login-with-keys", "destroy",
                       "change-password")

    authPW, unwrapBKey = stretch(emailUTF8, passwordUTF8)

    if command == "create":
        r = FXA_POST("account/create",
                     {"email": emailUTF8,
                      "authPW": authPW.encode("hex")},
                     {"accept-language": acceptLang}
                     )
        print r
        print "Now use the 'curl' command from the server logs to verify"
        print "Or if you used restmail.net use the verify command"
        return

    if command == "destroy":
        r = FXA_POST("account/destroy",
                     {"email": emailUTF8,
                      "authPW": authPW.encode("hex"),
                      })
        print r
        return

    if command == "change-password":
        return changePassword(emailUTF8, passwordUTF8, newPasswordUTF8)

    assert command in ("login", "login-with-keys")
    getKeys = bool(command == "login-with-keys")

    r = FXA_POST("account/login?keys=true" if getKeys else "account/login",
                 {"email": emailUTF8,
                  "authPW": authPW.encode("hex"),
                  })
    uid = str(r["uid"])
    sessionToken = r["sessionToken"].decode("hex")
    printhex("sessionToken", sessionToken)
    if getKeys:
        keyFetchToken = r["keyFetchToken"].decode("hex")
        printhex("keyFetchToken", keyFetchToken)

    email_status = getEmailStatus(sessionToken)
    print "email status:", email_status
    if email_status and getKeys:
        kA,kB = fetchKeys(keyFetchToken, unwrapBKey)
        printhex("kA", kA)
        printhex("kB", kB)

    if email_status:
        # exercise /certificate/sign with a real RSA public key. jwcrypto in
        # the server demands that "n" be of a recognized length
        privkey, pubkey = createKeypair()
        # the server limits duration to <= 1 day
        cert = signCertificate(sessionToken, pubkey, 24*3600*1000)
        print "cert:", cert
        header, payload = dumpCert(cert)
        duration = payload["exp"]/1000.0 - time.time()
        print "expires in: %ds (%.1f hours, %.2f days)" % (
            duration, duration/3600, duration/86400)
        assert header["alg"] == "RS256"
        assert payload["principal"]["email"] == "%s@%s" % (uid, HOST)
        audience = "http://example.org"
        a = fxa_crypto.createBackedAssertion(cert, privkey, audience)
        print "backed assertion:", a
        res = fxa_crypto.verifyBackedAssertion(audience, a)
        print "verified:", res
    # exercise /session/destroy
    print "destroying session now"
    print destroySession(sessionToken)
    print "session destroyed, this getEmailStatus should fail:"
    # check that the session is really gone
    try:
        getEmailStatus(sessionToken)
    except WebError as e:
        assert e.r.status_code == 401
        print e.r.content
        print " good, session really destroyed"
    else:
        print "bad, session not destroyed"
        assert 0

parser = argparse.ArgumentParser()
parser.add_argument("-e", "--email", help="email address for the account")
parser.add_argument("-p", "--password", help="login password")
parser.add_argument("-l", "--lang", help="accept-language header value")
parser.add_argument("command", help="one of: repl, create, login[-with-keys], destroy, change-password, forgotpw-send, forgotpw-resend, forgotpw-submit, verify, get-token-code")
parser.add_argument("args", nargs=argparse.REMAINDER)

def main():
    args = parser.parse_args()
    emailUTF8 = args.email or "fxa-%s@restmail.net" % os.urandom(6).encode("hex")
    passwordUTF8 = args.password or os.urandom(2).encode("hex")
    acceptLang = args.lang or "en-us"

    if not args.email and not args.password:
        print "To access this account later, use this command:"
        print "fxa-client --email %s --password %s" % (emailUTF8, passwordUTF8)

    if args.command == "repl":
        linep = argparse.ArgumentParser()
        linep.add_argument("command", help="one of: quit, create, login[-with-keys], destroy, change-password, forgotpw-send, forgotpw-resend, forgotpw-submit, verify, get-token-code")
        linep.add_argument("args", nargs=argparse.REMAINDER)
        while True:
            try:
                line = raw_input("fxa> ")
            except EOFError:
                print
                break
            if line:
                args = linep.parse_args(line.split())
                if args.command == "quit":
                    break
                try:
                    command(args, emailUTF8, passwordUTF8, acceptLang)
                except UnknownCommand as e:
                    print e
                    linep.print_help()
        print "To access this account later, use this command:"
        print "fxa-client --email %s --password %s" % (emailUTF8, passwordUTF8)
    else:
        command(args, emailUTF8, passwordUTF8, acceptLang)


if __name__ == '__main__':
    main()

# exercised:
#  account/create
#  NO: account/devices (might not even be implemented)
#  account/keys
#  account/reset
#  account/destroy
#
#  account/login
#
#  session/destroy
#
#  recovery_email/status
#  NO: recovery_email/resend_code
#  NO: recovery_email/verify_code
#
#  certificate/sign
#
#  password/change/start
#  password/change/finish
#  password/forgot/send_code
#  password/forgot/resend_code
#  password/forgot/verify_code
#
#  NO: get_random_bytes
