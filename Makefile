
help: .help-setup
	@echo "run ./ve/bin/fxa-client repl"
	@echo " starts an interactive shell"
	@echo " (uses random restmail.net email+password)"
	@echo " (add --email EMAIL and --password PW to override)"
	@echo
	@echo "FxA account creation:"
	@echo " > create"
	@echo "  then for restmail.net accounts, use:"
	@echo " > verify"
	@echo "  or for non-restmail account, extract and load verification URL from server logs"
	@echo
	@echo "FxA account usage:"
	@echo "  > login"
	@echo "  > login-with-keys"
	@echo " change-password:"
	@echo "  > change-password newpw"
	@echo " forgot-password:"
	@echo "  > forgotpw-send"
	@echo "   then for restmail.net accounts, use:"
	@echo "    > get-token-code"
	@echo "  > forgotpw-resend token"
	@echo "  > forgotpw-submit token code"
	@echo " destroy-account:"
	@echo "  > destroy"
	@echo
	@echo "All commands can be run directly, e.g."
	@echo " ./ve/bin/fxa-client --email EMAIL --password PW create"

ve:
	virtualenv ve

# scrypt-0.6.1 has some sort of installation bug: if it gets installed as an
# install_requires= dependency, the _scrypt.so file doesn't get installed,
# and it can't be imported. If we install it with pip, it works. Note that
# scrypt is only needed for fxa-vectors (not fxa-client).
.setup: ve
	ve/bin/python setup.py develop
	ve/bin/pip install scrypt
	touch .setup .help-setup

.help-setup:
	@echo "run: make setup, then:"

vectors: .setup
	ve/bin/python bin/fxa-vectors

.PHONY: setup clean run
setup: .setup
run: .setup
	ve/bin/fxa-client repl
clean:
	rm -rf ve .setup .help-setup
