
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

.setup: ve
	ve/bin/python setup.py develop
	touch .setup .help-setup

.help-setup:
	@echo "run: make setup, then:"

vectors: .setup
	ve/bin/fxa-vectors

.PHONY: setup clean run

setup: .setup

run: .setup
	ve/bin/fxa-client repl

clean:
	rm -rf ve .setup .help-setup
