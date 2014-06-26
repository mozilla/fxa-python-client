
help: .help-deps
	@echo "COMMAND=./ve/bin/fxa-client --email EMAIL@restmail.net --password pw"
	@echo "FxA account creation:"
	@echo " \$$COMMAND create"
	@echo "  then for restmail.net accounts, use:"
	@echo "   \$$COMMAND verify"
	@echo "  or for non-restmail account, extract and load verification URL from server logs"
	@echo
	@echo "FxA account usage:"
	@echo "  \$$COMMAND login"
	@echo "  \$$COMMAND login-with-keys"
	@echo " change-password:"
	@echo "  \$$COMMAND change-password newpw"
	@echo " forgot-password:"
	@echo "  \$$COMMAND forgotpw-send"
	@echo "   then for restmail.net accounts, use:"
	@echo "    \$$COMMAND get-token-code"
	@echo "  \$$COMMAND forgotpw-resend token"
	@echo "  \$$COMMAND forgotpw-submit token code"

	@echo " destroy-account:"
	@echo "  \$$COMMAND destroy"

ve:
	virtualenv ve

.help-deps:
	@echo "run: make ve deps install, then:"

.deps: ve
	ve/bin/pip install scrypt
	ve/bin/pip install requests
	ve/bin/pip install PyHawk
	ve/bin/pip install argparse
	ve/bin/pip install cryptography
	ve/bin/pip install PyBrowserID
	touch .deps .help-deps
.PHONY: deps
deps: .deps

develop: ve .deps
	ve/bin/python setup.py develop

vectors: .deps
	ve/bin/fxa-vectors

.PHONY: clean
clean:
	rm -rf ve .deps .help-deps
