
help: .help-deps
	@echo "FxA account creation:"
	@echo " ./ve/bin/fxa-client create EMAIL@restmail.net pw"
	@echo "  then for restmail.net accounts, use:"
	@echo "   ./ve/bin/fxa-client verify EMAIL@restmail.net"
	@echo "  or for non-restmail account, extract and load verification URL from server logs"
	@echo
	@echo "FxA account usage:"
	@echo "  ./ve/bin/fxa-client login EMAIL@restmail.net pw"
	@echo "  ./ve/bin/fxa-client login-with-keys EMAIL@restmail.net pw"
	@echo " change-password:"
	@echo "  ./ve/bin/fxa-client change-password EMAIL@restmail.net pw newpw"
	@echo " forgot-password:"
	@echo "  ./ve/bin/fxa-client forgotpw-send EMAIL@restmail.net"
	@echo "  ./ve/bin/fxa-client forgotpw-resend EMAIL@restmail.net token"
	@echo "  ./ve/bin/fxa-client forgotpw-submit EMAIL@restmail.net token code newerpw"
	@echo " destroy-account:"
	@echo "  ./ve/bin/fxa-client destroy EMAIL@restmail.net newerpw"

ve:
	virtualenv ve

.help-deps:
	@echo "run: make ve deps install, then:"

.deps: ve
	ve/bin/pip install scrypt
	ve/bin/pip install requests
	ve/bin/pip install PyHawk
	touch .deps .help-deps
.PHONY: deps
deps: .deps

install: ve
	ve/bin/python setup.py install

vectors: .deps
	ve/bin/python picl-crypto.py
