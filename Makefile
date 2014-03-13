
help: .help-deps
	@echo "FxA account creation:"
	@echo " ./ve/bin/fxa-client create email@example.org pw"
	@echo "  (and click verification email link)"
	@echo
	@echo "FxA account usage:"
	@echo "  ./ve/bin/fxa-client login email@example.org pw"
	@echo "  ./ve/bin/fxa-client login-with-keys email@example.org pw"
	@echo " change-password:"
	@echo "  ./ve/bin/fxa-client change-password email@example.org pw newpw"
	@echo " forgot-password:"
	@echo "  ./ve/bin/fxa-client forgotpw-send email@example.org"
	@echo "  ./ve/bin/fxa-client forgotpw-resend email@example.org token"
	@echo "  ./ve/bin/fxa-client forgotpw-submit email@example.org token code newerpw"
	@echo " destroy-account:"
	@echo "  ./ve/bin/fxa-client destroy email@example.org newerpw"

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
