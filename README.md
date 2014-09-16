fxa-python-client
=================

Python sample code to access Firefox Account (FxA) APIs, run by the server in
https://github.com/mozilla/fxa-auth-server . This is most useful for running
automated tests, and as supplemental documentation of the protocol.

To install this package you need a couple of prerequisites, the cryptography
module needs a C compiler and OpenSSL installed.

### Windows
* Microsoft Visual Studio 8, Express Edition: http://www.microsoft.com/en-us/download/details.aspx?id=40748
* Because python checks for the Visual Studio 8 by default point to the new Visual Studio installation:
  * SET VS90COMNTOOLS=%VS120COMNTOOLS%,
* Windows Developer Tools SDK: http://www.microsoft.com/en-us/download/confirmation.aspx?id=6510
  * During install make sure to check the option to update the system environment (for LIB and INCLUDE), otherwise set them manually afterwards
* OpenSSL, Developer Edition: https://slproweb.com/products/Win32OpenSSL.html
  * Update environment variables:
  * SET LIB=C:\OpenSSL-Win32\lib;C:\OpenSSL-Win32\lib\VC\static;%LIB%
  * SET INCLUDE=C:\OpenSSL-Win32\include;%INCLUDE%

### Linux (Ubuntu):
Open the terminal or any other package manager and install the following
packages:
```bash
sudo apt-get install build-essential libssl-dev libffi-dev python-dev
```

### Mac
* On OSX you need to install Xcode:
  * https://itunes.apple.com/us/app/xcode/id497799835?ls=1&mt=12

The source tree also contains a tool to create test vectors for the FxA auth
protocol.
For that you'll need an additional python package which needs to be installed
manually:
```bash
pip install -r requirements.txt
```