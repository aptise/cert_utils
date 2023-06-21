![Python package](https://github.com/jvanasco/cert_utils/workflows/Python%20package/badge.svg)

cert_utils
==========

**cert_utils** offers support for common operations when dealing with SSL
Certificates within the LetsEncrypt ecosystem.

This library was originally developed as a toolkit for bugfixing and
troubleshooting large ACME installations.

**cert_utils** will attempt to process operations with Python when possible.
If the required Python libraries are not installed, it will fallback to using
OpenSSL commandline via subprocesses.

**cert_utils** was formerly part of the **peter_sslers** ACME Client and
Certificate Management System, and has been descoped into it's own library.