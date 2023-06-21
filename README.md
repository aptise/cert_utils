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

**cert_utils** was formerly part of the **[peter_sslers](https://github.com/aptise/peter_sslers)** ACME Client and
Certificate Management System, and has been descoped into it's own library.

This library *does not* process Certificates and Certificate Data itself.
Instead, it offers a simplified API to invoke other libraries and extract data
from Certificates.  It was designed for developers and system administrators to
more easily use the various libraries to accomplish specific tasks on the
commandline or as part of other projects.



