![Python package](https://github.com/jvanasco/cert_utils/workflows/Python%20package/badge.svg)

cert_utils
==========

**cert_utils** offers support for common operations when dealing with SSL
Certificates within the LetsEncrypt ecosystem.

This library was originally developed as a toolkit for bugfixing and
troubleshooting large ACME installations.

**cert_utils** will attempt to process operations with Python when possible.
If the required Python libraries are not installed, it will fallback to using
OpenSSL commandline via subprocesses.  **cert_utils** does a bit of work to
standardize certificate operations across versions of Python and OpenSSL that
do not share the same inputs, outputs or invocations.

**cert_utils** was formerly part of the
**[peter_sslers](https://github.com/aptise/peter_sslers)** ACME Client and
Certificate Management System, and has been descoped into it's own library.

This library *does not* process Certificates and Certificate Data itself.
Instead, it offers a simplified API to invoke other libraries and extract data
from Certificates.  It was designed for developers and system administrators to
more easily use the various libraries to accomplish specific tasks on the
commandline or as part of other projects.

Why does this exist?
--------------------

The [peter_sslers](https://github.com/aptise/peter_sslers) project was designed
to deploy on a wide variety of production servers that did not share common
Python and OpenSSL installations.  Earlier versions of the library
(within peter_sslers) supported both Python2.7 and Python3, as it was common to
encounter a machine that did not have Python3 installed.  Although it is still
common to find these machines, Python2.7 was dropped to take advantage of
typing.  Depending on the version of OpenSSL installed on a system,
**cert_utils** will invoke the binary or regex the output to bridge support
through a unified interface.
