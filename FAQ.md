FAQ
===

#### Why do functions accept a `{type}_pem` and optional `{type_}_pem_filepath`
argument?

The library was designed to expect PEM data and use Python whenever possible.

In order to support a fallback onto OpenSSL on the commandline, the PEM data
needs to be written to a
[tempfile.NamedTemporaryFile](https://docs.python.org/3/library/tempfile.html#tempfile.NamedTemporaryFile)
on the filesystem. Several operations may need to do this repeatedly or
recursively to the same data, so support was given to minimize the creation of
tempfiles and minimize disk i/o.

The library tries to create and use these files as needed from PEM data.
Unfortunately, not all functions will generate these files as needed and will
raise a `FallbackError_FilepathRequired` exception if the data is needed.


#### Compatability with earlier Python versions

Python 3.6 has the following issue:

* the last compatibile version of acme is 1.23.0 
* acme 1.23.0 does not pin the pyopenssl version
* pip/etc may attempt to install an incompatible pyopenssl version
 * 23.2.0 will fail due to an invalid call by certbot
 * 23.1.0 has a bug that potentially affects this package

This package will attempt to install compatible versions for tests, but does not
do anything for regular installs, as it will fallback on OpenSSL commandline.