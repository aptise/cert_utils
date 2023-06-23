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