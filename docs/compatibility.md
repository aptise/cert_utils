# Certificate profiles and peer-socket compatibility

## Certificate names

Common Name behavior is profile-dependent, not universally an error.
Let's Encrypt's classic profile honors a requested CN that is also a DNS SAN.
When no CN is requested, the first DNS SAN is promoted to CN, unless it exceeds
64 characters. tlsserver and shortlived certificates omit the CN. Profile
availability is advertised in the ACME directory.

Reference: [Let's Encrypt profile documentation](https://letsencrypt.org/docs/profiles/).
The maintainer notes that orders/CSRs requesting a CN are rejected for the
non-classic profiles. This package should not impose classic's CN behavior on
other profiles, or apply a particular issuer's issuance rules to arbitrary X509
certificates. No CN insertion or profile enforcement was added in this change.

For valid classic certificates a CN is also in the SANs; for certificates with
no CN the existing helper falls through to SANs. The earlier audit's arbitrary
CN/SAN mismatch example therefore does not describe normal issuance under
these profiles. General-PKI certificates, IP identifiers and the distinction
between peer identity and chain validity remain separate contract questions;
profile rules alone do not define every X509 verification use case.

## Peer metadata

The package registers a public Requests response hook to extract the socket
peer and TLS certificate before Requests consumes the body and releases the
connection. At the time of this implementation urllib3 offers no equivalent
initial-socket hook for these details. Per the maintainer, an upstream API is
under discussion.

Until that exists, get_response_data deliberately probes historical Python,
Requests and urllib3 socket-storage layouts. This is an intentional
compatibility layer, not a recommendation to remove the public response hook
or replace it with post-consumption inspection. Tests exercise all five
layouts, TLS/plain sockets, missing peers and cached metadata. Preserve these
probes when changing request/session management.
