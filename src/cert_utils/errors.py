class CertUtilsError(Exception):
    """
    base class for Exceptions
    introduced for migration to Cryptography from OpenSSL backends
    """

    pass


class ToDo(CertUtilsError):
    # raised when this is something for us to do
    pass


class CryptographyError(CertUtilsError):
    pass


class OpenSslError(CertUtilsError):
    pass


class OpenSslError_CsrGeneration(OpenSslError):
    pass


class OpenSslError_InvalidKey(OpenSslError):
    pass


class OpenSslError_InvalidCSR(OpenSslError):
    pass


class OpenSslError_InvalidCertificate(OpenSslError):
    pass


class OpenSslError_VersionTooLow(OpenSslError):
    pass


class FallbackError(Exception):
    pass


class FallbackError_FilepathRequired(FallbackError):
    pass
