class OpenSslError(Exception):
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
