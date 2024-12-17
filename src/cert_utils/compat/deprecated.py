# local
from ..errors import OpenSslError


# ==============================================================================


def _cleanup_openssl_md5(data: bytes) -> str:
    """
    some versions of openssl handle the md5 as:
        '1231231231'
    others handle as
        "(stdin)= 123123'
    """
    data = data.strip()
    data_str = data.decode("utf8")
    if len(data_str) == 32 and (data_str[:9] != "(stdin)= "):
        return data_str
    if data_str[:9] != "(stdin)= " or not data_str:
        raise OpenSslError("error reading md5 (i)")
    data_str = data_str[9:]
    if len(data_str) != 32:
        raise OpenSslError("error reading md5 (ii)")
    return data_str
