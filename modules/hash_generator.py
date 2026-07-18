import hashlib


def generate_hashes(text):
    md5 = hashlib.md5(text.encode()).hexdigest()
    sha1 = hashlib.sha1(text.encode()).hexdigest()
    sha256 = hashlib.sha256(text.encode()).hexdigest()

    return {
        "MD5": md5,
        "SHA1": sha1,
        "SHA256": sha256,
    }