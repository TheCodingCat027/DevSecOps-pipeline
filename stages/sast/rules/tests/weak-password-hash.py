# Semgrep rule tests for devsecops-python-weak-hash-for-password
import hashlib
from hashlib import md5, sha1


def positives(password, pwd, user_password):
    # ruleid: devsecops-python-weak-hash-for-password
    h1 = hashlib.md5(password.encode()).hexdigest()

    # ruleid: devsecops-python-weak-hash-for-password
    h2 = hashlib.sha1(user_password.encode("utf-8")).hexdigest()

    # ruleid: devsecops-python-weak-hash-for-password
    h3 = hashlib.new("md5", pwd.encode())

    # ruleid: devsecops-python-weak-hash-for-password
    h4 = md5(password.encode()).hexdigest()

    # ruleid: devsecops-python-weak-hash-for-password
    h5 = sha1(password.encode()).hexdigest()

    # ruleid: devsecops-python-weak-hash-for-password
    h = hashlib.md5()
    h.update(password.encode())


def negatives(password, data, salt, blob):
    # checksum of non-password data is not this rule's concern
    # ok: devsecops-python-weak-hash-for-password
    a = hashlib.md5(data).hexdigest()

    # ok: devsecops-python-weak-hash-for-password
    b = hashlib.sha1(blob).hexdigest()

    # ok: devsecops-python-weak-hash-for-password
    c = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)

    # ok: devsecops-python-weak-hash-for-password
    d = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000)

    # ok: devsecops-python-weak-hash-for-password
    e = hashlib.sha256(data).hexdigest()

    # ok: devsecops-python-weak-hash-for-password
    h = hashlib.md5()
    h.update(data)
