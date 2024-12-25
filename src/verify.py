import hmac
import hashlib

def generate_hmac(data, secret_key):
    return hmac.new(secret_key, data, hashlib.sha256).hexdigest()

def verify_hmac(data, received_hmac, secret_key):
    calculated_hmac = generate_hmac(data, secret_key)
    return hmac.compare_digest(calculated_hmac, received_hmac)