from OpenSSL import crypto
import os

def create_key_pair(type, bits):
    """
    Create a public/private key pair.
    """
    pkey = crypto.PKey()
    pkey.generate_key(type, bits)
    return pkey

def create_cert_request(pkey, subject, digest="sha256"):
    """
    Create a certificate request.
    """
    req = crypto.X509Req()
    req.get_subject().CN = subject
    req.set_pubkey(pkey)
    req.sign(pkey, digest)
    return req

def create_certificate(req, issuer_cert, issuer_key, serial, validity_period, digest="sha256"):
    """
    Generate a certificate given a certificate request.
    """
    cert = crypto.X509()
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(validity_period)
    cert.set_issuer(issuer_cert.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.sign(issuer_key, digest)
    return cert

def save_certificate(file_name, cert):
    """
    Save the certificate to a file.
    """
    with open(file_name, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

def save_private_key(file_name, pkey):
    """
    Save the private key to a file.
    """
    with open(file_name, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))

# Generate CA
ca_key = create_key_pair(crypto.TYPE_RSA, 4096)
ca_req = create_cert_request(ca_key, "Example CA")
ca_cert = create_certificate(ca_req, ca_req, ca_key, 0, 365*24*60*60)

# Save CA
save_certificate("ca.crt", ca_cert)
save_private_key("ca.key", ca_key)

# Generate server certificate
server_key = create_key_pair(crypto.TYPE_RSA, 4096)
server_req = create_cert_request(server_key, "localhost")
server_cert = create_certificate(server_req, ca_cert, ca_key, 1, 365*24*60*60)

# Save server certificate
save_certificate("server.crt", server_cert)
save_private_key("server.key", server_key)

# Generate server certificate
verifier_key = create_key_pair(crypto.TYPE_RSA, 4096)
verifier_req = create_cert_request(verifier_key, "localhost")
verifier_key_cert = create_certificate(verifier_req, ca_cert, ca_key, 1, 365*24*60*60)

# Save server certificate
save_certificate("verifier.crt", server_cert)
save_private_key("verifier.key", server_key)