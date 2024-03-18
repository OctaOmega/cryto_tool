from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives.serialization import load_der_x509_certificate
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import NoEncryption
import pyjks

def load_key_and_certificates(pfx_file, pfx_password):
    with open(pfx_file, 'rb') as f:
        pfx_data = f.read()

    private_key = None
    cert = None
    cert_chain = []

    p12 = serialization.load_pem_private_key(pfx_data, password=pfx_password, backend=default_backend())

    for cert in p12.certificates:
        cert_chain.append(cert)
    
    private_key = p12
    
    return private_key, cert, cert_chain

def import_keypair_to_jks(pfx_file, pfx_password, jks_file, jks_password):
    private_key, cert, cert_chain = load_key_and_certificates(pfx_file, pfx_password.encode())

    alias = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    ks = pyjks.JavaKeyStore()
    ks.entries = {}
    
    ks.entries[alias] = pyjks.PrivateKeyEntry.new(alias, cert_chain, private_key)

    jks_data = ks.to_der(jks_password, 'JKS')

    with open(jks_file, 'wb') as f:
        f.write(jks_data)

    print("Key pair imported successfully to JKS keystore.")

pfx_file = 'example.pfx'
pfx_password = 'pfx_password'
jks_file = 'example.jks'
jks_password = 'jks_password'

import_keypair_to_jks(pfx_file, pfx_password, jks_file, jks_password)
