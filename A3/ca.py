from concurrent.futures import ThreadPoolExecutor
import grpc
import time
import hashlib
import ca_pb2
import ca_pb2_grpc

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b%a,a)
    return (g, x - (b//a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x%m

def verify(message, signature, public_key):
    n, e = public_key
    hash_value = hashlib.sha256(message).digest()
    decrypted_signature = pow(signature, e, n)
    if int.to_bytes(decrypted_signature, len(hash_value), 'big') == hash_value:
        return True
    else:
        raise Exception("Signature verification failed")
    
from Crypto.Util import number

def generate_large_prime(bit_length):
    """Generate a large prime number of approximately bit_length using PyCryptodome."""
    # Generate a prime number of bit_length
    prime_num = number.getPrime(bit_length)
    return prime_num

def generate_rsa_keys(bits=2048):
    # Public exponent
    e = 65537  # A common choice for e

    # Generate two large primes p and q
    p = generate_large_prime(bits // 2)
    q = generate_large_prime(bits // 2)
    while p == q:  # Ensure p and q are distinct
        q = generate_large_prime(bits // 2)

    # Calculate n and phi(n)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Calculate the private exponent d
    d = modinv(e, phi)
    
    public_key = (n, e)
    private_key = (n, d)
    return private_key, public_key

class CertificateAuthority(ca_pb2_grpc.CertificateAuthorityService):
    def __init__(self):
        self.ca_id = "CA-1"
        self.clients = {}
        # Generate CA keys
        self.ca_private_key, self.ca_public_key = generate_rsa_keys(2048)

    def Register(self, request, context):
        client_id = request.clientId
        public_key = (request.n, request.e)
        self.clients[client_id] = public_key
        print(f"Client {client_id} registered")
        return ca_pb2.RegisterResponse(success=True)

    def RequestCertificate(self, request, context):
        client_id = request.clientId
        if client_id not in self.clients:
            print(f"Client {client_id} is not registered")
        current_time = int(time.time())
        # make duration = 300 seconds
        duration = 2
        certificate_data = {
            'id': client_id,
            'n': str(self.clients[client_id][0]),
            'e': str(self.clients[client_id][1]),
            'timestamp': current_time,
            'duration': duration,
            'caId': self.ca_id
        }

        # Sign the certificate data using CA's private key
        certificate_data_bytes = str(certificate_data).encode('utf-8')
        signature = sign(certificate_data_bytes, self.ca_private_key)
        print(f"Certificate of {certificate_data['id']} signed")
        return ca_pb2.Certificate(
            id=client_id,
            n=str(self.clients[client_id][0]),
            e=str(self.clients[client_id][1]),
            timestamp=current_time,
            duration=duration,
            caId=self.ca_id,
            signature=str(signature)
        )

    def VerifyCertificate(self, request, context):
        certificate = request.certificate
        # Verify the certificate
        # Implement certificate verification logic
        return ca_pb2.CertificateVerificationResponse(isValid=True)  # Placeholder response                        
    
    def RequestCAPublicKey(self, request, context):
        return ca_pb2.PublicKey(n=str(self.ca_public_key[0]), d=str(self.ca_public_key[1]))

def sign(message, private_key):
    n, d = private_key
    hash_value = int.from_bytes(hashlib.sha256(message).digest(), byteorder='big')
    signature = pow(hash_value, d, n)
    return signature

def serve():
    server = grpc.server(thread_pool=ThreadPoolExecutor(max_workers=10))
    ca_pb2_grpc.add_CertificateAuthorityServiceServicer_to_server(CertificateAuthority(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    print("Server is listening on port 50051...")
    server.wait_for_termination()

if __name__ == "__main__":
    serve()