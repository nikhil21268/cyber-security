import grpc
import hashlib
import ca_pb2
import ca_pb2_grpc
from concurrent.futures import ThreadPoolExecutor
import threading
import time

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

class Client(ca_pb2_grpc.CertificateAuthorityService):
    def __init__(self, client_id):
        self.client_id = client_id
        self.private_key, self.public_key = generate_rsa_keys(2048)

        self.publicKeyOfOtherClient = (-1, -1)

    def setPublicKeyOfOtherClient(self, publicKey):
        self.publicKeyOfOtherClient = publicKey

def verify(message, signature, public_key):
    n, e = public_key
    hash_value = int.from_bytes(hashlib.sha256(message).digest(), byteorder='big')
    decrypted_signature = pow(signature, e, n)
    return decrypted_signature == hash_value

def encrypt(message, public_key):
    n, e = public_key
    # Convert the message to an integer
    message_int = int.from_bytes(message.encode('utf-8'), byteorder='big')
    # Encrypt the message
    encrypted_message = pow(message_int, e, n)
    return encrypted_message

def decrypt(encrypted_message, private_key):
    n, d = private_key
    # Decrypt the message
    decrypted_message_int = pow(encrypted_message, d, n)
    # Convert the decrypted integer back to bytes, then decode to a string
    decrypted_message_bytes = decrypted_message_int.to_bytes((decrypted_message_int.bit_length() + 7) // 8, byteorder='big')
    decrypted_message = decrypted_message_bytes.decode('utf-8')
    return decrypted_message

def monitor_certificates(certificate, check_interval=2):
    while True:
        if not is_certificate_valid(certificate):
            break
            # Handle expiration (e.g., notify, renew, etc.)
        time.sleep(check_interval)  # Wait before the next check

def is_certificate_valid(certificate):
    current_time = int(time.time())
    issue_time = certificate['timestamp']
    valid_duration = certificate['duration']
    expiration_time = issue_time + valid_duration
    return current_time <= expiration_time

def serve():
    '''server = grpc.server(thread_pool=ThreadPoolExecutor(max_workers=10))
    client_a = Client("A")
    ca_pb2_grpc.add_CertificateAuthorityServiceServicer_to_server(client_a, server)
    server.add_insecure_port('[::]:50052')
    server.start()
    print("Server is listening on port 50052...")'''

    client_a = Client("A")

    # Create a gRPC channel and stub to communicate with the CA server
    channel = grpc.insecure_channel('localhost:50051')
    stub = ca_pb2_grpc.CertificateAuthorityServiceStub(channel)

    # Ask public key from CA
    response = stub.RequestCAPublicKey(ca_pb2.PublicKeyRequest(clientId=client_a.client_id))
    if response:
        client_a.ca_public_key = (int(response.n), int(response.d))
    else:
        print("Failed to get CA public key")

    # Register client A with the CA server
    regResponse = stub.Register(ca_pb2.RegisterRequest(clientId=client_a.client_id, n=str(client_a.public_key[0]), e=str(client_a.public_key[1])))
    if regResponse:
        print("Client A registered successfully")
        print()
    else:
        print("Failed to register client A")

    input("Register client B with the CA server and press Enter to continue")

    # Request certificate of B from the CA server
    message = "CA_B"
    client_id = message[3:]
    response = stub.RequestCertificate(ca_pb2.CertificateRequest(clientId=client_id))
    if response:
        print("Received certificate of B from CA server")
        print()
    else:
        print("Couldn't get certificate of B from CA server")

    # Verify the certificate using CA's public key
    certificate_data = {
            'id': response.id,
            'n': response.n,
            'e': response.e,
            'timestamp': response.timestamp,
            'duration': response.duration,
            'caId': response.caId
        }
    
    message = str(certificate_data).encode('utf-8')
    receivedSignature = int(response.signature)
    thread = None
    if verify(message, int(receivedSignature), client_a.ca_public_key):
        print("Certificate verified")
        # Start the background thread for monitoring certificates
        thread = threading.Thread(target=monitor_certificates, args=(certificate_data, certificate_data['duration']))
        thread.daemon = True  # Optional: make the thread a daemon thread
        thread.start()
        client_a.setPublicKeyOfOtherClient((int(response.n), int(response.e)))
        print()
    else:
        print("Invalid certificate")

    input("Press Enter to send encrypted message from A to B")

    # Now, send encrypted message from A to B
    encrypted_messages = ["hello1", "hello2", "hello3"]

    # Create a gRPC channel and stub to communicate with the B
    channelB = grpc.insecure_channel('localhost:50053')
    stubB = ca_pb2_grpc.MessageExchangeServiceStub(channelB)
    for message in encrypted_messages:
        # Check if the thread is alive
        if thread.is_alive():
            print("Certificate of B is still active.")
        else:
            print("The Certificate of B has expired. Exiting...")
            break
        # encrypt message using B's public key
        encrypted_message = encrypt(message, client_a.publicKeyOfOtherClient)
        encrypted_response = stubB.ReceiveEncryptedMessage(ca_pb2.EncryptedMessage(message=str(encrypted_message)))
        if encrypted_response.response == "messedUp":
            print("Sorry, cannot process request due to Certificate Expiry")
            break
        # decrypt the encrypted_response received from B
        decrypted_response = decrypt(int(encrypted_response.response), client_a.private_key)
        print(f"Decrypted Response: {decrypted_response}")

    # server.wait_for_termination()

if __name__ == '__main__':
    serve()