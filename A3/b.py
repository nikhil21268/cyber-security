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

class MessageExchangeService(ca_pb2_grpc.MessageExchangeServiceServicer):
    def __init__(self, private_key, public_keyOfOtherClient, certA):
        self.private_key = private_key
        self.publicKeyOfOtherClient = public_keyOfOtherClient
        self.certA = certA
        self.duration = certA['duration']

        # Start the background thread for monitoring certificates
        self.thread = threading.Thread(target=monitor_certificates, args=(self.certA, self.duration))
        self.thread.daemon = True  # Optional: make the thread a daemon thread
        self.thread.start()

    def ReceiveEncryptedMessage(self, request, context):
        # Decrypt the message using B's private key
        decrypted_message = decrypt(int(request.message), self.private_key)
        print(f"Decrypted message received: {decrypted_message}")
        # Send an acknowledgement (optional)
        ack = ""
        if decrypted_message == "hello1":
            ack = "acked1"
        elif decrypted_message == "hello2":
            ack = "acked2"
        elif decrypted_message == "hello3":
            ack = "acked3"
        # encrypt the ack
        ack_encrypted = encrypt(ack, self.publicKeyOfOtherClient)
        # Check if the thread is alive
        if self.thread.is_alive():
            print("Certificate of B is still active.")
        else:
            print("The Certificate of B has expired. Exiting...")
            return ca_pb2.Acknowledgement(response=str("messedUp"))
        return ca_pb2.Acknowledgement(response=str(ack_encrypted))

class Client:
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
    client_b = Client("B")
    ca_pb2_grpc.add_CertificateAuthorityServiceServicer_to_server(client_b, server)
    server.add_insecure_port('[::]:50053')
    server.start()
    print("Server is listening on port 50053...")'''

    client_b = Client("B")

    # Create a gRPC channel and stub to communicate with the CA server
    channel = grpc.insecure_channel('localhost:50051')
    stub = ca_pb2_grpc.CertificateAuthorityServiceStub(channel)

    # Ask public key from CA
    response = stub.RequestCAPublicKey(ca_pb2.PublicKeyRequest(clientId=client_b.client_id))
    if response:
        client_b.ca_public_key = (int(response.n), int(response.d))
    else:
        print("Failed to get CA public key")

    # Register client B with the CA server
    regResponse = stub.Register(ca_pb2.RegisterRequest(clientId=client_b.client_id, n=str(client_b.public_key[0]), e=str(client_b.public_key[1])))
    if regResponse:
        print("Client B registered successfully")
        print()
    else:
        print("Failed to register client B")

    input("Register client A with the CA server and press Enter to continue")

    # Request certificate of A from the CA server
    message = "CA_A"
    client_id = message[3:]
    response = stub.RequestCertificate(ca_pb2.CertificateRequest(clientId=client_id))
    if response:
        print("Received certificate of A from CA server")
        print()
    else:
        print("Couldn't get certificate of A from CA server")

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
    if verify(message, int(receivedSignature), client_b.ca_public_key):
        print("Certificate verified")
        client_b.setPublicKeyOfOtherClient((int(response.n), int(response.e)))
        print()
    else:
        print("Invalid certificate")
        return

    server = grpc.server(ThreadPoolExecutor(max_workers=10))
    b_private_key = client_b.private_key
    # Add the MessageExchangeService to the server
    ca_pb2_grpc.add_MessageExchangeServiceServicer_to_server(MessageExchangeService(b_private_key, client_b.publicKeyOfOtherClient, certificate_data), server)
    server.add_insecure_port('[::]:50053')
    server.start()
    print("Server B is listening on port 50053...")

    server.wait_for_termination()

if __name__ == '__main__':
    serve()