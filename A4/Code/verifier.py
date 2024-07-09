import grpc
from concurrent import futures
import verifier_pb2
import verifier_pb2_grpc
import timestamp_service_pb2
import timestamp_service_pb2_grpc
import rsa
import hashlib

import rsa

def generate_rsa_keys(key_size=2048):
    (public_key, private_key) = rsa.newkeys(key_size)
    with open('verifier_public_key.pem', 'wb') as pub_file:
        pub_file.write(public_key.save_pkcs1('PEM'))
    with open('verifier_private_key.pem', 'wb') as priv_file:
        priv_file.write(private_key.save_pkcs1('PEM'))

generate_rsa_keys()

# Loading the RSA private key in the verifier
def load_private_key(filepath):
    with open(filepath, 'rb') as key_file:
        private_key = rsa.PrivateKey.load_pkcs1(key_file.read())
    return private_key

# Loading the RSA public key in the client
def load_public_key(filepath):
    with open(filepath, 'rb') as key_file:
        public_key = rsa.PublicKey.load_pkcs1(key_file.read())
    return public_key

# Example of loading keys
verifier_private_key = load_private_key('verifier_private_key.pem')


import os

class VerificationService(verifier_pb2_grpc.VerificationServiceServicer):
    def VerifyDocument(self, request, context):
        # Extract bytes from the request
        print("Received a document verification request.")
        document_bytes = request.document_data
        
        # Assume some method to determine the file type or it can be included in the request
        file_type = request.file_type  # 'pdf' or 'jpg'
        
        # Define the output file path
        output_path = f'received_document.{file_type}'
        
        # Save the document
        with open(output_path, 'wb') as file:
            file.write(document_bytes)

        # Extract and possibly recompute the hash for verification
        doc_hash = hashlib.sha256(request.document_data).hexdigest()  # Example of recomputing hash
        document_hash = hashlib.sha256((doc_hash + request.timestamp).encode()).digest()
        signature = bytes.fromhex(request.signature)
        print("Verifying the document.")
        try:
            rsa.verify(document_hash, signature, server_public_key)
            print("Verification successful: The document is authentic.")
            return verifier_pb2.VerificationResponse(is_verified=True, message="Verification successful: The document is authentic.")
        except rsa.VerificationError:
            print("Verification failed: The document's integrity is compromised.")
            return verifier_pb2.VerificationResponse(is_verified=False, message="Verification failed: The document's integrity is compromised.")
        

'''class VerificationService(verifier_pb2_grpc.VerificationServiceServicer):

    def VerifyDocument(self, request, context):
        # Extract and possibly recompute the hash for verification
        doc_hash = hashlib.sha256(request.document_data).hexdigest()  # Example of recomputing hash
        print("here\n")
        document_hash = hashlib.sha256((doc_hash + request.timestamp).encode()).digest()
        signature = bytes.fromhex(request.signature)

        try:
            rsa.verify(document_hash, signature, server_public_key)
            return verifier_pb2.VerificationResponse(is_verified=True, message="Verification successful: The document is authentic.")
        except rsa.VerificationError:
            return verifier_pb2.VerificationResponse(is_verified=False, message="Verification failed: The document's integrity is compromised.")'''

'''class VerificationService(verifier_pb2_grpc.VerificationServiceServicer):

    def VerifyDocument(self, request, context):
        signature = bytes.fromhex(request.signature)
        doc_hash = hashlib.sha256((request.document_hash + request.timestamp).encode()).digest()
        try:
            rsa.verify(doc_hash, signature, server_public_key)
            return verifier_pb2.VerificationResponse(is_verified=True, message="Verification successful: The document is authentic.")
        except rsa.VerificationError:
            return verifier_pb2.VerificationResponse(is_verified=False, message="Verification failed: The document's integrity is compromised.")'''

def serve():
    # Load server's certificate and private key
    with open('verifier.crt', 'rb') as f:
        server_certificate = f.read()
    with open('verifier.key', 'rb') as f:
        server_private_key = f.read()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    verifier_pb2_grpc.add_VerificationServiceServicer_to_server(VerificationService(), server)
    server_credentials = grpc.ssl_server_credentials(((server_private_key, server_certificate,),))
    server.add_secure_port('[::]:50052', server_credentials)
    server.start()
    print("Third party server started on port 50052")
    server.wait_for_termination()

def get_server_public_key():
    # Load the CA certificate
    with open('ca.crt', 'rb') as f:
        ca_certificate = f.read()
    # Create client credentials using the CA certificate
    client_credentials = grpc.ssl_channel_credentials(root_certificates=ca_certificate)
    channel = grpc.secure_channel('localhost:50051', client_credentials)
    stub = timestamp_service_pb2_grpc.PublicKeyServiceStub(channel)
    response = stub.GetServerPublicKey(timestamp_service_pb2.Empty())
    return response.public_key

if __name__ == "__main__":
    server_public_key_pem = get_server_public_key()
    server_public_key = rsa.PublicKey.load_pkcs1(server_public_key_pem.encode('utf-8'))
    # Proceed with verification or other tasks using the public key
    try:
        serve()
    except KeyboardInterrupt:
        print("Verifier stopped.")

'''if __name__ == "__main__":
    # Load or define the server's public key
    server_public_key = load_public_key('server_public_key.pem')
    serve()'''