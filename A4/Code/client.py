import grpc
import timestamp_service_pb2
import timestamp_service_pb2_grpc
import hashlib
import base64

# Function to calculate the hash of binary files (PDF or JPG)
def calculate_document_hash(file_path):
    with open(file_path, 'rb') as file:
        content = file.read()
        return hashlib.sha256(content).hexdigest()

# Load the CA certificate
with open('ca.crt', 'rb') as f:
    ca_certificate = f.read()

# Create client credentials using the CA certificate
client_credentials = grpc.ssl_channel_credentials(root_certificates=ca_certificate)

# Create a secure channel with client credentials
channel = grpc.secure_channel('localhost:50051', client_credentials)

# Create a stub (client)
stub = timestamp_service_pb2_grpc.TimestampServiceStub(channel)

# Example: Send hash of the PDF document to the server
pdf_path = "Report.pdf"
pdf_hash = calculate_document_hash(pdf_path)

# Example: Send hash of the JPG document to the server
jpg_path = "Report.jpg"
jpg_hash = calculate_document_hash(jpg_path)

# Creating and sending requests for both PDF and JPG
pdf_request = timestamp_service_pb2.DocumentRequest(document_content=pdf_hash)
jpg_request = timestamp_service_pb2.DocumentRequest(document_content=jpg_hash)

# Send the document hashes to the server and print out the responses
pdf_response = stub.StampDocument(pdf_request)
jpg_response = stub.StampDocument(jpg_request)

print(f"PDF Timestamp: {pdf_response.timestamp}\nPDF Signature: {pdf_response.signature}")
print(f"JPG Timestamp: {jpg_response.timestamp}\nJPG Signature: {jpg_response.signature}")

# Now sending these documents to the verifier - for verification
input("Press Enter to continue...")

import rsa
# Loading the RSA public key in the client
def load_public_key(filepath):
    with open(filepath, 'rb') as key_file:
        public_key = rsa.PublicKey.load_pkcs1(key_file.read())
    return public_key

client_public_key = load_public_key('verifier_public_key.pem')  # Assuming client will use the verifier's public key

# Assuming these imports and functions have already been defined:
import grpc
import timestamp_service_pb2
import timestamp_service_pb2_grpc
import verifier_pb2
import verifier_pb2_grpc
import hashlib

# Function to calculate the hash of binary files (PDF or JPG)
def calculate_document_hash(file_path):
    with open(file_path, 'rb') as file:
        content = file.read()
        return hashlib.sha256(content).hexdigest()

import grpc
import verifier_pb2
import verifier_pb2_grpc

# Function to read file data in binary
def read_file_binary(file_path):
    with open(file_path, 'rb') as file:
        return file.read()

# Setup the channel and stub for the verifier
verifier_channel = grpc.secure_channel('localhost:50052', client_credentials)
verifier_stub = verifier_pb2_grpc.VerificationServiceStub(verifier_channel)

# Read binary data of PDF and JPG
pdf_data = read_file_binary("Report.pdf")
jpg_data = read_file_binary("Report.jpg")

# Create verification requests
pdf_verification_request = verifier_pb2.VerificationRequest(
    document_data=pdf_data,
    file_type='pdf',
    timestamp=pdf_response.timestamp,  # Assuming pdf_response is from server interaction
    signature=pdf_response.signature
)

jpg_verification_request = verifier_pb2.VerificationRequest(
    document_data=jpg_data,
    file_type='jpg',
    timestamp=jpg_response.timestamp,  # Assuming jpg_response is from server interaction
    signature=jpg_response.signature
)

# Send the documents to the verifier
pdf_verification_response = verifier_stub.VerifyDocument(pdf_verification_request)
jpg_verification_response = verifier_stub.VerifyDocument(jpg_verification_request)

print(f"PDF Verification: {pdf_verification_response.message}")
print(f"JPG Verification: {jpg_verification_response.message}")

'''# Assuming verifier gRPC stub and channel have been correctly set up similar to timestamp_service
verifier_channel = grpc.secure_channel('localhost:50052', client_credentials)
verifier_stub = verifier_pb2_grpc.VerificationServiceStub(verifier_channel)

# Continuing with sending PDF and JPG file hashes for verification:
def send_for_verification(path, stub, timestamp, signature):
    doc_hash = calculate_document_hash(path)
    request = verifier_pb2.VerificationRequest(
        document_hash=doc_hash,
        timestamp=timestamp,
        signature=signature
    )
    response = stub.VerifyDocument(request)
    return response

# Using the responses from the timestamp service to verify documents
pdf_verification_response = send_for_verification(pdf_path, verifier_stub, pdf_response.timestamp, pdf_response.signature)
jpg_verification_response = send_for_verification(jpg_path, verifier_stub, jpg_response.timestamp, jpg_response.signature)

print(f"PDF Verification: {pdf_verification_response.message}")
print(f"JPG Verification: {jpg_verification_response.message}")'''