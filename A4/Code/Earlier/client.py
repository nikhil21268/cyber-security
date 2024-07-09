# Earlier approach based on strings - not PDFs or JPGs
'''import grpc
import timestamp_service_pb2
import timestamp_service_pb2_grpc
import hashlib

# Function to calculate the hash of the document
def calculate_document_hash(document_content):
    return hashlib.sha256(document_content.encode()).hexdigest()

# Load the CA certificate
with open('ca.crt', 'rb') as f:
    ca_certificate = f.read()

# Create client credentials using the CA certificate
client_credentials = grpc.ssl_channel_credentials(root_certificates=ca_certificate)

# Create a secure channel with client credentials
channel = grpc.secure_channel('localhost:50051', client_credentials)

# Create a stub (client)
stub = timestamp_service_pb2_grpc.TimestampServiceStub(channel)

# Send hash of the document to the server (only the hash is sent, not the document itself)
document_content = "Your document content here"
document_hash = calculate_document_hash(document_content)
document_request = timestamp_service_pb2.DocumentRequest(document_content=document_hash)

# Send the document to the server and print out the response
response = stub.StampDocument(document_request)
print(f"Timestamp: {response.timestamp}\nSignature: {response.signature}")'''