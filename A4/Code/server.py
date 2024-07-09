from concurrent import futures
import grpc
import timestamp_service_pb2
import timestamp_service_pb2_grpc
import hashlib
import rsa
import ntplib
from time import ctime
import requests
from datetime import datetime

# Load server's certificate and private key
with open('server.crt', 'rb') as f:
    server_certificate = f.read()
with open('server.key', 'rb') as f:
    server_private_key = f.read()

def generate_rsa_keys(key_size=2048):
    (public_key, private_key) = rsa.newkeys(key_size)
    with open('server_public_key.pem', 'wb') as pub_file:
        pub_file.write(public_key.save_pkcs1('PEM'))
    with open('server_private_key.pem', 'wb') as priv_file:
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

# Implementing the server-side logic
class TimestampServiceServicer(timestamp_service_pb2_grpc.TimestampServiceServicer):
    def __init__(self):
        # self.server_private_key = rsa.newkeys(512)[1]  # Simplified for example
        self.server_private_key = load_private_key('server_private_key.pem')

    def get_gmt_time(self):
        try:
            # Make a secure HTTPS request to the worldtimeapi
            response = requests.get('https://worldtimeapi.org/api/timezone/Etc/UTC')
            response.raise_for_status()  # Raise an error for bad status codes
            
            # Parse the response JSON and extract the datetime
            datetime_str = response.json()['datetime']
            # Convert the ISO 8601 datetime string to a datetime object
            datetime_obj = datetime.fromisoformat(datetime_str)
            
            # Convert the datetime object to a string in your preferred format
            gmt_time_str = datetime_obj.strftime('%Y-%m-%d %H:%M:%S')
            return gmt_time_str
        except requests.RequestException as e:
            print(f"Error fetching time: {e}")
            return None
        
    # An insecure alternative to the above function
    '''def get_gmt_time(self):
        ntp_client = ntplib.NTPClient()
        response = ntp_client.request('pool.ntp.org', version=3)
        return ctime(response.tx_time)'''

    def StampDocument(self, request, context):
        print("The server has received a document hash.")
        document_content = request.document_content
        timestamp = self.get_gmt_time()
        print(f"Timestamp received: {timestamp}")
        doc_hash = hashlib.sha256((document_content + timestamp).encode()).digest()
        signature = rsa.sign(doc_hash, self.server_private_key, 'SHA-256')
        print("The server has signed the document hash.")
        return timestamp_service_pb2.DocumentResponse(timestamp=timestamp, signature=signature.hex())
    
class PublicKeyService(timestamp_service_pb2_grpc.PublicKeyServiceServicer):
    def GetServerPublicKey(self, request, context):
        # Assuming the public key is stored in a PEM file
        with open('server_public_key.pem', 'rb') as key_file:
            public_key = key_file.read().decode('utf-8')
        return timestamp_service_pb2.PublicKeyResponse(public_key=public_key)

# Create a server credentials object
server_credentials = grpc.ssl_server_credentials(((server_private_key, server_certificate,),))

# Create a gRPC server
server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
timestamp_service_pb2_grpc.add_TimestampServiceServicer_to_server(TimestampServiceServicer(), server)
timestamp_service_pb2_grpc.add_PublicKeyServiceServicer_to_server(PublicKeyService(), server)

print('Starting server. Listening on port 50051.')
# Add secure port using server credentials
try:
    server.add_secure_port('[::]:50051', server_credentials)
    server.start()
    server.wait_for_termination()
except KeyboardInterrupt:
    print('Server has stopped.')