# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

import timestamp_service_pb2 as timestamp__service__pb2


class TimestampServiceStub(object):
    """The timestamp service definition.
    """

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.StampDocument = channel.unary_unary(
                '/TimestampService/StampDocument',
                request_serializer=timestamp__service__pb2.DocumentRequest.SerializeToString,
                response_deserializer=timestamp__service__pb2.DocumentResponse.FromString,
                )


class TimestampServiceServicer(object):
    """The timestamp service definition.
    """

    def StampDocument(self, request, context):
        """Sends a document to the server and receives a timestamp and signature.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_TimestampServiceServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'StampDocument': grpc.unary_unary_rpc_method_handler(
                    servicer.StampDocument,
                    request_deserializer=timestamp__service__pb2.DocumentRequest.FromString,
                    response_serializer=timestamp__service__pb2.DocumentResponse.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'TimestampService', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class TimestampService(object):
    """The timestamp service definition.
    """

    @staticmethod
    def StampDocument(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/TimestampService/StampDocument',
            timestamp__service__pb2.DocumentRequest.SerializeToString,
            timestamp__service__pb2.DocumentResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)


class PublicKeyServiceStub(object):
    """Missing associated documentation comment in .proto file."""

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.GetServerPublicKey = channel.unary_unary(
                '/PublicKeyService/GetServerPublicKey',
                request_serializer=timestamp__service__pb2.Empty.SerializeToString,
                response_deserializer=timestamp__service__pb2.PublicKeyResponse.FromString,
                )


class PublicKeyServiceServicer(object):
    """Missing associated documentation comment in .proto file."""

    def GetServerPublicKey(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_PublicKeyServiceServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'GetServerPublicKey': grpc.unary_unary_rpc_method_handler(
                    servicer.GetServerPublicKey,
                    request_deserializer=timestamp__service__pb2.Empty.FromString,
                    response_serializer=timestamp__service__pb2.PublicKeyResponse.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'PublicKeyService', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class PublicKeyService(object):
    """Missing associated documentation comment in .proto file."""

    @staticmethod
    def GetServerPublicKey(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/PublicKeyService/GetServerPublicKey',
            timestamp__service__pb2.Empty.SerializeToString,
            timestamp__service__pb2.PublicKeyResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)
