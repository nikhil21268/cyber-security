# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

import verifier_pb2 as verifier__pb2


class VerificationServiceStub(object):
    """Missing associated documentation comment in .proto file."""

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.VerifyDocument = channel.unary_unary(
                '/VerificationService/VerifyDocument',
                request_serializer=verifier__pb2.VerificationRequest.SerializeToString,
                response_deserializer=verifier__pb2.VerificationResponse.FromString,
                )


class VerificationServiceServicer(object):
    """Missing associated documentation comment in .proto file."""

    def VerifyDocument(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_VerificationServiceServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'VerifyDocument': grpc.unary_unary_rpc_method_handler(
                    servicer.VerifyDocument,
                    request_deserializer=verifier__pb2.VerificationRequest.FromString,
                    response_serializer=verifier__pb2.VerificationResponse.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'VerificationService', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class VerificationService(object):
    """Missing associated documentation comment in .proto file."""

    @staticmethod
    def VerifyDocument(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/VerificationService/VerifyDocument',
            verifier__pb2.VerificationRequest.SerializeToString,
            verifier__pb2.VerificationResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)