# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: verifier.proto
# Protobuf Python Version: 4.25.0
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0everifier.proto\"e\n\x13VerificationRequest\x12\x15\n\rdocument_data\x18\x01 \x01(\x0c\x12\x11\n\tfile_type\x18\x02 \x01(\t\x12\x11\n\ttimestamp\x18\x03 \x01(\t\x12\x11\n\tsignature\x18\x04 \x01(\t\"<\n\x14VerificationResponse\x12\x13\n\x0bis_verified\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t2V\n\x13VerificationService\x12?\n\x0eVerifyDocument\x12\x14.VerificationRequest\x1a\x15.VerificationResponse\"\x00\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'verifier_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  DESCRIPTOR._options = None
  _globals['_VERIFICATIONREQUEST']._serialized_start=18
  _globals['_VERIFICATIONREQUEST']._serialized_end=119
  _globals['_VERIFICATIONRESPONSE']._serialized_start=121
  _globals['_VERIFICATIONRESPONSE']._serialized_end=181
  _globals['_VERIFICATIONSERVICE']._serialized_start=183
  _globals['_VERIFICATIONSERVICE']._serialized_end=269
# @@protoc_insertion_point(module_scope)
