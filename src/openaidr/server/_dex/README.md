# Dex protocol messages

`api.proto` and `LICENSE` are copied without changes from
[Dex v2.45.1](https://github.com/dexidp/dex/tree/v2.45.1/api/v2).
`api_pb2.py` is generated with `grpcio-tools==1.78.0`:

```sh
python -m grpc_tools.protoc -I src \
  --python_out=src src/openaidr/server/_dex/api.proto
```

The broker helper uses only ListClients, GetClient, and CreateClient through gRPC's supported
generic client interface. The `broker` extra installs gRPC and a compatible
protobuf runtime. Tenant servers and sensors do not need gRPC.
