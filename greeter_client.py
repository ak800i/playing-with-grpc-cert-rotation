from concurrent import futures
import collections
import logging
import time

import threading
import grpc
import sys

import helloworld_pb2
import helloworld_pb2_grpc

import resources

_ONE_DAY_IN_SECONDS = 60 * 60 * 24

CA_1_PEM = resources.cert_hier_1_root_ca_cert()
CA_2_PEM = resources.cert_hier_2_root_ca_cert()
CA_BOTH_PEM = resources.cert_hier_both_root_ca_certs()

CLIENT_KEY_1_PEM = resources.cert_hier_1_client_1_key()
CLIENT_CERT_CHAIN_1_PEM = (resources.cert_hier_1_client_1_cert() +
                           resources.cert_hier_1_intermediate_ca_cert())

CLIENT_KEY_2_PEM = resources.cert_hier_2_client_1_key()
CLIENT_CERT_CHAIN_2_PEM = (resources.cert_hier_2_client_1_cert() +
                           resources.cert_hier_2_intermediate_ca_cert())

SERVER_KEY_1_PEM = resources.cert_hier_1_server_1_key()
SERVER_CERT_CHAIN_1_PEM = (resources.cert_hier_1_server_1_cert() +
                           resources.cert_hier_1_intermediate_ca_cert())

SERVER_KEY_2_PEM = resources.cert_hier_2_server_1_key()
SERVER_CERT_CHAIN_2_PEM = (resources.cert_hier_2_server_1_cert() +
                           resources.cert_hier_2_intermediate_ca_cert())

port = 50051


def _create_channel(port, credentials):
    return grpc.secure_channel('localhost:{}'.format(port), credentials)


def _create_client_stub(channel, expect_success):
    if expect_success:
        grpc.channel_ready_future(channel).result(timeout=2)
    return helloworld_pb2_grpc.GreeterStub(channel)


def _perform_rpc(client_stub, message=None):
    # we don't care about the actual response of the rpc; only
    # whether we can perform it or not, and if not, the status
    # code must be UNAVAILABLE
    request = helloworld_pb2.HelloRequest(name=message)
    response = client_stub.SayHello(request)
    print("Greeter client received: " + response.message)


def _do_one_shot_client_rpc(expect_success,
                            root_certificates=None,
                            private_key=None,
                            certificate_chain=None,
                            message=None):
    credentials = grpc.ssl_channel_credentials(
        root_certificates=root_certificates,
        private_key=private_key,
        certificate_chain=certificate_chain)
    with _create_channel(port, credentials) as client_channel:
        client_stub = _create_client_stub(client_channel, expect_success)
        _perform_rpc(client_stub, message)


def main():
    global port

    '''
    Should succeed. Initial cert configuration.
    '''
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_1_PEM,
                            private_key=CLIENT_KEY_2_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_2_PEM,
                            message="root1, pk2, crt2")

    '''
    Should succeed again.
    '''
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_1_PEM,
                            private_key=CLIENT_KEY_2_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_2_PEM,
                            message="root1, pk2, crt2")
        
    '''
    Should succeed yet again.
    '''
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_1_PEM,
                            private_key=CLIENT_KEY_2_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_2_PEM,
                            message="root1, pk2, crt2")
    
    print("This should fail server-side [root1, pk1, crt1]:")
    try:
        _do_one_shot_client_rpc(True,
                                root_certificates=CA_1_PEM,
                                private_key=CLIENT_KEY_1_PEM,
                                certificate_chain=CLIENT_CERT_CHAIN_1_PEM,
                                message="unexpected success root1, pk1, crt1")
    except:
        print("^This did fail server-side [root1, pk1, crt1]")

    '''
    Should succeed again after previous bad config.
    '''
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_1_PEM,
                            private_key=CLIENT_KEY_2_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_2_PEM,
                            message="root1, pk2, crt2")

    '''
    Create and verify persistant channel A and stub.
    '''
    channel_A = _create_channel(
        port,
        grpc.ssl_channel_credentials(
            root_certificates=CA_1_PEM,
            private_key=CLIENT_KEY_2_PEM,
            certificate_chain=CLIENT_CERT_CHAIN_2_PEM))
    persistent_client_stub_A = _create_client_stub(channel_A, True)
    _perform_rpc(persistent_client_stub_A, message="channelA: root1, pk2, crt2")

    '''
    Create and verify persistant channel B and stub.
    '''
    channel_B = _create_channel(
        port,
        grpc.ssl_channel_credentials(
            root_certificates=CA_1_PEM,
            private_key=CLIENT_KEY_2_PEM,
            certificate_chain=CLIENT_CERT_CHAIN_2_PEM))
    persistent_client_stub_B = _create_client_stub(channel_B, True)
    _perform_rpc(persistent_client_stub_B, message="channelB: root1, pk2, crt2")

    try:
        while True:
            print("sleeping... please change certs before continuing")
            time.sleep(_ONE_DAY_IN_SECONDS)
    except KeyboardInterrupt:
        asd = 'wtf'


    '''
    Should succeed. Client using both certs for server auth and new certs for signing.
    '''
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_BOTH_PEM,
                            private_key=CLIENT_KEY_1_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_1_PEM,
                            message="(root1 and root2), pk1, crt1")

    '''
    Should succeed. Client using both certs for server auth and OLD certs for signing.
    '''
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_BOTH_PEM,
                            private_key=CLIENT_KEY_2_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_2_PEM,
                            message="(root1 and root2), pk2, crt2")
    
    print("This should fail client-side [root2, pk1, crt1]:")
    try:
        _do_one_shot_client_rpc(True,
                                root_certificates=CA_2_PEM,
                                private_key=CLIENT_KEY_1_PEM,
                                certificate_chain=CLIENT_CERT_CHAIN_1_PEM,
                                message="unexpected success [root2, pk1, crt1]")
    except:
        print("^This did fail client-side [root2, pk1, crt1]")
        
    '''
    Should succeed. Client using both certs for server auth and NEW certs for signing.
    '''
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_BOTH_PEM,
                            private_key=CLIENT_KEY_1_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_1_PEM,
                            message="(root1 and root2), pk1, crt1")
    
    '''
    Persistant channel A should still work.
    '''
    _perform_rpc(persistent_client_stub_A, message="channelA: root1, pk2, crt2")
    
    '''
    Persistant channel B should still work.
    '''
    _perform_rpc(persistent_client_stub_B, message="channelB: root1, pk2, crt2")

    try:
        while True:
            print("sleeping... please change certs before continuing")
            time.sleep(_ONE_DAY_IN_SECONDS)
    except KeyboardInterrupt:
        asd = 'wtf'
        
    '''
    Should succeed. Client using both certs for server auth and new certs for signing.
    '''
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_BOTH_PEM,
                            private_key=CLIENT_KEY_1_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_1_PEM,
                            message="(root1 and root2), pk1, crt1")
        
    '''
    Should succeed. Client using new certs for server auth and new certs for signing.
    '''
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_2_PEM,
                            private_key=CLIENT_KEY_1_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_1_PEM,
                            message="root2, pk1, crt1")
    
    print("This should fail client-side [root1, pk1, crt1]:")
    try:
        _do_one_shot_client_rpc(True,
                                root_certificates=CA_1_PEM,
                                private_key=CLIENT_KEY_1_PEM,
                                certificate_chain=CLIENT_CERT_CHAIN_1_PEM,
                                message="unexpected success [root1, pk1, crt1]")
    except:
        print("^This did fail client-side [root1, pk1, crt1]")
        
    '''
    Should succeed. Client using both certs for server auth and new certs for signing.
    '''
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_BOTH_PEM,
                            private_key=CLIENT_KEY_1_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_1_PEM,
                            message="(root1 and root2), pk1, crt1")

    '''
    Should succeed. Client using new certs for server auth and new certs for signing.
    '''
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_2_PEM,
                            private_key=CLIENT_KEY_1_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_1_PEM,
                            message="root2, pk1, crt1")
    
    '''
    Persistant channel A should still work.
    '''
    _perform_rpc(persistent_client_stub_A, message="channelA: root1, pk2, crt2")
    
    '''
    Persistant channel B should still work.
    '''
    _perform_rpc(persistent_client_stub_B, message="channelB: root1, pk2, crt2")

    try:
        while True:
            print("sleeping... please change certs before continuing")
            time.sleep(_ONE_DAY_IN_SECONDS)
    except KeyboardInterrupt:
        asd = 'wtf'

    '''
    Should succeed. Client using new certs for server auth and new certs for signing.
    '''
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_2_PEM,
                            private_key=CLIENT_KEY_1_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_1_PEM,
                            message="root2, pk1, crt1")

    print("This should fail server-side [root2, pk2, crt2]:")
    try:
        _do_one_shot_client_rpc(True,
                                root_certificates=CA_2_PEM,
                                private_key=CLIENT_KEY_2_PEM,
                                certificate_chain=CLIENT_CERT_CHAIN_2_PEM,
                                message="unexpected success [root2, pk2, crt2]")
    except:
        print("^This did fail server-side [root2, pk2, crt2]")

    '''
    Should succeed again after previous bad config.
    '''
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_2_PEM,
                            private_key=CLIENT_KEY_1_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_1_PEM,
                            message="root2, pk1, crt1")

    channel_A.close()
    channel_B.close()

    print("reached the end of main()")


if __name__ == '__main__':
    main()
