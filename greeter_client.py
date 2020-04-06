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


def _create_client_stub(channel):
    grpc.channel_ready_future(channel).result(timeout=2)
    return helloworld_pb2_grpc.GreeterStub(channel)


def _perform_rpc(client_stub, message=None):
    # we don't care about the actual response of the rpc; only
    # whether we can perform it or not, and if not, the status
    # code must be UNAVAILABLE
    request = helloworld_pb2.HelloRequest(name=message)
    response = client_stub.SayHello(request)
    print("Greeter client received: " + response.message)


def _create_message(
    expect_success = True,
    root_certificates=None,
    private_key=None,
    certificate_chain=None):
    message = ""
    if (expect_success == False):
        message += "UNEXPECTED SUCCESS: "
    message += "["
    if (root_certificates == CA_1_PEM):
        message += "CA_1_PEM, "
    elif (root_certificates == CA_2_PEM):
        message += "CA_2_PEM, "
    elif (root_certificates == CA_BOTH_PEM):
        message += "CA_BOTH_PEM, "
    else:
        message += "unknown, "
    
    if (private_key == CLIENT_KEY_1_PEM):
        message += "CLIENT_KEY_1_PEM, "
    elif (private_key == CLIENT_KEY_2_PEM):
        message += "CLIENT_KEY_2_PEM, "
    else:
        message += "unknown, "
    
    if (certificate_chain == CLIENT_CERT_CHAIN_1_PEM):
        message += "CLIENT_CERT_CHAIN_1_PEM"
    elif (certificate_chain == CLIENT_CERT_CHAIN_2_PEM):
        message += "CLIENT_CERT_CHAIN_2_PEM"
    else:
        message += "unknown"

    return message + "]"



def _do_one_shot_client_rpc(expect_success,
                            root_certificates=None,
                            private_key=None,
                            certificate_chain=None):
    message = _create_message(expect_success, root_certificates, private_key, certificate_chain)
    credentials = grpc.ssl_channel_credentials(
        root_certificates=root_certificates,
        private_key=private_key,
        certificate_chain=certificate_chain)
    with _create_channel(port, credentials) as client_channel:
        client_stub = _create_client_stub(client_channel)
        _perform_rpc(client_stub, message)


def main():
    global port
    isTestSuccess = True

    '''
    Should succeed. Initial cert configuration.
    '''
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_1_PEM,
                            private_key=CLIENT_KEY_2_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_2_PEM)

    '''
    Should succeed again.
    '''
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_1_PEM,
                            private_key=CLIENT_KEY_2_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_2_PEM)
        
    '''
    Should succeed yet again.
    '''
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_1_PEM,
                            private_key=CLIENT_KEY_2_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_2_PEM)
    
    print("This should fail server-side " + _create_message(True, CA_1_PEM, CLIENT_KEY_1_PEM, CLIENT_CERT_CHAIN_1_PEM))
    try:
        _do_one_shot_client_rpc(False,
                                root_certificates=CA_1_PEM,
                                private_key=CLIENT_KEY_1_PEM,
                                certificate_chain=CLIENT_CERT_CHAIN_1_PEM)
        isTestSuccess = False
    except grpc.FutureTimeoutError:
        print("^This did fail server-side " + _create_message(True, CA_1_PEM, CLIENT_KEY_1_PEM, CLIENT_CERT_CHAIN_1_PEM))

    '''
    Should succeed again after previous bad config.
    '''
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_1_PEM,
                            private_key=CLIENT_KEY_2_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_2_PEM)

    '''
    Create and verify persistant channel A and stub.
    '''
    messageChannelA = "channelA: " + _create_message(True, CA_1_PEM, CLIENT_KEY_2_PEM, CLIENT_CERT_CHAIN_2_PEM)
    channel_A = _create_channel(
        port,
        grpc.ssl_channel_credentials(
            root_certificates=CA_1_PEM,
            private_key=CLIENT_KEY_2_PEM,
            certificate_chain=CLIENT_CERT_CHAIN_2_PEM))
    persistent_client_stub_A = _create_client_stub(channel_A)
    _perform_rpc(persistent_client_stub_A, messageChannelA)

    '''
    Create and verify persistant channel B and stub.
    '''
    messageChannelB = "channelB: " + _create_message(True, CA_1_PEM, CLIENT_KEY_2_PEM, CLIENT_CERT_CHAIN_2_PEM)
    channel_B = _create_channel(
        port,
        grpc.ssl_channel_credentials(
            root_certificates=CA_1_PEM,
            private_key=CLIENT_KEY_2_PEM,
            certificate_chain=CLIENT_CERT_CHAIN_2_PEM))
    persistent_client_stub_B = _create_client_stub(channel_B)
    _perform_rpc(persistent_client_stub_B, messageChannelB)

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
                            certificate_chain=CLIENT_CERT_CHAIN_1_PEM)

    '''
    Should succeed. Client using both certs for server auth and OLD certs for signing.
    '''
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_BOTH_PEM,
                            private_key=CLIENT_KEY_2_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_2_PEM)
    
    print("This should fail client-side " + _create_message(True, CA_2_PEM, CLIENT_KEY_1_PEM, CLIENT_CERT_CHAIN_1_PEM))
    try:
        _do_one_shot_client_rpc(False,
                                root_certificates=CA_2_PEM,
                                private_key=CLIENT_KEY_1_PEM,
                                certificate_chain=CLIENT_CERT_CHAIN_1_PEM)
        isTestSuccess = False
    except grpc.FutureTimeoutError:
        print("^This did fail client-side " + _create_message(True, CA_2_PEM, CLIENT_KEY_1_PEM, CLIENT_CERT_CHAIN_1_PEM))
        
    '''
    Should succeed. Client using both certs for server auth and NEW certs for signing.
    '''
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_BOTH_PEM,
                            private_key=CLIENT_KEY_1_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_1_PEM)
    
    '''
    Persistant channel A should still work.
    '''
    _perform_rpc(persistent_client_stub_A, messageChannelA)
    
    '''
    Persistant channel B should still work.
    '''
    _perform_rpc(persistent_client_stub_B, messageChannelB)

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
                            certificate_chain=CLIENT_CERT_CHAIN_1_PEM)
        
    '''
    Should succeed. Client using new certs for server auth and new certs for signing.
    '''
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_2_PEM,
                            private_key=CLIENT_KEY_1_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_1_PEM)
    
    print("This should fail client-side " + _create_message(True, CA_1_PEM, CLIENT_KEY_1_PEM, CLIENT_CERT_CHAIN_1_PEM))
    try:
        _do_one_shot_client_rpc(False,
                                root_certificates=CA_1_PEM,
                                private_key=CLIENT_KEY_1_PEM,
                                certificate_chain=CLIENT_CERT_CHAIN_1_PEM)
        isTestSuccess = False
    except grpc.FutureTimeoutError:
        print("^This did fail client-side " + _create_message(True, CA_1_PEM, CLIENT_KEY_1_PEM, CLIENT_CERT_CHAIN_1_PEM))
        
    '''
    Should succeed. Client using both certs for server auth and new certs for signing.
    '''
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_BOTH_PEM,
                            private_key=CLIENT_KEY_1_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_1_PEM)

    '''
    Should succeed. Client using new certs for server auth and new certs for signing.
    '''
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_2_PEM,
                            private_key=CLIENT_KEY_1_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_1_PEM)
    
    '''
    Persistant channel A should still work.
    '''
    _perform_rpc(persistent_client_stub_A, messageChannelA)
    
    '''
    Persistant channel B should still work.
    '''
    _perform_rpc(persistent_client_stub_B, messageChannelB)

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
                            certificate_chain=CLIENT_CERT_CHAIN_1_PEM)

    print("This should fail server-side " + _create_message(True, CA_2_PEM, CLIENT_KEY_2_PEM, CLIENT_CERT_CHAIN_2_PEM))
    try:
        _do_one_shot_client_rpc(False,
                                root_certificates=CA_2_PEM,
                                private_key=CLIENT_KEY_2_PEM,
                                certificate_chain=CLIENT_CERT_CHAIN_2_PEM)
        isTestSuccess = False
    except grpc.FutureTimeoutError:
        print("^This did fail server-side " + _create_message(True, CA_2_PEM, CLIENT_KEY_2_PEM, CLIENT_CERT_CHAIN_2_PEM))

    '''
    Should succeed again after previous bad config.
    '''
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_2_PEM,
                            private_key=CLIENT_KEY_1_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_1_PEM)
    
    '''
    Persistant channel A should still work.
    '''
    _perform_rpc(persistent_client_stub_A, messageChannelA)
    
    '''
    Persistant channel B should still work.
    '''
    _perform_rpc(persistent_client_stub_B, messageChannelB)

    channel_A.close()
    channel_B.close()

    print("isTestSuccess = {}".format(isTestSuccess))
    print("reached the end of main()")


if __name__ == '__main__':
    main()
