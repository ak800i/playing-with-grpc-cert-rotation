from concurrent import futures
import collections
import logging
import time

import threading
import grpc

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

# for use with the CertConfigFetcher. Roughly a simple custom mock
# implementation
Call = collections.namedtuple('Call', ['did_raise', 'returned_cert_config'])

cert_config_fetcher = None
port = 50051

class CertConfigFetcher(object):

    def __init__(self):
        self._lock = threading.Lock()
        self._calls = []
        self._should_raise = False
        self._cert_config = None

    def reset(self):
        with self._lock:
            self._calls = []
            self._should_raise = False
            self._cert_config = None

    def configure(self, should_raise, cert_config):
        assert not (should_raise and cert_config), (
            "should not specify both should_raise and a cert_config at the same time"
        )
        with self._lock:
            self._should_raise = should_raise
            self._cert_config = cert_config

    def getCalls(self):
        with self._lock:
            return self._calls

    def __call__(self):
        with self._lock:
            if self._should_raise:
                self._calls.append(Call(True, None))
                raise ValueError('just for fun, should not affect the test')
            else:
                self._calls.append(Call(False, self._cert_config))
                return self._cert_config


class SignatureValidationInterceptor(grpc.ServerInterceptor):

    def __init__(self):

        def abort(ignored_request, context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, 'Invalid signature')

        self._abortion = grpc.unary_unary_rpc_method_handler(abort)

    def intercept_service(self, continuation, handler_call_details):
        # Example HandlerCallDetails object:
        #     _HandlerCallDetails(
        #       method=u'/helloworld.Greeter/SayHello',
        #       invocation_metadata=...)
        method_name = handler_call_details.method.split('/')[-1]
        expected_metadata = (_SIGNATURE_HEADER_KEY, method_name[::-1])
        if expected_metadata in handler_call_details.invocation_metadata:
            return continuation(handler_call_details)
        else:
            return self._abortion


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    helloworld_pb2_grpc.add_GreeterServicer_to_server(Greeter(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    server.wait_for_termination()

class Greeter(helloworld_pb2_grpc.GreeterServicer):

    def SayHello(self, request, context):
        return helloworld_pb2.HelloReply(message='Hello, %s!' % request.name)


def run_server():
    # Bind interceptor to server
    initial_cert_config = grpc.ssl_server_certificate_configuration(
        [(SERVER_KEY_1_PEM, SERVER_CERT_CHAIN_1_PEM)],
        root_certificates=CA_2_PEM, # for verifying clients
    )
    global cert_config_fetcher
    cert_config_fetcher = CertConfigFetcher()
    server_credentials = grpc.dynamic_ssl_server_credentials(
        initial_cert_config,
        cert_config_fetcher,
        require_client_authentication=True)

    print("CA_2_PEM length: {}".format(len(CA_2_PEM)))

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    helloworld_pb2_grpc.add_GreeterServicer_to_server(Greeter(), server)
    global port
    port = server.add_secure_port('[::]:{}'.format(port), server_credentials)
    print('[::]:{}'.format(port))
    server.start()


def _create_channel(port, credentials):
    return grpc.secure_channel('localhost:{}'.format(port), credentials)


def _create_client_stub(channel, expect_success):
    if expect_success:
        # per Nathaniel: there's some robustness issue if we start
        # using a channel without waiting for it to be actually ready
        grpc.channel_ready_future(channel).result(timeout=2)
        #print("dbg-post channel_ready_future")
    return helloworld_pb2_grpc.GreeterStub(channel)


def _perform_rpc(client_stub, message=None):
    # we don't care about the actual response of the rpc; only
    # whether we can perform it or not, and if not, the status
    # code must be UNAVAILABLE
    #print("dbg-entered _perform_rpc")
    request = helloworld_pb2.HelloRequest(name=message)
    #print("dbg-post request")
    response = client_stub.SayHello(request)
    print("Greeter client received: " + response.message)


def _do_one_shot_client_rpc(expect_success,
                            root_certificates=None,
                            private_key=None,
                            certificate_chain=None,
                            message=None):
    #print("dbg-entered _do_one_shot_client_rpc")
    credentials = grpc.ssl_channel_credentials(
        root_certificates=root_certificates,
        private_key=private_key,
        certificate_chain=certificate_chain)
    #print("dbg-post ssl_channel_credentials")
    with _create_channel(port, credentials) as client_channel:
        #print("dbg-post _create_channel")
        #print("dbg-post client_channel: {}".format(client_channel))
        client_stub = _create_client_stub(client_channel, expect_success)
        #print("dbg-post _create_client_stub")
        _perform_rpc(client_stub, message)


def main():
    global cert_config_fetcher
    global port
    #run_server()
    #print("dbg-post run server")

    '''
    Should succeed. Initial cert configuration.
    '''
    #cert_config_fetcher.configure(False, None)
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_1_PEM,
                            private_key=CLIENT_KEY_2_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_2_PEM,
                            message="root1, pk2, crt2")
    #print("actual_calls={}".format(cert_config_fetcher.getCalls()))

    '''
    Should succeed again.
    '''
    #cert_config_fetcher.reset()
    #cert_config_fetcher.configure(False, None)
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_1_PEM,
                            private_key=CLIENT_KEY_2_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_2_PEM,
                            message="root1, pk2, crt2")
    #print("actual_calls={}".format(cert_config_fetcher.getCalls()))
        
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
                                message="root1, pk1, crt1")
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

    '''cert_config_new = grpc.ssl_server_certificate_configuration(
        [(SERVER_KEY_2_PEM, SERVER_CERT_CHAIN_2_PEM)],
        root_certificates=CA_1_PEM)'''


    '''
    Should succeed. Client using both certs for server auth and new certs for signing.
    '''
    '''cert_config_fetcher.reset()
    cert_config_fetcher.configure(False, cert_config_new)'''
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_BOTH_PEM,
                            private_key=CLIENT_KEY_1_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_1_PEM,
                            message="(root1 and root2), pk1, crt1")
    #print("actual_calls={}".format(cert_config_fetcher.getCalls()))
    
    '''print("This should fail[root2, pk1, crt1]:")
    try:
        _do_one_shot_client_rpc(True,
                                root_certificates=CA_2_PEM,
                                private_key=CLIENT_KEY_1_PEM,
                                certificate_chain=CLIENT_CERT_CHAIN_1_PEM,
                                message="root2, pk1, crt1")
    except:
        print("^This did fail[root2, pk1, crt1]")'''

    '''
    Should succeed. Client using both certs for server auth and OLD certs for signing.
    '''
    _do_one_shot_client_rpc(True,
                            root_certificates=CA_BOTH_PEM,
                            private_key=CLIENT_KEY_2_PEM,
                            certificate_chain=CLIENT_CERT_CHAIN_2_PEM,
                            message="(root1 and root2), pk2, crt2")
        
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
    #print("persistent_client_stub_A done")
    
    '''
    Persistant channel B should still work.
    '''
    _perform_rpc(persistent_client_stub_B, message="channelB: root1, pk2, crt2")
    #print("persistent_client_stub_B done")

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
    
    print("This should fail server-side [(root1 and root2), pk2, crt2]:")
    try:
        _do_one_shot_client_rpc(True,
                                root_certificates=CA_BOTH_PEM,
                                private_key=CLIENT_KEY_2_PEM,
                                certificate_chain=CLIENT_CERT_CHAIN_2_PEM,
                                message="(root1 and root2), pk2, crt2")
    except:
        print("^This did fail server-side [(root1 and root2), pk2, crt2]")
        
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

    channel_A.close()
    channel_B.close()

    print("reached the end of main()")
    #server.wait_for_termination()


if __name__ == '__main__':
    main()
