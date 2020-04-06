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

# for use with the CertConfigFetcher. Roughly a simple custom mock
# implementation
Call = collections.namedtuple('Call', ['did_raise', 'returned_cert_config'])

cert_config_fetcher = None

class Greeter(helloworld_pb2_grpc.GreeterServicer):

    def SayHello(self, request, context):
        return helloworld_pb2.HelloReply(message='Hello, %s!' % request.name)


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


def serve():
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
    server.add_secure_port('[::]:50051', server_credentials)
    server.start()

    numOfKeyboardInterrupts = 0
    while True:
        try:
            while True:
                time.sleep(_ONE_DAY_IN_SECONDS)
        except KeyboardInterrupt:
            numOfKeyboardInterrupts += 1
        if (numOfKeyboardInterrupts == 1):
            print("first interrupt: changing certs...")
            cert_config_new = grpc.ssl_server_certificate_configuration(
                [(SERVER_KEY_1_PEM, SERVER_CERT_CHAIN_1_PEM)],
                root_certificates=CA_BOTH_PEM)
            print("CA_BOTH_PEM length: {}".format(len(CA_BOTH_PEM)))
            cert_config_fetcher.reset()
            cert_config_fetcher.configure(False, cert_config_new)
            print("certs changed")
            continue
        if (numOfKeyboardInterrupts == 2):
            print("second interrupt: changing certs...")
            cert_config_new = grpc.ssl_server_certificate_configuration(
                [(SERVER_KEY_2_PEM, SERVER_CERT_CHAIN_2_PEM)],
                root_certificates=CA_1_PEM)
            print("CA_1_PEM length: {}".format(len(CA_1_PEM)))
            print("SERVER_KEY_2_PEM length: {}".format(len(SERVER_KEY_2_PEM)))
            print("SERVER_CERT_CHAIN_2_PEM length: {}".format(len(SERVER_CERT_CHAIN_2_PEM)))
            cert_config_fetcher.reset()
            cert_config_fetcher.configure(False, cert_config_new)
            print("certs changed")
            continue
        if (numOfKeyboardInterrupts == 3):
            print("third interrupt: stopping server...")
            server.stop(0)
            break

if __name__ == '__main__':
    serve()
