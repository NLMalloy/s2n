#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

"""
Handshake tests against openssl using TLS13.
At the moment these tests are expected fail, as TLS13 is incomplete.
"""

import argparse
import os
import sys
import subprocess

from s2n_test_constants import *
from common.s2n_test_openssl import run_openssl_connection_test
from common.s2n_test_scenario import get_scenarios, Mode, Cipher, Version
from s2n_handshake_test_s_client import IntegrationTestFailure, print_result, read_process_output_until, ProcessFailed, cert_path_to_str, create_thread_pool


PROTO_VERS_TO_S_CLIENT_ARG = {
    S2N_TLS13 : "-tls1_3",
}

ALL_CIPHERS = [
    Cipher("TLS_AES_256_GCM_SHA384", Version.TLS13),
    Cipher("TLS_CHACHA20_POLY1305_SHA256", Version.TLS13),
    Cipher("TLS_AES_128_GCM_SHA256", Version.TLS13)
]

def try_handshake(host, port, cipher, ssl_version, server_cert=None, server_key=None,
        server_cipher_pref=None, sig_algs=None, curves=None, resume=False, no_ticket=False,
        enter_fips_mode=False, client_auth=None, client_cert=DEFAULT_CLIENT_CERT_PATH,
        client_key=DEFAULT_CLIENT_KEY_PATH, expected_cipher=None,
        debug_cmds=False, tls13_flag=False, results=dict
        ):
    """
    Attempt to handshake against s2nd listening on `host` and `port` using Openssl s_client

    :param int host: host for s2nd to listen on
    :param int port: port for s2nd to listen on
    :param str cipher: ciphers for Openssl s_client to offer. See https://www.openssl.org/docs/man1.0.2/apps/ciphers.html
    :param int ssl_version: SSL version for s_client to use
    :param str server_cert: path to certificate for s2nd to use
    :param str server_key: path to private key for s2nd to use
    :param str sig_algs: Signature algorithms for s_client to offer
    :param str curves: Elliptic curves for s_client to offer
    :param bool resume: True if s_client should try to reconnect to s2nd and reuse the same TLS session. False for normal negotiation.
    :param bool no_ticket: True if s2n server should not use session ticket to resume the same TLS session.
    :param bool enter_fips_mode: True if s2nd should enter libcrypto's FIPS mode. Libcrypto must be built with a FIPS module to enter FIPS mode.
    :param bool client_auth: True if the test should try and use client authentication
    :param str client_cert: Path to the client's cert file
    :param str client_key: Path to the client's private key file
    :param str expected_cipher: the cipher we expect to negotiate
    :param bool debug_cmds: print commands that are invoked for the handshake tests
    :param bool tls13_flag: determine whether to add tls13_flag to s2nd
    :param dict results: object that can be used to update tests results like run count back to caller
    :return: 0 on successfully negotiation(s), -1 on failure
    """

    results['tests_ran'] += 1

    # Override certificate for ECDSA if unspecified. We can remove this when we
    # support multiple certificates
    if server_cert is None and "ECDSA" in cipher:
        server_cert = TEST_ECDSA_CERT
        server_key = TEST_ECDSA_KEY

    # Fire up s2nd
    s2nd_cmd = ["../../bin/s2nd"]

    if server_cert is not None:
        s2nd_cmd.extend(["--cert", server_cert])
    if server_key is not None:
        s2nd_cmd.extend(["--key", server_key])
    if client_auth is not None:
        s2nd_cmd.append("-m")
        s2nd_cmd.extend(["-t", client_cert])

    s2nd_cmd.extend([str(host), str(port)])

    s2nd_ciphers = "test_all"
    if server_cipher_pref is not None:
        s2nd_ciphers = server_cipher_pref
    if enter_fips_mode == True:
        s2nd_ciphers = "test_all_fips"
        s2nd_cmd.append("--enter-fips-mode")

    if tls13_flag:
        s2nd_cmd.append("--tls13")
        # we use tls12 only cipher preferences to keep s2nd negotiating maximum versions of TLS 1.2
        if s2nd_ciphers == "test_all" and ssl_version != S2N_TLS13:
            s2nd_ciphers = "test_all_tls12"

    s2nd_cmd.append("-c")
    s2nd_cmd.append(s2nd_ciphers)
    if no_ticket:
        s2nd_cmd.append("-T")
    #if use_corked_io:
     #   s2nd_cmd.append("-C")

    s_client_cmd = ["openssl", "s_client", "-connect", str(host) + ":" + str(port)]

    if ssl_version is not None:
        s_client_cmd.append(PROTO_VERS_TO_S_CLIENT_ARG[ssl_version])
    if cipher is not None:
        cipher_format = cipher

        if client_cert is not None and 'sha1' in client_cert:
            # OpenSSL 1.1.1e prohibits SHA1 in security level 1 and above.
            # For those specific certs we can run in security level 0.
            cipher_format = "{}@SECLEVEL=0".format(cipher)
        s_client_cmd.extend(["-cipher", cipher_format])
    if sig_algs is not None:
        s_client_cmd.extend(["-sigalgs", sig_algs])
    if curves is not None and ssl_version != S2N_TLS13:
        s_client_cmd.extend(["-curves", curves])
    elif ssl_version == S2N_TLS13:
        s_client_cmd.append("-curves P-256")
    if resume == True:
        s_client_cmd.append("-reconnect")
    if client_auth is not None:
        s_client_cmd.extend(["-key", client_key])
        s_client_cmd.extend(["-cert", client_cert])
    #always no server name
    s_client_cmd.append("-noservername")

    # For verifying extensions that s2nd sends expected extensions
    s_client_cmd.append("-tlsextdebug")

    if debug_cmds:
        print("s2nd:\t", " ".join(s2nd_cmd))
        print("s_client:\t", " ".join(s_client_cmd))

    # Fire up s2nd
    s2nd = subprocess.Popen(s2nd_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    # Make sure s2nd has started
    s2nd.stdout.readline()

    # Fire up s_client
    s_client = subprocess.Popen(s_client_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    s_client_out = ""
    s2nd_out = ""

    openssl_connect_marker = "CONNECTED"
    openssl_reconnect_marker = "drop connection and then reconnect"
    end_of_msg_marker = "__end_of_msg__"

    # Wait until openssl and s2n have finished the handshake and are connected to each other
    try:
        s_client_out += read_process_output_until(s_client, openssl_connect_marker)
        s2nd_out += read_process_output_until(s2nd, openssl_connect_marker)
    except ProcessFailed as ex:
        print("Client or daemon failed: {}".format(ex))
        return -1

    if resume == True:
        for i in range(0,5):
            # Wait for openssl to resume connection 5 times in a row, and verify resumption works.
            try:
                s_client_out += read_process_output_until(s_client, openssl_reconnect_marker)
                s2nd_out += read_process_output_until(s2nd, openssl_connect_marker)
            except ProcessFailed as ex:
                print("Client or daemon failed: {}".format(ex))
                return -1

    data_to_validate = cipher + " " + str(uuid.uuid4())

    # Write the data to openssl towards s2n server
    msg = (data_to_validate + "\n" + end_of_msg_marker + "\n\n").encode("utf-8")
    s_client.stdin.write(msg)
    s_client.stdin.flush()

     # Write the data to s2n towards openssl client
    s2nd.stdin.write(msg)
    s2nd.stdin.flush()

    # Wait for the Data transfer to complete between OpenSSL and s2n
    try:
        s_client_out += read_process_output_until(s_client, end_of_msg_marker)
        s2nd_out += read_process_output_until(s2nd, end_of_msg_marker)
    except ProcessFailed as ex:
        print("Client or daemon failed: {}".format(ex))
        return -1

    cleanup_processes(s2nd, s_client)

    if validate_data_transfer(data_to_validate, s_client_out, s2nd_out) != 0:
        return -1

    if resume is True:
        if validate_resume(s2nd_out) != 0:
            return -1

    if expected_cipher is not None:
        if find_expected_cipher(expected_cipher, s_client_out) != 0:
            return -1

    return 0

def run_handshake_test(host, port, ssl_version, cipher, fips_mode, no_ticket, use_client_auth, client_cert_path, client_key_path, **kwargs):
    cipher_name = cipher.openssl_name
    cipher_vers = cipher.min_tls_vers

    # Skip the cipher if openssl can't test it. 3DES/RC4 are disabled by default in 1.1.1
    if not cipher.openssl_1_1_1_compatible:
        return 0

    if ssl_version and ssl_version < cipher_vers:
        return 0

    client_cert_str=str(use_client_auth)

    if (use_client_auth is not None) and (client_cert_path is not None):
        client_cert_str = cert_path_to_str(client_cert_path)

    ret = try_handshake(host, port, cipher_name, ssl_version,
        no_ticket=no_ticket, enter_fips_mode=fips_mode, client_auth=use_client_auth,
        client_cert=client_cert_path, client_key=client_key_path,
        **kwargs)

    result_prefix = "Cipher: %-30s ClientCert: %-16s Vers: %-8s ... " % (cipher_name, client_cert_str, S2N_PROTO_VERS_TO_STR[ssl_version])
    print_result(result_prefix, ret)

    return ret

def handshake_test(host, port, test_ciphers, fips_mode,
        no_ticket=False, use_client_auth=None, use_client_cert=None, use_client_key=None, **kwargs):
    """
    Basic handshake tests using all valid combinations of supported cipher suites and TLS versions.
    """
    print("\n\tRunning handshake tests:")

    failed = False
    ssl_version = S2N_TLS13
    print("\n\tTesting ciphers using client version: " + S2N_PROTO_VERS_TO_STR[ssl_version])
    threadpool = create_thread_pool()
    port_offset = 0
    results = []

    for cipher in test_ciphers:
        async_result = threadpool.apply_async(run_handshake_test,
            (host, port + port_offset, ssl_version, cipher, fips_mode,
                no_ticket, use_client_auth, use_client_cert, use_client_key),
            kwargs)
        port_offset += 1
        results.append(async_result)

    threadpool.close()
    threadpool.join()
    for async_result in results:
        if async_result.get() != 0:
            failed = True

    if failed:
        raise IntegrationTestFailure

def client_auth_test(host, port, test_ciphers, fips_mode, **kwargs):
    print("\n\tRunning client auth tests:")

    for filename in os.listdir(TEST_CERT_DIRECTORY):
        if "client_cert" in filename and "rsa" in filename:
            client_cert_path = TEST_CERT_DIRECTORY + filename
            client_key_path = TEST_CERT_DIRECTORY + filename.replace("client_cert", "client_key")
            handshake_test(host, port, test_ciphers, fips_mode,
                no_ticket=True, use_client_auth=True, use_client_cert=client_cert_path, use_client_key=client_key_path,
                **kwargs)

def main():
    parser = argparse.ArgumentParser(description='Runs TLS1.3 minimal handshake integration tests against Openssl')
    parser.add_argument('host', help='The host to connect to')
    parser.add_argument('port', type=int, help='The port to bind to')

    args = parser.parse_args()
    host = args.host
    port = args.port

    test_ciphers = S2N_LIBCRYPTO_TO_TEST_CIPHERS['openssl-1.1.1']
    host = args.host
    port = args.port
    libcrypto_version = 'openssl-1.1.1'
    failed = 0

    print("\n\tRunning TLS1.3 handshake tests with openssl: %s" % os.popen('openssl version').read())
    failed += run_openssl_connection_test(get_scenarios(host, port, versions=[Version.TLS13], s2n_modes=Mode.all(), ciphers=Cipher.all()))

    results = {'tests_ran': 0}

    try:
        options=dict(
            results=results,
            tls13_flag = True,
            debug_cmds = True,
        )

        client_auth_test(host, port, ALL_CIPHERS, fips_mode=False, **options)
    except IntegrationTestFailure as ex:
        failed += 1

    print("Total handshakes: ", results['tests_ran'])

    return failed


if __name__ == "__main__":
    sys.exit(main())

