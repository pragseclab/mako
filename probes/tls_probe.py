from probes.probe import Probe
import concurrent.futures
import socket 
import ssl

class TLSProbe(Probe):

    def run(self):
        tls_versions = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]

        # for tlsVersion in results.keys():
        #     results[tlsVersion] = self.testTLSVersion(tlsVersion)

        with concurrent.futures.ThreadPoolExecutor(len(tls_versions)) as executor: 
            futures = executor.map(self.testTLSVersion, tls_versions)
        results = {tls_version: result for (tls_version, result) in zip(tls_versions, futures)}

        return results

    def testTLSVersion(self, version):
        versionFlags = {"SSLv2" : ssl.OP_NO_SSLv2, "SSLv3" : ssl.OP_NO_SSLv3, "TLSv1" : ssl.OP_NO_TLSv1,
                "TLSv1.1" : ssl.OP_NO_TLSv1_1, "TLSv1.2" : ssl.OP_NO_TLSv1_2, "TLSv1.3" : ssl.OP_NO_TLSv1_3}

        context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
        context.verify_mode = ssl.CERT_NONE # disable cert. validation
        context.check_hostname = False  # disable host name checking
        context.options &= ~ssl.OP_NO_SSLv3

        # Disable all TLS versions and reenable the one that we do want
        blackListVersions = ssl.OP_NO_TLSv1_3 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1 | ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2
        blackListVersions &= ~versionFlags[version]
        context.options |= blackListVersions

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # create socket
        wrappedSocket = context.wrap_socket(s, server_hostname = self.domain, do_handshake_on_connect=True) # wrap socket into TLS context
        wrappedSocket.settimeout(2)
        try:
            wrappedSocket.connect((self.ip, 443)) # TLS socket connection
            acceptedVersion = wrappedSocket.version()
            return acceptedVersion == version
        except (ssl.SSLError):
            return False
        except socket.timeout:
            return 408
        except (ConnectionResetError, socket.gaierror, Exception):
            return None
        finally:
            wrappedSocket.close()