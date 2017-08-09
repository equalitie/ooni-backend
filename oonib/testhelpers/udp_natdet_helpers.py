#!/usr/bin/env python2

# This piece of code only does basic format checking and will reply to all
# requests that look valid. Therefore, if used as-is, it can be used for rebound
# attacks via UDP source address spoofing. It is recommended to use ip(6)tables
# to limit the rate of requests that reach this helper, for example:
#
# iptables -A INPUT -p udp --dport <server_port> -m hashlimit \
#          --hashlimit-name nat-detect-helper --hashlimit-above 5/minute \
#          --hashlimit-mode srcip,dstip,dstport --hashlimit-burst 5 \
#          --hashlimit-srcmask 32 -j DROP
#
# See iptables' hashlimit module documentation. For IPv6, the source mask can
# be set to values up to 128 (56 or 64 would generally be reasonable choices).

import re
import socket
import sys

from twisted.internet import protocol, reactor

try:
    from oonib.config import config
except ImportError:
    config = None


# Format: "NATDET <16-hex digit peer name>"
_data_re = re.compile(r'^NATDET [0-9a-f]{16}$')
_max_data_len = len('NATDET 0123456789abcdef')


class NATDetectionProtocol(protocol.DatagramProtocol):
    def __init__(self, altAddrs=[]):
        self.altAddrs = list(altAddrs)

    def startProtocol(self):
        # Get alternate addresses from OONI backend config if available.
        if config:
            configAltSources = config.helpers['nat-detection'].alternate_sources
            self.altAddrs += [(addr['address'] or '', addr['port'])
                              for addr in configAltSources]

        # Create sockets for alternate (send-only) addresses.
        self.altSocks = []
        for (host, port) in self.altAddrs:
            altsock = socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET, socket.SOCK_DGRAM)
            self.altSocks.append(altsock)
            altsock.setblocking(False)
            altsock.bind((host, port))

    def stopProtocol(self):
        # Close all alternate address sockets.
        for altsock in self.altSocks:
            altsock.close()

    def datagramReceived(self, data, (host, port)):
        data = data[:_max_data_len]
        if not _data_re.match(data):
            return  # drop malformed datagrams

        # Received something: we reply with same data
        # along with host and port we see for the remote
        # (via the main and alternate sockets).
        addr = ('[%s]:%d' if ':' in host else '%s:%d') % (host, port)
        reply = '%s %s' % (data, addr)
        self.transport.write (reply, (host, port))
        for altsock in self.altSocks:
            altsock.sendto(reply, (host, port))


def unpackAddr(s):  # '1.2.3.4:1234' -> ('1.2.3.4', 1234)
    host, port = s.rsplit(':', 1) if ':' in s else ('', s)
    host = host.translate(None, '[]')  # delete IPv6 brackets
    port = int(port)
    return (host, port)


def main():
    if len(sys.argv) < 2:
        sys.stderr.write(
            "Usage: %s [MAIN_HOST]:MAIN_PORT [[ALT_HOST]:ALT_PORT]...\n"
            % sys.argv[0])
        sys.exit(1)

    mainHost, mainPort = unpackAddr(sys.argv[1])
    altAddrs = [unpackAddr(s) for s in sys.argv[2:]]

    proto = NATDetectionProtocol(altAddrs)

    reactor.listenUDP(mainPort, proto, interface=mainHost)
    reactor.run()

if __name__ == '__main__':
    main()
