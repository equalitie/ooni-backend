"""UDP-based NAT detection helper.

See the documentation of the `NATDetectionProtocol` class for more
information.

Rate limiting
-------------

This piece of code only does basic format checking and will reply to all
requests that look valid.  Therefore, if used as-is, it can be used for
rebound attacks via UDP source address spoofing.  With Linux, it is
recommended to use ``ip(6)tables`` to limit the rate of requests that reach
this helper, for example::

    # iptables -A INPUT -p udp --dport <SERVER_PORT> -m hashlimit \
               --hashlimit-name nat-detect-helper --hashlimit-above 5/minute \
               --hashlimit-mode srcip,dstip,dstport --hashlimit-burst 5 \
               --hashlimit-srcmask 32 -j DROP

See iptables' ``hashlimit`` module documentation.  For IPv6, the source mask
can be set to values up to 128 (56 or 64 would generally be reasonable
choices).

Standalone execution
--------------------

Besides being run as a OONI backend helper, the helper can be run standalone
if Twisted is available (package ``python-twisted-core`` in Debian Wheezy and
newer).  It requires at least one argument with a ``[MAIN_HOST:]MAIN_PORT``
main address and optional arguments with ``[ALT_HOST:]ALT_PORT`` alternate
addresses.

Example standalone invocation::

    $ python /path/to/udp_natdet_helpers.py 12345 12346 192.0.2.1:13579

This receives messages on port 12345 of all interfaces and sends replies from
that port (using whatever source IP the system chooses), and also from port
12346 (using whatever source IP the system chooses) and from IP ``192.0.2.1``
and port 13579.

To run the previous configuration as a permanent systemd service under
GNU/Linux, you may create a unit file like the following one::

    [Unit]
    Description=NAT detection server
    After=network.target

    [Service]
    ExecStart=/usr/bin/python2 /path/to/udp_natdet_helpers.py 12345 12346 192.0.2.1:13579
    Restart=on-failure
    User=nobody
    Group=nogroup

    [Install]
    WantedBy=default.target

Save it as ``/etc/systemd/system/natdet-server.service`` and enable and start
it with::

    # systemctl enable natdet-server
    # systemctl start natdet-server
"""

import re
import socket
import sys

from twisted.internet import protocol, reactor

try:
    from oonib.config import config
except ImportError:
    config = None


"""Default endpoint IP address when the host part is not specified.

The IPv4 wildcard is used for compatibility with how the OONI backend
interprets null addresses in its configuration file.
"""
DEF_ENDPOINT_ADDR = ''

# Format: "NATDET <16-hex digit peer name>"
_data_re = re.compile(r'^NATDET [0-9a-f]{16}$')
_max_data_len = len('NATDET 0123456789abcdef')


class NATDetectionProtocol(protocol.DatagramProtocol):
    """Trivial UDP protocol to help with the detection of NAT.

    This protocol helps detect different types of NAT by echoing back the
    received payload not only from the receiving (main) address, but also from
    additional (alternate) ones.  To configure alternate addresses, you may
    either provide a sequence of ``(ip, port)`` pairs to the constructor, or
    use the backend's configuration file (see below).

    The *protocol* is very simple.  A message is received from the client at
    the main address with the following format::

        NATDET <16-hex digit id>

    Then a reply is sent from the main address and also from alternate
    addresses with the following format::

        NATDET <16-hex digit id> <IP>:<PORT>

    Where ``<IP>:<PORT>`` is the transport address of the client as seen in
    the received datagram.

    For *configuration*, when available, the protocol uses the
    ``nat-detection`` key under the ``helpers`` main key.  The following keys
    must be specified there:

    ``address``
      The IP address of the UDP endpoint where messages are received and sent
      from (main address).  Use a null address for listening on all IPv4
      interfaces, or give a explicit address if you want to use several ones.

    ``port``
      The port number of the UDP endpoint where messages are received and sent
      from (main address).

    ``alternate_sources``
      A (maybe empty) list of UDP endpoints where messages are also sent from
      (alternate addresses).  Each entry in the list is a mapping with
      ``address`` and ``port`` keys, with semantics similar to those defining
      the main address.  It is recommended that you include at least one entry
      with a different port than the main address and, if the host has it, one
      with a different, explicit IP address.
    """
    def __init__(self, altAddrs=[]):
        self.altAddrs = list(altAddrs)

    def startProtocol(self):
        # Get alternate addresses from OONI backend config if available.
        if config and 'nat-detection' in config.helpers:
            configAltSources = config.helpers['nat-detection'].alternate_sources
            self.altAddrs += [(addr['address'] or DEF_ENDPOINT_ADDR, addr['port'])
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


def _unpackAddr(s):  # '1.2.3.4:1234' -> ('1.2.3.4', 1234)
    host, port = s.rsplit(':', 1) if ':' in s else (DEF_ENDPOINT_ADDR, s)
    host = host.translate(None, '[]')  # delete IPv6 brackets
    port = int(port)
    return (host, port)


def main():
    if len(sys.argv) < 2:
        sys.stderr.write(
            "Usage: %s [MAIN_HOST:]MAIN_PORT [[ALT_HOST:]ALT_PORT]...\n"
            % sys.argv[0])
        sys.exit(1)

    mainHost, mainPort = _unpackAddr(sys.argv[1])
    altAddrs = [_unpackAddr(s) for s in sys.argv[2:]]

    proto = NATDetectionProtocol(altAddrs)

    reactor.listenUDP(mainPort, proto, interface=mainHost)
    reactor.run()

if __name__ == '__main__':
    main()
