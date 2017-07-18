from twisted.internet.protocol import Protocol, Factory, ServerFactory

from oonib.config import config
from oonib import log

import collections
import random
import re
import time


# Accept ``PORT`` or ``PORT PROTO[ FLAG]...``.
_max_data_len = 100
_data_re = re.compile(r'^([0-9]+)(| [A-Z]+( [_a-z]+)*)$')

# Discard peer entries older than this many seconds.
MAX_PEER_AGE_SECS = 2 * 24 * 60 * 60  # 2 days


# A peer entry with a time stamp, transport address, protocol and a tuple of flags.
PeerEntry = collections.namedtuple('PeerEntry', 'ts addr proto flags')

class PeerLocatorProtocol(Protocol):
    """A simple protocol to get the P2P address of a probe and send that of
    another one in response.

    The helper receives a string with either just a port number (for old HTTP
    pobes) or a port number, a protocol and a set of flags (for new probes).
    It stores a time-stamped entry with the probe's public address, the
    reported port number, protocol and flags.  Then it replies with a random
    entry of the same protocol which does not share the same address and port,
    and which is not very old.  For old probes, a protocol-less, HTTP
    URL-compatible string is sent back with the flags and time stamp encoded
    as query arguments.

    Example of received message (old HTTP probe on P2P port 80)::

        80

    Example of received message (new HTTP probe on P2P port 80 behind NAT)::

        80 HTTP nat

    Example of reply (new probe)::

        1500288137.95785 192.0.2.1:80 HTTP nat

    Example of reply (old probe, implicit HTTP)::

        192.0.2.1:80/?ts=1500288137.95785&nat=true
    """

    def _parseInput(self, data):
        """Parse `data` and return a new `PeerEntry`.

        If `data` has a bad format, return `None`.
        """
        # Protect against garbage.
        data = data[:_max_data_len]
        if not _data_re.match(data)
            return

        # Construct the entry.
        splitted = data.split()
        port = int(splitted[0])
        if len(splitted) > 1:  # new probe
            proto = splitted[1]
            flags = tuple(splitted[2:])
        else:  # old probe
            proto = 'HTTP'
            flags = ()

        return PeerEntry(ts=time.time(),
                         addr=b'%s:%d' % (self.transport.getPeer().host, port),
                         proto=proto, flags=flags)

    def _parsePeerEntry(self, data):
        """Parse `data` and return a `PeerEntry`."""
        splitted = data.split()
        return PeerEntry(ts=float(splitted[0]),
                         addr=splitted[1],
                         proto=splitted[2], flags=tuple(splitted([3:])))

    def _formatPeerEntry(self, peer):
        """Format the given `peer` entry into a string."""
        return b'%f %s %s %s' % (peer.ts, peer.addr, peer.proto, ' '.join(peer.flags))

    def _formatPeerEntryOld(self, peer):
        """Format the given `peer` into an HTTP URL-compatible string."""
        s = b'%s/?ts=%f' % (peer.addr, peer.ts)
        s += b'&nat=%s' % bytes(b'nat' in peer.flags).lower()
        return s

    def dataReceived(self, data):
        peer = self._parseInput(data)
        if not peer:
            return
        is_old_probe = bool(peer.flags)  # old probes report no flags

        log.msg("registering: %s" % peer.addr)
        random_peer_addr = peer.addr
        try:
            with open(config.helpers['peer-locator'].peer_list, 'a+') as peer_list_file:
                now = time.time()  # only consider entries not older than max peer age
                peer_list = filter(lambda p: ((now - p.ts) < MAX_PEER_AGE_SECS
                                              and p.proto == peer.proto),
                                   [_parsePeerEntry(l) for l in peer_list_file.readlines()])
                if peer.addr in [p.addr for p in peer_list]:  # only compare IP:PORT
                    log.msg('we already know the peer')
                else:
                    log.msg('new peer: %s' % (peer,))
                    peer_list_file.write(_formatPeerEntry(peer) + '\n')
                    peer_list.append(peer)
                peer_pool_size = len(peer_list)

                log.msg(str(peer_list))
                log.msg("choosing a random peer from pool of %d peers" % peer_pool_size)
                # Do not return any entry with the same ``PUB_ADDR:PORT``.
                while(peer_pool_size > 1 and random_peer_addr == peer.addr):
                    random_peer = random.choice(peer_list)
                    random_peer_addr = random_peer[1]

        except IOError as e:
            log.msg("IOError %s" % e)

        if (random_peer_addr == peer.addr):
            out = ''
        else:
            log.msg("seeding peer %s to peer %s" % (random_peer_addr, peer.addr))
            out = (_formatPeerEntry(random_peer) if not is_old_probe
                   else _formatPeerEntryOld(random_peer))

        self.transport.write(out)

class PeerLocatorHelper(Factory):
    protocol = PeerLocatorProtocol

