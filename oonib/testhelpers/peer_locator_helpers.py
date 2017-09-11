from twisted.internet.protocol import Protocol, Factory, ServerFactory

from oonib.config import config
from oonib import log

import collections
import random
import re
import time


# Accept ``PORT`` or ``PORT PROTO FLAG[=VALUE]...``.
_max_data_len = 200
_data_re = re.compile(r'^[0-9]+(| [A-Z]+( [_a-z]+(=\S*)?)+)$')

# Discard peer entries older than this many seconds.
MAX_PEER_AGE_SECS = (7 - 1) * 24 * 60 * 60  # 6 days, one less than max server age


# A peer entry with a time stamp, transport address, protocol and a tuple of flags.
PeerEntry = collections.namedtuple('PeerEntry', 'ts addr proto flags')

class PeerLocatorProtocol(Protocol):
    """A simple protocol to get the P2P address of a probe and send that of
    another one in response.

    The helper receives a string with a port number, a protocol and a set of
    flags, all separated by a single space (including flags); flags may have a
    possibly empty value assigned with ``=`` (no whitespace is allowed in flag
    values).  The helper stores a time-stamped entry with the probe's public
    address, the reported port number, protocol and flags.  Then it replies
    with a random entry of the same protocol which does not share the same
    address and port, and which is not very old.

    If the received port number is 0 the entry is not compared nor stored, but
    an entry of the same protocol is still sent back if available to the
    probe.  This can be used by probes which have not started their own peer
    (or have failed to do so) to just query for a peer of a given protocol.

    Old HTTP probes only send a port number.  This is also accepted, and in
    this case a protocol-less, HTTP URL-compatible string is sent back with
    the flags and time stamp encoded as query arguments.

    Example of received message (old HTTP probe on P2P port 80)::

        80

    Example of received message (new HTTP probe on P2P port 80 behind NAT)::

        80 HTTP nat

    Example of reply (new probe)::

        1500288137.95785 192.0.2.1:80 HTTP nat

    Example of reply (old probe, implicit HTTP)::

        192.0.2.1:80/?ts=1500288137.95785&nat=true

    NAT is assumed unless explicitly stated with the ``nonat`` flag.
    """

    def _parseInput(self, data):
        """Parse `data` and return a new `PeerEntry`.

        If `data` has a bad format, return `None`.
        """
        # Protect against garbage.
        data = data[:_max_data_len]
        if not _data_re.match(data):
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
                         proto=splitted[2], flags=tuple(splitted[3:]))

    def _formatPeerEntry(self, peer):
        """Format the given `peer` entry into a string."""
        return b'%f %s %s %s' % (peer.ts, peer.addr, peer.proto, ' '.join(peer.flags))

    def _formatPeerEntryOld(self, peer):
        """Format the given `peer` into an HTTP URL-compatible string."""
        s = b'%s/?ts=%f' % (peer.addr, peer.ts)
        s += b'&nat=%s' % ('false' if b'nonat' in peer.flags else 'true')
        return s

    def dataReceived(self, data):
        peer = self._parseInput(data)
        if not peer:
            return
        is_new_probe = bool(peer.flags)  # old probes report no flags

        log.msg("processing: %s" % (peer,))
        peer_data = (peer.addr, set(peer.flags))
        random_peer = None
        try:
            with open(config.helpers['peer-locator'].peer_list, 'a+') as peer_list_file:
                now = time.time()  # only consider entries not older than max peer age
                peer_list = filter(lambda p: ((now - p.ts) < MAX_PEER_AGE_SECS
                                              and p.proto == peer.proto),
                                   [self._parsePeerEntry(l) for l in peer_list_file.readlines()])
                if peer.addr.endswith(':0'):
                    log.msg('query-only request, not saving peer')
                elif peer_data in [(p.addr, set(p.flags)) for p in peer_list]:  # compare IP:PORT and flags
                    log.msg('we already know the peer')
                else:
                    log.msg('new peer')
                    peer_list_file.write(self._formatPeerEntry(peer) + '\n')

                # Get a peer entry with a different ``PUB_ADDR:PORT``.
                # Query-only peers never match since entries with port 0 are never stored.
                other_peers = [p for p in peer_list if p.addr != peer.addr]
                log.msg("choosing a random peer from a pool of %d peers" % len(other_peers))
                if other_peers:
                    random_peer = random.choice(other_peers)

        except IOError as e:
            log.msg("IOError %s" % e)

        if random_peer:
            log.msg("seeding: %s" % (random_peer,))
            out = (self._formatPeerEntry(random_peer) if is_new_probe
                   else self._formatPeerEntryOld(random_peer))
        else:
            log.msg("no other peers to seed")
            out = ''

        self.transport.write(out)
        self.transport.loseConnection()

class PeerLocatorHelper(Factory):
    protocol = PeerLocatorProtocol

