from twisted.internet.protocol import Protocol, Factory, ServerFactory

from oonib.config import config
from oonib import log

import random
import re
import time

# Accept ``PORT[ FLAG]...``.
_max_data_len = 100
_data_re = re.compile(r'^([0-9]+)( [_a-z]+)*$')

# Discard peer entries older than this many seconds.
MAX_PEER_AGE_SECS = 2 * 24 * 60 * 60  # 2 days

class PeerLocatorProtocol(Protocol):
    """A simple protocol to get the P2P address of a probe and send that of
    another one in response.

    The helper receives a string with either just a port number (for old
    pobes) or a port number and a set of flags (for new probes).  It stores a
    time-stamped entry with the probe's public address, the reported port
    number and flags.  Then it replies with a random entry which does not
    share the same address and port.  For old probes, a protocol-less,
    URL-compatible string is sent back with the flags and time stamp encoded
    as query arguments.

    Example of received message (old probe on P2P port 80)::

        80

    Example of received message (new probe on P2P port 80 behind NAT)::

        80 nat

    Example of reply (new probe)::

        1500288137.95785 192.0.2.1:80 nat

    Example of reply (old probe)::

        192.0.2.1:80/?ts=1500288137.95785&nat=true
    """

    def _parseInput(self, data):
        """Parse `data` and return a tuple of current time stamp, address and flags.

        If `data` has a bad format, return `None`.
        """
        # Protect against garbage.
        data = data[:_max_data_len]
        if not _data_re.match(data)
            return

        # Construct the entry.
        splitted = data.split()
        port = int(splitted[0])
        flags = tuple(splitted[1:])

        return (time.time(), b'%s:%d' % (self.transport.getPeer().host, port), flags)

    def _parsePeerEntry(self, data):
        """Parse `data` and return a peer entry tuple."""
        splitted = data.split()
        return (float(splitted[0]), splitted[1], tuple(splitted([2:])))

    def _formatPeerEntry(self, peer):
        """Format the given `peer` into a string."""
        return b'%f %s %s' % (peer[0], peer[1], ' '.join(peer[2]))

    def _formatPeerEntryOld(self, peer):
        """Format the given `peer` into a URL-compatible string."""
        (ts, addr, flags) = peer
        s = b'%s/?ts=%f' % (addr, ts)
        s += b'&nat=%s' % bytes(b'nat' in flags).lower()
        return s

    def dataReceived(self, data):
        peer = self._parseInput(data)
        if not peer:
            return
        (ts, peer_addr, flags) = peer
        is_old_probe = bool(flags)  # old probes report no flags

        log.msg("registering: %s" % peer_addr)
        random_peer_addr = peer_addr
        try:
            with open(config.helpers['peer-locator'].peer_list, 'a+') as peer_list_file:
                now = time.time()  # only consider entries not older than max peer age
                peer_list = filter(lambda p: ((now - p[0]) < MAX_PEER_AGE_SECS),
                                   [_parsePeerEntry(l) for l in peer_list_file.readlines()])
                if peer_addr in [p[1] for p in peer_list]:  # only compare IP:PORT
                    log.msg('we already know the peer')
                else:
                    log.msg('new peer: %s' % (peer,))
                    peer_list_file.write(_formatPeerEntry(peer) + '\n')
                    peer_list.append(peer)
                peer_pool_size = len(peer_list)

                log.msg(str(peer_list))
                log.msg("choosing a random peer from pool of %d peers" % peer_pool_size)
                # Do not return any entry with the same ``PUB_ADDR:PORT``.
                while(peer_pool_size > 1 and random_peer_addr == peer_addr):
                    random_peer = random.choice(peer_list)
                    random_peer_addr = random_peer[1]

        except IOError as e:
            log.msg("IOError %s" % e)

        if (random_peer_addr == peer_addr):
            out = ''
        else:
            log.msg("seeding peer %s to peer %s" % (random_peer_addr, peer_addr))
            out = (_formatPeerEntry(random_peer) if not is_old_probe
                   else _formatPeerEntryOld(random_peer))

        self.transport.write(out)

class PeerLocatorHelper(Factory):
    protocol = PeerLocatorProtocol

