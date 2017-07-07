from twisted.internet.protocol import Protocol, Factory, ServerFactory

from oonib.config import config
from oonib import log

import random
import re

_max_data_len = len('[0123:4567:89ab:cdef:0123:4567:89ab:cdef]:65535')
# Accept ``PORT`` or ``ADDR:PORT`` with IPv4 ``ADDR`` or IPv6 ``[ADDR]``.
_data_re = re.compile('^(?:([.0-9]+|\[[:0-9a-fA-F]+\]):)?([0-9]+)$')

class PeerLocatorProtocol(Protocol):
    """
    A simple protocol to get the p2p ip:port of the probe 
    and send another pair in response
    """
    def dataReceived(self, data):
        match = _data_re.match(data[:_max_data_len])  # protect against garbage
        if not match:
            return
        (local_addr, port) = match.groups()

        remote_addr = self.transport.getPeer().host
        self_peer = self_peer_short = '%s:%s' % (remote_addr, port)
        if local_addr:
            self_peer += ('/?nat=%s' % str(local_addr == remote_addr).lower())
        random_peer = self_peer

        log.msg("registering: %s" % self_peer)
        try:
            with open(config.helpers['peer-locator'].peer_list, 'a+') as peer_list_file:
                peer_list = [peer.strip() for peer in peer_list_file.readlines()]
                if self_peer in peer_list:
                    log.msg('we already know the peer')
                else:
                    log.msg('new peer %s' % self_peer)
                    peer_list_file.write(self_peer + '\n')
                    peer_list.append(self_peer)
                peer_pool_size = len(peer_list)

                log.msg(str(peer_list))
                log.msg("choosing a random peer from pool of %d peers" % peer_pool_size)
                # The file may contain ``PUB_ADDR:PORT`` or ``PUB_ADDR:PORT/?QUERY_ARGS`` entries,
                # do not return any entry with the same ``PUB_ADDR:PORT``.
                random_peer_short = self_peer_short
                while(peer_pool_size > 1 and random_peer_short == self_peer_short):
                    # If the list only contains the sort and a long version of the same peer,
                    # this will loop forever.  However this should be a very rare case.
                    random_peer = random.choice(peer_list)
                    random_peer_short = random_peer.split('/')[0]

        except IOError as e:
            log.msg("IOError %s" % e)

        log.msg("seeding peer %s to peer %s" % (random_peer, self_peer))
        if (random_peer_short == self_peer_short):
            random_peer = ''

        self.transport.write(random_peer)

class PeerLocatorHelper(Factory):
    protocol = PeerLocatorProtocol

