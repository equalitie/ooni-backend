from twisted.internet.protocol import Protocol, Factory, ServerFactory

from oonib.config import config
from oonib import log

import random

class PeerLocatorProtocol(Protocol):
    """
    A simple protocol to get the p2p ip:port of the probe 
    and send another pair in response
    """
    def dataReceived(self, data):
        self_peer = random_peer = '%s:%s' % (self.transport.getPeer().host, data)
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
                while(peer_pool_size > 1 and random_peer == self_peer):
                    random_peer = random.choice(peer_list)

        except IOError as e:
            log.msg("IOError %s" % e)

        log.msg("seeding peer %s to peer %s" % (random_peer, self_peer))
        if (random_peer == self_peer):
            random_peer = ''

        self.transport.write(random_peer)

class PeerLocatorHelper(Factory):
    protocol = PeerLocatorProtocol

