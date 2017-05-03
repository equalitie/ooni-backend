from twisted.internet.protocol import Protocol, Factory, ServerFactory

from oonib.config import config
from oonib import log

from random import randint
peers_probes = []

class PeerLocatorProtocol(Protocol):
    """
    A simple protocol to get the p2p ip:port of the probe 
    and send another pair in response
    """
    def dataReceived(self, data):
        self_peer = self.transport.getPeer(),data
        log.msg(str(self_peer))
        try:
            self.peer_probes.append(self_peer)
        except AttributeError:
            self.peer_probes = [self_peer]
            
        random_peer = self_peer
        while(len(self.peer_probes) > 1 and random_peer == self_peer):
            random_peer = peer_probes[randint(0, peer_probes)]

        if (random_peer == self_peer):
            random_peer = ''

        self.transport.write(random_peer)

class PeerLocatorHelper(Factory):
    protocol = PeerLocatorProtocol

