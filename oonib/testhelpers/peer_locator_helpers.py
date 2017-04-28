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
        import pdb
        pdb.set_trace()
        self_peer = self.transport.getPeer(),data
        try:
            self.peer_probes.append(self_peer)
        except NameError:
            self.peer_probes = [self_peer]
            
        random_peer = self_peer
        while(len(peer_probes) > 0 and random_peer == self_peer):
            random_peer = peer_probes[randint(0, peer_probes)]

        if (random_peer == self_peer):
            random_peer = ''

        self.transport.write(random_peer)

class PeerLocatorHelper(Factory):
    protocol = PeerLocatorProtocol

