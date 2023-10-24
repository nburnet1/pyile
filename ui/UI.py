from typing import Union

from pyile_protocol.lib.peers.AuthPeer import AuthPeer
from pyile_protocol.lib.peers.Peer import Peer


class UI:
    def __init__(self, config, peer):
        if type(self) == UI:
            raise TypeError("UI cannot be directly instantiated")
        self.config = config
        self.peer: Union[Peer, AuthPeer, None] = None
