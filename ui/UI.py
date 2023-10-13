class UI:
    def __init__(self, config, peer):
        if type(self) == UI:
            raise TypeError("UI cannot be directly instantiated")
        self.config = config
        self.peer = None

