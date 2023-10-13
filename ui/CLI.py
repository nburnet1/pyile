from ui.UI import UI


class CLI(UI):
    def __init__(self, config, peer):
        UI.__init__(self, config=config, peer=peer)

    def fill_user_data(self):
        pass
