import argparse
import json


def arg_check():
    parser = argparse.ArgumentParser(description='P2P File Transfer Application')
    parser.add_argument('-s', '--start',
                        help="starts the connection as an Authenticating Peer, by default joins a connection.",
                        action="store_true", default=False)
    parser.add_argument('-i', '--ip', help="IPV4 that the starter node is at", nargs='?', type=str, default=None)
    parser.add_argument('-p', '--port', help="Port that the starter node is listening", nargs='?', type=int,
                        default=4702)
    parser.add_argument('-j', '--join_port', help="Port for joining node", nargs='?', type=int, default=4702)
    parser.add_argument('-g', '--gui', help="Launches GUI rather than command line", action="store_true", default=False)
    parser.add_argument('-a', '--alias', help="Specifies the alias used to connect", nargs='?', type=str,
                        default=None)
    parser.add_argument('-c', '--config', help="Specifies the config file to use", nargs='?', type=str,
                        default='config.json')
    parser.add_argument('-S', '--shadow', help="Specifies the shadow string to use", nargs='?', type=str, default=None)
    argu = parser.parse_args()
    return argu


class Configuration:
    def __init__(self, ip):
        self.argu = arg_check()
        self.json_path = self.argu.config
        self.json_contents = self.init_json()
        self.ip = ip

    def init_json(self):
        with open(self.json_path, 'r') as file:
            json_contents = json.load(file)
            return json_contents

    def write_json(self, json_update):
        try:
            with open(self.json_path, 'w') as file:
                json.dump(json_update, file, indent=4)
            return True
        except FileNotFoundError:
            return False

    def check_user_data(self):
        if self.argu.alias is None:
            if self.json_contents["general"]["alias"] is None \
                    or self.json_contents["general"]["alias"] == "":
                return False
        else:
            self.json_contents["general"]["alias"] = self.argu.alias

        if self.argu.port is None:
            if self.json_contents["auth_peer"]["port"] is None \
                    or self.json_contents["auth_peer"]["port"] == "":
                return False
        else:
            self.json_contents["auth_peer"]["port"] = self.argu.port

        if self.argu.join_port is None:
            if self.json_contents["join_peer"]["port"] is None \
                    or self.json_contents["join_peer"]["port"] == "":
                return False
        else:
            self.json_contents["join_peer"]["port"] = self.argu.join_port

        if self.argu.shadow is None:
            if self.json_contents["auth_peer"]["shadow"] is None \
                    or self.json_contents["auth_peer"]["shadow"] == "":
                return False

        return True

