import socket

from configuration.Configuration import Configuration
from ui.CLI import CLI
from ui.GUI import GUI


def main():
    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    print("Your Computer IP Address is: " + IPAddr)
    config = Configuration(IPAddr)
    print(config.argu)
    print(config.json_contents)

    if config.argu.gui:
        interface = GUI(config=config, peer=None)
    else:
        interface = CLI(config=config, peer=None)

    filled = config.check_user_data()

    while not filled:
        interface.config_popup()
        filled = config.check_user_data()
        if not filled:
            interface.warning_popup("Please fill out all user data.")

    try:
        config.write_json(config.json_contents)
    except FileNotFoundError:
        interface.error_popup("File could not be found.")

    print(config.json_contents)

    interface.start()


if __name__ == '__main__':
    main()
