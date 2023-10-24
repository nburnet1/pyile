import sys
import threading

from pyile_protocol.lib.messenger.Messenger import Messenger
from pyile_protocol.lib.peers.AuthPeer import AuthPeer
from pyile_protocol.lib.peers.JoinPeer import JoinPeer

from ui.UI import UI
import tkinter as tk
from tkinter import ttk, scrolledtext

from ui.ui_utils import *


class GUI(UI):
    def __init__(self, config, peer):
        UI.__init__(self, config=config, peer=peer)
        self.config_window = None
        self.main_window = None
        self.warning_window = None
        self.error_window = None
        self.main_notebook = None
        self.info_window = None
        self.selected_conversation = None

    def info_popup(self, message):
        self.info_window = tk.Tk()
        self.info_window.title("Info")

        config_window(self.info_window)

        self.info_window = configure_window_grid(self.info_window, 7, 7, 1, 1)

        contents = tk.Text(self.info_window,
                           font=("TkDefaultFont", 14))
        contents.grid(row=1, column=4, padx=10, pady=(30, 10), sticky="nsew")
        contents.insert(tk.END, message)

        self.info_window.update()
        self.info_window.minsize(self.info_window.winfo_width(), self.info_window.winfo_height())
        x_coordinate = calc_screen(self.info_window.winfo_screenwidth(), self.info_window.winfo_width())
        y_coordinate = calc_screen(self.info_window.winfo_screenheight(), self.info_window.winfo_height())
        self.info_window.geometry("+{}+{}".format(x_coordinate, y_coordinate))

    def warning_popup(self, message):
        self.warning_window = tk.Tk()
        self.warning_window.title("Warning")

        config_window(self.warning_window)

        self.warning_window = configure_window_grid(self.warning_window, 7, 7, 1, 1)

        self.main_window.state("withdrawn")
        self.warning_window.protocol("WM_DELETE_WINDOW", lambda: self.on_popup_close(self.warning_window))

        contents = tk.Text(self.warning_window,
                           font=("TkDefaultFont", 14))
        contents.grid(row=1, column=4, padx=10, pady=(30, 10), sticky="nsew")
        contents.insert(tk.END, message)

        center_window(self.warning_window)

    def error_popup(self, message):
        self.error_window = tk.Tk()
        self.error_window.title("Error")

        config_window(self.error_window)

        self.error_window.geometry("300x300")
        self.error_window = configure_window_grid(self.error_window, 7, 7, 1, 1)
        header = ttk.Label(self.error_window, text="Error:",
                           font=("TkDefaultFont", 16))
        header.grid(row=0, column=3, padx=10, pady=(30, 10), sticky="nsew", columnspan=1)
        subheader = ttk.Label(self.error_window,
                              text=message,
                              font=("TkDefaultFont", 14))
        subheader.grid(row=1, column=4, padx=10, pady=(30, 10), sticky="nsew", columnspan=1)
        self.main_window.state("withdrawn")
        self.error_window.protocol("WM_DELETE_WINDOW", lambda: self.exit_gui())
        center_window(self.error_window)

    def config_popup(self):
        def submit(text_widget):
            text = text_widget.get("1.0", tk.END)

            if check_json_data(text):
                self.config.json_contents = json.loads(text)
                self.config_window.destroy()
            else:
                self.warning_popup("Invalid JSON data.")

        self.config_window = tk.Tk()
        self.config_window.title("Please Fill out User Data")

        config_window(self.config_window)

        self.config_window.protocol("WM_DELETE_WINDOW", lambda: sys.exit(1))

        self.config_window = configure_window_grid(self.config_window, 7, 7, 1, 1)

        header = ttk.Label(self.config_window, text="Please fill out any blank information.",
                           font=("TkDefaultFont", 16))
        header.grid(row=0, column=0, padx=10, pady=(30, 10), sticky="nsew", columnspan=1)
        subheader = ttk.Label(self.config_window,
                              text="This file is referenced and can later be found at " + str(self.config.json_path),
                              font=("TkDefaultFont", 14))
        subheader.grid(row=1, column=0, padx=10, pady=(30, 10), sticky="nsew", columnspan=1)

        text_widget = tk.Text(self.config_window, font=("TkDefaultFont", 16))
        text_widget.grid(row=3, column=0, padx=10, pady=(30, 10), sticky="nsew")
        json_str = json.dumps(self.config.json_contents, indent=4)
        text_widget.insert(tk.END, json_str)

        accent_button = ttk.Button(self.config_window, command=lambda: submit(text_widget), text="Save & Continue",
                                   style="Accent.TButton")
        accent_button.grid(row=4, column=0, padx=5, pady=10, sticky="nsew")

        center_window(self.config_window)

        self.config_window.mainloop()

    def connect(self, shadow, ip, port, alias, join_port, connect_tab):
        self.config.json_contents["general"]["alias"] = alias
        self.config.json_contents["auth_peer"]["port"] = port
        self.config.json_contents["join_peer"]["port"] = join_port
        self.config.write_json(self.config.json_contents)

        # 192.168.1.65
        self.peer = JoinPeer(address=("self.config.ip", join_port), alias=alias, messenger=Messenger())
        try:
            self.peer.get_authenticated((ip, port), shadow)
        except Exception as e:
            self.warning_popup("Could not connect to peer. The authenticating peer may not be running." + str(e))
            return

        connect_thread = threading.Thread(target=self.peer.connect)
        connect_thread.start()

        self.main_notebook.select(1)
        connect_tab.destroy()

    def auth(self, shadow, port, allowed_attempts, alias, admin_tab):
        self.config.json_contents["general"]["alias"] = alias
        self.config.json_contents["auth_peer"]["port"] = port
        self.config.json_contents["auth_peer"]["password_attempts_allowed"] = allowed_attempts
        self.config.json_contents["auth_peer"]["shadow"] = shadow

        # 192.168.1.65
        self.peer = AuthPeer(address=("self.config.ip", port), alias=alias, messenger=Messenger(),
                             password_attempts=allowed_attempts, password=shadow)

        print(self.peer)
        auth_thread = threading.Thread(target=self.peer.authenticate_peers)
        peer_thread = threading.Thread(target=self.peer.connect)
        auth_thread.start()
        peer_thread.start()

        self.main_notebook.select(1)
        admin_tab.destroy()

    def exit_gui(self):
        if self.peer is not None:
            self.peer.leave()
        self.main_window.destroy()
        sys.exit(0)

    def on_popup_close(self, window):
        self.main_window.state("normal")
        window.destroy()

    def check_peer_tree(self, treeview, length):
        if self.peer is not None and len(self.peer.peers) != length:
            treeview.delete(*treeview.get_children())
            treeview.insert("", "end", iid="Broadcast", text="Broadcast")
            for peer in self.peer.peers:
                if peer != self.peer.peer_address:
                    treeview.insert("", "end", iid=peer, text=peer)
            length = len(self.peer.peers)
            if self.selected_conversation is not None:
                if self.selected_conversation == "Broadcast":
                    treeview.selection_set(self.selected_conversation)
                else:
                    converted_value = self.selected_conversation[0] + " " + str(self.selected_conversation[1])
                    if converted_value in treeview.get_children():
                        treeview.selection_set(converted_value)
                    else:
                        self.selected_conversation = None

        treeview.after(1000, lambda: self.check_peer_tree(treeview, length))

    def on_peer_tree_select(self, treeview, message_display, length):
        selected_item = treeview.selection()
        if len(selected_item) == 0:
            return
        if selected_item[0] == "Broadcast":
            self.selected_conversation = "Broadcast"
        else:
            item_list = selected_item[0].split()
            item_list[1] = int(item_list[1])
            self.selected_conversation = tuple(item_list)

        if self.selected_conversation not in self.peer.messenger.messages:
            message_display.config(state=tk.NORMAL)
            message_display.delete("1.0", tk.END)
            message_display.insert(tk.END, "No Conversations Yet.")
            conversation_length = 0
        else:
            conversation_length = len(self.peer.messenger.messages[self.selected_conversation])

            if conversation_length != length:
                message_display.config(state=tk.NORMAL)
                message_display.delete("1.0", tk.END)
                for i in self.peer.messenger.messages[self.selected_conversation]:
                    message_display.insert(tk.END, i['message']['alias'] + "\n" + i['message']['data'] + "\n\n")
                message_display.config(state=tk.DISABLED)

        message_display.after(1000, lambda: self.on_peer_tree_select(treeview, message_display, conversation_length))

    def handle_message(self, entry):
        if self.peer is None:
            self.info_popup("Peer is not connected.")
        elif self.selected_conversation is None:
            self.info_popup("Please select a conversation.")
        else:
            message = entry.get()
            entry.delete(0, tk.END)
            if len(message) > 0 and message != "" and message != " ":
                if self.selected_conversation == "Broadcast":
                    self.peer.broadcast(message)
                else:
                    self.peer.send(self.selected_conversation, message, self.selected_conversation)
            entry.focus_set()

    def status_check(self, peer_view, banned_view, limbo_view, dist_view, view_lengths):
        def redraw(i):
            def tree_insert(view, view_list):
                view.delete(*view.get_children())
                for i in view_list:
                    view.insert("", "end", iid=i, text=i)

            if i == 0:
                tree_insert(peer_view, self.peer.peers)
            elif i == 1:
                tree_insert(banned_view, self.peer.blocked_peers)
            elif i == 2:
                tree_insert(limbo_view, self.peer.limbo_peers)
            elif i == 3:
                tree_insert(dist_view, self.peer.dist_sockets)

        if self.peer is not None:
            temp_list = [len(self.peer.peers), len(self.peer.blocked_peers), len(self.peer.limbo_peers),
                         len(self.peer.dist_sockets)]

            for i in range(len(temp_list)):
                if temp_list[i] != view_lengths[i]:
                    view_lengths[i] = temp_list[i]
                    redraw(i)

        peer_view.after(1000, lambda: self.status_check(peer_view, banned_view, limbo_view, dist_view, view_lengths))

    def start(self):
        def check_for_errors():
            if self.peer is not None:
                if len(self.peer.messenger.errors) > 0:
                    self.error_popup(self.peer.messenger.errors[-1]['message'])
                    return
            self.main_window.after(1000, check_for_errors)

        def connect_tab():
            connect_tab = ttk.Frame(self.main_notebook)
            self.main_notebook.add(connect_tab, text="Connect")
            info_frame = ttk.Frame(connect_tab)
            info_frame.pack(expand=True)

            ip_frame = ttk.Frame(info_frame, padding=(0, 10))
            ip_frame.pack(side="top", expand=True, fill="x")
            ip_label = ttk.Label(ip_frame, text="IP: ")
            ip_label.pack(side="left")
            ip_label_value = ttk.Label(ip_frame, text=self.config.ip, )
            ip_label_value.pack(side="right")

            alias_frame = ttk.Frame(info_frame)
            alias_frame.pack(side="top", expand=True, fill="x")
            alias_label = ttk.Label(alias_frame, text="Alias: ")
            alias_label.pack(side="left")
            alias_entry = ttk.Entry(alias_frame)
            if self.config.json_contents["general"]["alias"] is not None:
                alias_entry.insert(0, self.config.json_contents["general"]["alias"])
            elif self.config.argu.alias is not None:
                alias_entry.insert(0, self.config.argu.alias)

            alias_entry.pack(side="right")
            auth_frame = ttk.Frame(info_frame)
            auth_frame.pack(side="top", expand=True, fill="x")
            auth_label = ttk.Label(auth_frame, text="Authenticating Peer: ")
            auth_label.pack(side="left")
            auth_entry = ttk.Entry(auth_frame)
            if self.config.argu.ip is not None:
                auth_entry.insert(0, self.config.argu.ip)
            auth_entry.pack(side="right")

            port_frame = ttk.Frame(info_frame)
            port_frame.pack(side="top", expand=True, fill="x")
            port_label = ttk.Label(port_frame, text="Authenticating Port: ")
            port_label.pack(side="left")
            port_entry = ttk.Entry(port_frame)
            if self.config.json_contents["join_peer"]["port"] is not None:
                port_entry.insert(0, self.config.json_contents["auth_peer"]["port"])
            elif self.config.argu.port is not None:
                port_entry.insert(0, self.config.argu.port)
            port_entry.pack(side="right")

            join_port_frame = ttk.Frame(info_frame)
            join_port_frame.pack(side="top", expand=True, fill="x")
            join_port_label = ttk.Label(join_port_frame, text="Joining Port: ")
            join_port_label.pack(side="left")
            join_port_entry = ttk.Entry(join_port_frame)
            if self.config.json_contents["join_peer"]["port"] is not None:
                join_port_entry.insert(0, self.config.json_contents["join_peer"]["port"])
            elif self.config.argu.join_port is not None:
                join_port_entry.insert(0, self.config.argu.join_port)
            join_port_entry.pack(side="right")

            password_frame = ttk.Frame(info_frame)
            password_frame.pack(side="top", expand=True, fill="x")
            password_label = ttk.Label(password_frame, text="Password: ")
            password_label.pack(side="left")
            password_entry = ttk.Entry(password_frame, show="*")
            if self.config.argu.shadow is not None:
                password_entry.insert(0, self.config.argu.shadow)
            password_entry.pack(side="right")

            connect_button = ttk.Button(info_frame, text="Connect", style="Accent.TButton",
                                        command=lambda: self.connect(
                                            password_entry.get(), auth_entry.get(), int(port_entry.get()),
                                            alias_entry.get(), int(join_port_entry.get()), connect_tab))
            connect_button.pack(side="bottom", expand=True, fill="x", pady=10)

        def message_tab():

            message_tab = ttk.Frame(self.main_notebook)
            self.main_notebook.add(message_tab, text="Messages")
            # Scrollbar
            # Tree Frame
            tree_frame = ttk.Frame(message_tab)
            tree_frame.pack(side="left", expand=True, fill="both")
            tree_scroll = ttk.Scrollbar(tree_frame)
            tree_scroll.pack(side="right", fill="y")
            # Treeview
            tree_view = ttk.Treeview(tree_frame, selectmode="extended", yscrollcommand=tree_scroll.set,
                                     height=12)
            tree_view.pack(expand=True, fill="both", side="left")
            tree_view.yview_moveto(1.0)
            tree_scroll.config(command=tree_view.yview)

            # Treeview columns
            tree_view.column("#0", width=120)

            # Treeview headings
            tree_view.heading("#0", text="Available Conversations", anchor="center")

            self.check_peer_tree(tree_view, 0)

            # Messaging Frame
            message_frame = ttk.Frame(message_tab)
            message_frame.pack(side="right", expand=True, fill="both")
            message_display = scrolledtext.ScrolledText(message_frame, wrap=tk.WORD, state=tk.DISABLED)
            message_display.pack(padx=10, pady=10, side="top", expand=True, fill="both")
            entry_frame = ttk.Frame(message_frame)
            entry_frame.pack(padx=10, pady=10, side="bottom", fill="x")
            entry = ttk.Entry(entry_frame)
            entry.pack(side="left", expand=True, fill="x")
            entry.bind("<FocusIn>", lambda event, entry=entry: on_entry_click(event, entry, "Send Message to Peer..."))
            entry.bind("<FocusOut>", lambda event, entry=entry: on_entry_leave(event, entry, "Send Message to Peer..."))
            entry.bind("<Return>", lambda event, entry=entry: self.handle_message(entry))
            send_button = ttk.Button(entry_frame, text="Send", style="Accent.TButton",
                                     command=lambda: self.handle_message(entry))
            send_button.pack(side="right", expand=False, fill="x")
            on_entry_leave(None, entry, "Send Message to Peer...")
            tree_view.bind("<<TreeviewSelect>>",
                           lambda event, tree_view=tree_view, message_display=message_display: self.on_peer_tree_select(
                               tree_view, message_display, 0))

        def admin_tab():
            admin_tab = ttk.Frame(self.main_notebook)
            self.main_notebook.add(admin_tab, text="Admin")
            info_frame = ttk.Frame(admin_tab)
            info_frame.pack(expand=True)

            ip_frame = ttk.Frame(info_frame, padding=(0, 10))
            ip_frame.pack(side="top", expand=True, fill="x")
            ip_label = ttk.Label(ip_frame, text="IP: ")
            ip_label.pack(side="left")
            ip_label_value = ttk.Label(ip_frame, text=self.config.ip, )
            ip_label_value.pack(side="right")

            alias_frame = ttk.Frame(info_frame)
            alias_frame.pack(side="top", expand=True, fill="x")
            alias_label = ttk.Label(alias_frame, text="Alias: ")
            alias_label.pack(side="left")
            alias_entry = ttk.Entry(alias_frame)
            if self.config.json_contents["general"]["alias"] is not None:
                alias_entry.insert(0, self.config.json_contents["general"]["alias"])
            elif self.config.argu.alias is not None:
                alias_entry.insert(0, self.config.argu.alias)
            alias_entry.pack(side="right")

            port_frame = ttk.Frame(info_frame)
            port_frame.pack(side="top", expand=True, fill="x")
            port_label = ttk.Label(port_frame, text="Port: ")
            port_label.pack(side="left")
            port_entry = ttk.Entry(port_frame)
            if self.config.json_contents["join_peer"]["port"] is not None:
                port_entry.insert(0, self.config.json_contents["join_peer"]["port"])
            elif self.config.argu.port is not None:
                port_entry.insert(0, self.config.argu.port)
            port_entry.pack(side="right")

            password_frame = ttk.Frame(info_frame)
            password_frame.pack(side="top", expand=True, fill="x")
            password_label = ttk.Label(password_frame, text="Password: ")
            password_label.pack(side="left")
            password_entry = ttk.Entry(password_frame, show="*")
            if self.config.argu.shadow is not None:
                password_entry.insert(0, self.config.argu.shadow)
            password_entry.pack(side="right")

            allowed_attempts = ttk.Frame(info_frame)
            allowed_attempts.pack(side="top", expand=True, fill="x")
            allowed_attempts_label = ttk.Label(allowed_attempts, text="Allowed Attempts: ")
            allowed_attempts_label.pack(side="left")
            allowed_attempts_entry = ttk.Entry(allowed_attempts)
            if self.config.json_contents["auth_peer"]["password_attempts_allowed"] is not None:
                allowed_attempts_entry.insert(0, self.config.json_contents["auth_peer"]["password_attempts_allowed"])
            allowed_attempts_entry.pack(side="right")

            start_button = ttk.Button(info_frame, text="Start", style="Accent.TButton",
                                      command=lambda: self.auth(
                                          password_entry.get(), int(port_entry.get()),
                                          int(allowed_attempts_entry.get()),
                                          alias_entry.get(), admin_tab
                                      ))
            start_button.pack(side="bottom", expand=True, fill="x", pady=10)

        def status_tab():
            status_tab = ttk.Frame(self.main_notebook)
            self.main_notebook.add(status_tab, text="Status")

            tree_frame = ttk.Frame(status_tab)
            tree_frame.pack(side="left", expand=True, fill="both")

            dist_frame = ttk.Frame(tree_frame)
            dist_frame.pack(side="bottom", expand=True, fill="both")
            dist_scroll = ttk.Scrollbar(dist_frame)
            dist_scroll.pack(side="right", fill="y")
            # Treeview
            dist_view = ttk.Treeview(dist_frame, selectmode="extended", yscrollcommand=dist_scroll.set,
                                     height=12)
            dist_view.pack(expand=True, fill="both", side="left")
            dist_view.yview_moveto(1.0)
            dist_scroll.config(command=dist_view.yview)

            # Treeview columns
            dist_view.column("#0", width=120)

            # Treeview headings
            dist_view.heading("#0", text="Distribute Connections", anchor="center")

            limbo_scroll = ttk.Scrollbar(tree_frame)
            limbo_scroll.pack(side="right", fill="y")
            # Treeview
            limbo_view = ttk.Treeview(tree_frame, selectmode="extended", yscrollcommand=limbo_scroll.set,
                                      height=12)
            limbo_view.pack(expand=True, fill="both", side="right")
            limbo_view.yview_moveto(1.0)
            limbo_scroll.config(command=limbo_view.yview)

            # Treeview columns
            limbo_view.column("#0", width=120)

            # Treeview headings
            limbo_view.heading("#0", text="Limbo Peers", anchor="center")

            banned_scroll = ttk.Scrollbar(tree_frame)
            banned_scroll.pack(side="right", fill="y")
            # Treeview
            banned_view = ttk.Treeview(tree_frame, selectmode="extended", yscrollcommand=banned_scroll.set,
                                       height=12)
            banned_view.pack(expand=True, fill="both", side="right")
            banned_view.yview_moveto(1.0)
            banned_scroll.config(command=banned_view.yview)

            # Treeview columns
            banned_view.column("#0", width=120)

            # Treeview headings
            banned_view.heading("#0", text="Banned Peers", anchor="center")

            peer_scroll = ttk.Scrollbar(tree_frame)
            peer_scroll.pack(side="right", fill="y")
            # Treeview
            peer_view = ttk.Treeview(tree_frame, selectmode="extended", yscrollcommand=peer_scroll.set,
                                     height=12)
            peer_view.pack(expand=True, fill="both", side="left")
            peer_view.yview_moveto(1.0)
            peer_scroll.config(command=peer_view.yview)

            # Treeview columns
            peer_view.column("#0", width=120)

            # Treeview headings
            peer_view.heading("#0", text="Peers", anchor="center")

            self.status_check(peer_view, banned_view, limbo_view, dist_view, [0, 0, 0, 0])

        def log_tab():
            def update_treeview(self, tree_view, value):
                # Update the Treeview data based on the selected radio button
                # Get the selected radio button's value
                # Clear the Treeview
                tree_view.delete(*tree_view.get_children())
                # Add data to the Treeview based on the selected radio button value
                if self.peer is None:
                    self.info_popup("Peer is not connected.")
                elif value == -1:  # All
                    for item in self.peer.messenger.seq_list:
                        tree_view.insert("", "end", values=(item["state"], item['time_stamp'], item['message']))
                elif value == 0:  # Info
                    for item in self.peer.messenger.info:
                        tree_view.insert("", "end", values=(item["state"], item['time_stamp'], item['message']))
                elif value == 1:  # Warning
                    for item in self.peer.messenger.warnings:
                        tree_view.insert("", "end", values=(item["state"], item['time_stamp'], item['message']))
                elif value == 2:  # Error
                    for item in self.peer.messenger.errors:
                        tree_view.insert("", "end", values=(item["state"], item['time_stamp'], item['message']))

            log_tab = ttk.Frame(self.main_notebook)
            self.main_notebook.add(log_tab, text="Log")
            radio_frame = ttk.Frame(log_tab)
            radio_frame.pack(side="top", fill="x")

            all_radio = ttk.Radiobutton(radio_frame, text="All", value=-1,
                                        command=lambda: update_treeview(self, tree_view, -1))
            all_radio.pack(side="left")
            info_radio = ttk.Radiobutton(radio_frame, text="Info", value=0,
                                         command=lambda: update_treeview(self, tree_view, 0))
            info_radio.pack(side="left")
            warning_radio = ttk.Radiobutton(radio_frame, text="Warning", value=1,
                                            command=lambda: update_treeview(self, tree_view, 1))
            warning_radio.pack(side="left")
            error_radio = ttk.Radiobutton(radio_frame, text="Error", value=2,
                                          command=lambda: update_treeview(self, tree_view, 2))
            error_radio.pack(side="left")

            tree_frame = ttk.Frame(log_tab)
            tree_frame.pack(side="right", expand=True, fill="both")
            tree_scroll_y = ttk.Scrollbar(tree_frame)
            tree_scroll_y.pack(side="right", fill="y")

            tree_scroll_x = ttk.Scrollbar(tree_frame, orient="horizontal")
            tree_scroll_x.pack(side="bottom", fill="x")

            tree_view = ttk.Treeview(tree_frame, selectmode="extended", yscrollcommand=tree_scroll_y.set,
                                     xscrollcommand=tree_scroll_x.set, height=12, columns=("#1", "#2", "#3"),
                                     show="headings")
            tree_view.pack(expand=True, fill="both", side="left")
            tree_scroll_y.config(command=tree_view.yview)
            tree_scroll_x.config(command=tree_view.xview)

            # Treeview columns

            tree_view.column("#1", width=100)
            tree_view.column("#2", minwidth=200)
            tree_view.column("#3", minwidth=500)
            # Treeview headings
            tree_view.heading("#1", text="State", anchor="w")
            tree_view.heading("#2", text="Time", anchor="w")
            tree_view.heading("#3", text="Message", anchor="w")

        self.main_window = tk.Tk()
        self.main_window.title("Pyile")
        config_window(self.main_window)
        self.main_window.protocol("WM_DELETE_WINDOW", lambda: self.exit_gui())
        configure_window_grid(self.main_window, 7, 7, 1, 1)

        header = ttk.Label(self.main_window, text="Pyile",
                           font=("TkDefaultFont", 16))
        header.grid(row=0, column=0, padx=10, pady=(30, 10), sticky="nsew")
        self.main_notebook = ttk.Notebook(self.main_window)
        self.main_notebook.grid(row=1, column=0, padx=10, pady=(30, 10), sticky="nsew", rowspan=4, columnspan=7)

        check_for_errors()

        if self.config.argu.start:
            admin_tab()
            status_tab()
        else:
            connect_tab()

        message_tab()

        log_tab()

        self.main_notebook = configure_window_grid(self.main_notebook, 1, 1, 1, 1)

        center_window(self.main_window)

        self.main_window.mainloop()
