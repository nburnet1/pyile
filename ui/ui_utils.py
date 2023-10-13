import json
import tkinter as tk
from tkinter import ttk


def calc_screen(screensize, size):
    return int((screensize / 2) - (size / 2))


def configure_window_grid(window, row, column, row_weight, column_weight):
    for i in range(row):
        window.rowconfigure(index=i, weight=row_weight)
    for i in range(column):
        window.columnconfigure(index=i, weight=column_weight)
    return window


def on_entry_click(event, entry, text):
    if entry.get() == text:
        entry.delete(0, tk.END)  # Clear the placeholder text
        entry.configure(foreground="white")


def on_entry_leave(event, entry, text):
    if entry.get() == "":
        entry.configure(foreground="grey")
        entry.insert(0, text)


def center_window(window):
    window.update()
    window.minsize(window.winfo_width(), window.winfo_height())
    x_coordinate = calc_screen(window.winfo_screenwidth(), window.winfo_width())
    y_coordinate = calc_screen(window.winfo_screenheight(), window.winfo_height())
    window.geometry("+{}+{}".format(x_coordinate, y_coordinate))


def config_window(window):
    window.attributes("-topmost", True)
    window.option_add("*tearOff", False)
    style = ttk.Style(window)
    window.tk.call("source", "./styles/forest-dark.tcl")
    style.theme_use("forest-dark")

def check_json_data(text):
    try:
        json.loads(text)
        return True
    except json.decoder.JSONDecodeError:
        return None
