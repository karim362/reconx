"""Termux detection & helpers."""
import os


def is_termux():
    return "com.termux" in os.environ.get("PREFIX", "")


def termux_info():
    if is_termux():
        return "Termux (Android)"
    return "Desktop"
