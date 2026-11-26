"""Lightweight dark-theme tooltips — pure tkinter, no dependencies.

Usage: Tooltip(widget, "text"). Works on tk and ttk widgets, shows after a
short hover delay, hides on leave/click, and never steals focus.
"""
import tkinter as tk


class Tooltip:
    def __init__(self, widget, text, delay=450, width=340):
        self.widget = widget
        self.text = text
        self.delay = delay
        self.width = width
        self._after = None
        self._tip = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")
        widget.bind("<Destroy>", self._hide, add="+")

    def set_text(self, text):
        """Update the tooltip text live (e.g. Start/Stop changes meaning)."""
        self.text = text
        if self._tip:   # currently visible — refresh in place
            self._hide()
            self._schedule()

    def _schedule(self, _event=None):
        self._cancel()
        try:
            self._after = self.widget.after(self.delay, self._show)
        except Exception:
            pass

    def _cancel(self):
        if self._after:
            try:
                self.widget.after_cancel(self._after)
            except Exception:
                pass
            self._after = None

    def _hide(self, _event=None):
        self._cancel()
        if self._tip:
            try:
                self._tip.destroy()
            except Exception:
                pass
            self._tip = None

    def _show(self):
        self._after = None
        if self._tip:
            return
        # never explain a control the user cannot use right now
        try:
            if str(self.widget.cget("state")) == "disabled":
                return
        except (tk.TclError, AttributeError):
            pass
        try:
            if self.widget.instate(["disabled"]):
                return
        except (tk.TclError, AttributeError):
            pass
        try:
            x = self.widget.winfo_rootx() + 8
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
            self._tip = tk.Toplevel(master=self.widget.winfo_toplevel())
            self._tip.wm_overrideredirect(True)
            self._tip.attributes("-topmost", True)
            self._tip.wm_geometry(f"+{x}+{y}")
            lbl = tk.Label(
                self._tip, text=self.text, bg="#12161f", fg="#e6e9f0",
                relief="solid", borderwidth=1, font=("Segoe UI", 9),
                justify="left", padx=8, pady=5, wraplength=self.width)
            lbl.pack()
            # keep the tip on-screen: clamp at the edges, flip above the
            # widget when it would overflow the bottom
            self._tip.update_idletasks()
            sw = self._tip.winfo_screenwidth()
            sh = self._tip.winfo_screenheight()
            tw = self._tip.winfo_reqwidth()
            th = self._tip.winfo_reqheight()
            if x + tw > sw - 8:
                x = max(8, sw - tw - 8)
            if y + th > sh - 8:
                y = max(8, self.widget.winfo_rooty() - th - 6)
            self._tip.wm_geometry(f"+{x}+{y}")
            self._tip.bind("<Leave>", self._hide, add="+")
            self._tip.bind("<Enter>", self._hide, add="+")
        except Exception:
            self._tip = None
