"""Lightweight dark-theme tooltips — pure tkinter, no dependencies.

Usage: Tooltip(widget, "text"). Works on tk and ttk widgets, shows after a
short hover delay, hides on leave/click, and never steals focus.

DISABLED widgets DO get their tooltip (the older 'never explain a control
the user cannot use' policy made controls that spend most of their life
disabled — the Download button before an update is found, every Settings
field while the proxy runs — feel like they had no tooltip at all). The
normal text describes the control either way; callers that need a special
disabled-state explanation can pass disabled_text=...
"""
import tkinter as tk


class Tooltip:
    def __init__(self, widget, text, delay=450, width=340, disabled_text=None):
        self.widget = widget
        self.text = text
        self.disabled_text = disabled_text   # None = show the normal text
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
        text = self.text
        try:
            disabled = (str(self.widget.cget("state")) == "disabled")
        except (tk.TclError, AttributeError):
            disabled = False
        try:
            disabled = disabled or self.widget.instate(["disabled"])
        except (tk.TclError, AttributeError):
            pass
        if disabled:
            if self.disabled_text is None:
                pass                  # show the normal text on disabled too
            else:
                text = self.disabled_text
        try:
            x = self.widget.winfo_rootx() + 8
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
            self._tip = tk.Toplevel(master=self.widget.winfo_toplevel())
            self._tip.wm_overrideredirect(True)
            self._tip.attributes("-topmost", True)
            self._tip.wm_geometry(f"+{x}+{y}")
            lbl = tk.Label(
                self._tip, text=text, bg="#12161f", fg="#e6e9f0",
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


class NotebookTips:
    """Tooltips for ttk.Notebook TAB headers (a plain Tooltip can't target
    a tab). Hovering a tab shows that tab's description; the tip follows
    the cursor between tabs and hides off-tab. Never raises."""

    def __init__(self, notebook, texts, delay=450):
        self.nb = notebook
        self.texts = list(texts)
        self.delay = delay
        self._after = None
        self._tip = None
        self._index = -1
        notebook.bind("<Motion>", self._motion, add="+")
        notebook.bind("<Leave>", self._hide, add="+")
        notebook.bind("<ButtonPress>", self._hide, add="+")
        notebook.bind("<Destroy>", self._hide, add="+")

    def _cancel(self):
        if self._after:
            try:
                self.nb.after_cancel(self._after)
            except Exception:
                pass
            self._after = None

    def _hide(self, _event=None):
        self._cancel()
        self._index = -1
        if self._tip:
            try:
                self._tip.destroy()
            except Exception:
                pass
            self._tip = None

    def _motion(self, event):
        try:
            idx = self.nb.index(f"@{event.x},{event.y}")
        except Exception:
            self._hide()
            return
        if idx == self._index:
            return                       # same tab — keep the current tip
        self._hide()
        if idx < 0 or idx >= len(self.texts) or not self.texts[idx]:
            return
        self._index = idx
        try:
            self._after = self.nb.after(self.delay, lambda: self._show(idx))
        except Exception:
            self._after = None

    def _show(self, idx):
        self._after = None
        self._tip = tk.Toplevel(master=self.nb.winfo_toplevel())
        self._tip.wm_overrideredirect(True)
        self._tip.attributes("-topmost", True)
        x = self.nb.winfo_rootx() + 12
        y = self.nb.winfo_rooty() + 40
        self._tip.wm_geometry(f"+{x}+{y}")
        lbl = tk.Label(
            self._tip, text=self.texts[idx], bg="#12161f", fg="#e6e9f0",
            relief="solid", borderwidth=1, font=("Segoe UI", 9),
            justify="left", padx=8, pady=5, wraplength=380)
        lbl.pack()
        self._tip.update_idletasks()
        if x + self._tip.winfo_reqwidth() > self._tip.winfo_screenwidth() - 8:
            x = max(8, self._tip.winfo_screenwidth()
                    - self._tip.winfo_reqwidth() - 8)
            self._tip.wm_geometry(f"+{x}+{y}")
        self._tip.bind("<Leave>", self._hide, add="+")
        self._tip.bind("<Enter>", self._hide, add="+")
