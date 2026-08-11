r"""QR rendering for TOTP enrollment.

Uses segno - a pure-Python, dependency-free QR library - so the packaged app
stays self-contained. Every function degrades gracefully (returns None / "")
when segno is unavailable, and the enrollment screens always still show the raw
secret and otpauth:// URI as text for manual entry, so a missing QR never blocks
enrollment.
"""


def _matrix(uri, border=4):
    import segno
    qr = segno.make(uri, error="m")   # 'M' error correction: robust, still compact
    return [list(row) for row in qr.matrix_iter(scale=1, border=border)]


def photoimage(uri, scale=7, border=4):
    """Return a tk.PhotoImage of the QR for `uri`, or None if unavailable.

    The caller MUST keep a reference to the returned image (e.g.
    `label.image = img`) or Tk will garbage-collect it and show nothing.
    """
    try:
        import tkinter as tk
        rows = _matrix(uri, border)
    except Exception:
        return None
    try:
        w, h = len(rows[0]), len(rows)
        img = tk.PhotoImage(width=w, height=h)
        # One put() for the whole grid: each row is "{c c c ...}".
        data = " ".join(
            "{" + " ".join("#000000" if v else "#ffffff" for v in row) + "}"
            for row in rows
        )
        img.put(data)
        return img.zoom(scale)   # integer upscale: crisp, no blur
    except Exception:
        return None


def ascii_qr(uri):
    """Return a text/terminal QR for `uri`, or '' if segno is unavailable."""
    try:
        import io
        import segno
        buf = io.StringIO()
        segno.make(uri, error="m").terminal(buf, compact=True)
        return buf.getvalue()
    except Exception:
        return ""
