"""Minimal stand-in for PIL.Image (see __init__.py). Any real image operation fails loudly."""


class Image:
    """Nothing is ever an instance of this, so reportlab's isinstance() checks return False."""


def open(*args, **kwargs):
    raise ImportError("Embedding images needs the Pillow library (pip install pillow).")
