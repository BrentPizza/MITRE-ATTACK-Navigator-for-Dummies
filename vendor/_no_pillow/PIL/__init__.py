"""Placeholder used ONLY when the real Pillow library is not installed.

reportlab imports ``PIL.Image`` when it loads, but only calls it to embed pictures in a PDF.
The reports from attack_overlap.py contain no pictures, so they build without Pillow.
attack_overlap.py adds this folder to the import path only after ``import PIL`` has failed,
so an installed Pillow always takes priority.
"""
