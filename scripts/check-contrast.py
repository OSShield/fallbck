#!/usr/bin/env python3
"""Check WCAG contrast for FallBCK's semantic color pairs (no dependencies)."""
import re
from pathlib import Path

css = (Path(__file__).resolve().parents[1] / 'web/static/css/app.css').read_text()
blocks = re.findall(r':root(?:\[data-theme=dark\])?\s*\{([^}]+)', css)
def tokens(block):
    return dict(re.findall(r'--([\w-]+)\s*:\s*(#[0-9a-fA-F]{6})', block))
def luminance(color):
    values = [int(color[i:i+2], 16) / 255 for i in (1, 3, 5)]
    linear = [v / 12.92 if v <= .04045 else ((v + .055) / 1.055) ** 2.4 for v in values]
    return sum(v * weight for v, weight in zip(linear, (.2126, .7152, .0722)))
def contrast(a, b):
    x, y = sorted([luminance(a), luminance(b)])
    return (y + .05) / (x + .05)

light = tokens(blocks[0]); dark = light | tokens(blocks[1])
for theme, palette in [('light', light), ('dark', dark)]:
    pairs = [(fg, bg, 4.5) for fg in ['ink', 'muted', 'good', 'bad', 'warning']
             for bg in ['canvas', 'surface', 'inset']]
    pairs += [('on-action', 'action', 4.5), ('on-accent', 'accent', 4.5), ('rail-ink', 'rail', 4.5)]
    pairs += [(fg, bg, 3) for fg in ['strong-rule', 'focus'] for bg in ['canvas', 'surface', 'inset']]
    pairs += [('accent', 'rail', 3)]
    measured = []
    for fg, bg, minimum in pairs:
        value = contrast(palette[fg], palette[bg]); measured.append(value)
        assert value >= minimum, f'{theme}: {fg}/{bg} is {value:.2f}:1; requires {minimum}:1'
    print(f'PASS {theme}: {len(pairs)} text, control-boundary and focus color pairs')
