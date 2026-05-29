"""Generate a 1920x1080 LinkedIn cover image for siem-to-ocsf (no external assets)."""

from __future__ import annotations

import os

from PIL import Image, ImageDraw, ImageFont

W, H = 1920, 1080

BG = (13, 17, 23)
BG2 = (9, 12, 18)
PANEL = (22, 27, 34)
PANEL2 = (28, 34, 48)
BORDER = (48, 54, 61)
TEXT = (230, 237, 243)
MUTED = (139, 148, 158)
ACCENT = (88, 166, 255)
GREEN = (63, 185, 80)
PURPLE = (210, 168, 255)
ORANGE = (240, 136, 62)

MENLO = "/System/Library/Fonts/Menlo.ttc"
HELV = "/System/Library/Fonts/HelveticaNeue.ttc"


def font(path, size, index=0):
    return ImageFont.truetype(path, size, index=index)


# Fonts
f_eyebrow = font(MENLO, 26, 1)
f_title = font(MENLO, 150, 1)       # Menlo Bold
f_sub = font(HELV, 58, 0)
f_chip = font(MENLO, 30, 0)
f_card_title = font(HELV, 50, 0)
f_card_mono = font(MENLO, 28, 0)
f_card_small = font(MENLO, 25, 0)
f_badge = font(MENLO, 27, 0)
f_url = font(MENLO, 30, 1)

img = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(img, "RGBA")

# --- background: vertical gradient + faint dotted grid + soft glow ---
for y in range(H):
    t = y / H
    c = tuple(int(BG[i] + (BG2[i] - BG[i]) * t) for i in range(3))
    d.line([(0, y), (W, y)], fill=c)

for gx in range(0, W, 48):
    for gy in range(0, H, 48):
        d.ellipse([gx, gy, gx + 2, gy + 2], fill=(255, 255, 255, 6))

# soft blue glow behind the title
for r in range(420, 0, -8):
    a = int(10 * (1 - r / 420))
    d.ellipse([300 - r, 250 - r, 300 + r, 250 + r], fill=(88, 166, 255, a))

MARGIN = 110


def rounded(box, radius, fill=None, outline=None, width=1):
    d.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)


def center_text(cx, cy, text, fnt, fill):
    bb = d.textbbox((0, 0), text, font=fnt)
    d.text((cx - (bb[2] - bb[0]) / 2, cy - (bb[3] - bb[1]) / 2 - bb[1]), text, font=fnt, fill=fill)


# --- header ---
d.text((MARGIN, 96), "OPEN-SOURCE  ·  OCSF NORMALISATION LAYER", font=f_eyebrow, fill=ACCENT)

# Title with coloured "ocsf"
tx, ty = MARGIN, 140
pre, hi, post = "siem-to-", "ocsf", ""
d.text((tx, ty), pre, font=f_title, fill=TEXT)
wpre = d.textlength(pre, font=f_title)
d.text((tx + wpre, ty), hi, font=f_title, fill=ACCENT)

# Subtitle
d.text((MARGIN, 330), "Six SIEM dialects. One OCSF schema.", font=f_sub, fill=TEXT)
d.text((MARGIN, 408),
       "Normalise alerts from six vendors into a single, schema-validated event model.",
       font=font(HELV, 34, 0), fill=MUTED)

# divider
d.line([(MARGIN, 480), (W - MARGIN, 480)], fill=BORDER, width=2)

# --- flow diagram ---
vendors = [
    ("Cortex XDR", ORANGE),
    ("FortiSIEM", (248, 81, 73)),
    ("Microsoft Sentinel", ACCENT),
    ("CrowdStrike LogScale", (255, 123, 114)),
    ("Zscaler ZIA", (121, 192, 255)),
    ("Check Point", PURPLE),
]

# left: 6 vendor chips stacked
chip_x = MARGIN
chip_w = 560
chip_h = 56
gap = 16
top = 524
for i, (name, dot) in enumerate(vendors):
    y = top + i * (chip_h + gap)
    rounded([chip_x, y, chip_x + chip_w, y + chip_h], 12, fill=PANEL, outline=BORDER, width=2)
    d.ellipse([chip_x + 26, y + chip_h / 2 - 9, chip_x + 44, y + chip_h / 2 + 9], fill=dot)
    bb = d.textbbox((0, 0), name, font=f_chip)
    d.text((chip_x + 66, y + (chip_h - (bb[3] - bb[1])) / 2 - bb[1]), name, font=f_chip, fill=TEXT)

# converging arrows -> a hub label
hub_x = chip_x + chip_w + 70
mid_y = top + (6 * (chip_h + gap) - gap) / 2
for i in range(6):
    y = top + i * (chip_h + gap) + chip_h / 2
    d.line([(chip_x + chip_w + 8, y), (hub_x, mid_y)], fill=(88, 166, 255, 90), width=3)
d.ellipse([hub_x - 10, mid_y - 10, hub_x + 10, mid_y + 10], fill=ACCENT)

# hub -> arrow to card
card_x = hub_x + 120
d.line([(hub_x + 10, mid_y), (card_x - 26, mid_y)], fill=ACCENT, width=5)
d.polygon([(card_x - 26, mid_y - 14), (card_x - 26, mid_y + 14), (card_x - 2, mid_y)], fill=ACCENT)

# small label under the hub arrow
d.text((hub_x - 30, mid_y + 26), "parsers → mapper", font=font(MENLO, 22, 0), fill=MUTED)

# right: OCSF card
card_w = W - MARGIN - card_x
card_h = 350
card_y = int(mid_y - card_h / 2)
rounded([card_x, card_y, card_x + card_w, card_y + card_h], 18,
        fill=PANEL2, outline=ACCENT, width=2)

pad = 40
d.text((card_x + pad, card_y + 34), "OCSF Detection Finding", font=f_card_title, fill=TEXT)
d.text((card_x + pad, card_y + 104), "class_uid 2004  ·  category_uid 2  ·  type_uid 200401",
       font=f_card_mono, fill=ACCENT)

# validated pill
pill = [card_x + pad, card_y + 150, card_x + pad + 372, card_y + 196]
rounded(pill, 22, fill=(63, 185, 80, 38), outline=GREEN, width=2)
d.text((card_x + pad + 22, card_y + 160), "✓  schema-validated", font=f_card_mono, fill=GREEN)

fields = ["severity_id / severity", "finding_info + ATT&CK", "observables[]",
          "evidences[]", "enrichments[]"]
fy = card_y + 206
for fld in fields:
    d.text((card_x + pad, fy), "•  " + fld, font=f_card_small, fill=MUTED)
    fy += 27

# --- bottom badges ---
by = H - 86
badges = [("OCSF 1.8.0", ACCENT), ("Python 3.12", TEXT), ("MIT", TEXT),
          ("▶ live browser demo", GREEN)]
bx = MARGIN
for label, col in badges:
    bw = d.textlength(label, font=f_badge) + 44
    rounded([bx, by, bx + bw, by + 48], 24, fill=PANEL, outline=BORDER, width=2)
    d.text((bx + 22, by + 10), label, font=f_badge, fill=col)
    bx += bw + 16

url = "github.com/sai-teja-girimaji/siem-to-ocsf"
uw = d.textlength(url, font=f_url)
d.text((W - MARGIN - uw, by + 8), url, font=f_url, fill=ACCENT)

out = "assets/linkedin-cover.png"
os.makedirs("assets", exist_ok=True)
img.save(out)
img.save(os.path.expanduser("~/Desktop/siem-to-ocsf-linkedin-cover.png"))
print("saved", out, img.size)
