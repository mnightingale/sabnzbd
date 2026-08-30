#!/usr/bin/python3 -OO
# Copyright 2007-2026 by The SABnzbd-Team (sabnzbd.org)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

"""
tests.visual.compare - Diff two sets of screenshots

Run against the captures from two builds. Writes a report of what changed, and a diff image
for anything that did, so a reviewer can see the change rather than take it on trust.

    python -m tests.visual.compare <before_dir> <after_dir> <diff_dir>
"""

import os
import sys

from PIL import Image, ImageChops

# A screenshot is not expected to differ at all, but anti-aliasing can flip the odd pixel
# between runs on the same image, so a handful of pixels is not worth failing over.
THRESHOLD_PERCENT = 0.02


def changed_fraction(before: Image.Image, after: Image.Image) -> tuple[float, Image.Image]:
    """Return the fraction of pixels that differ, and an image highlighting them"""
    if before.size != after.size:
        # A resized page is a change in itself; grow both to the union so the diff is visible
        size = (max(before.width, after.width), max(before.height, after.height))
        padded_before = Image.new("RGB", size, "white")
        padded_after = Image.new("RGB", size, "white")
        padded_before.paste(before, (0, 0))
        padded_after.paste(after, (0, 0))
        before, after = padded_before, padded_after

    diff = ImageChops.difference(before.convert("RGB"), after.convert("RGB"))
    mask = diff.convert("L").point(lambda p: 255 if p > 8 else 0)
    changed = sum(mask.histogram()[1:])
    return changed / float(mask.width * mask.height), ImageChops.add(after.convert("RGB"), diff)


def main(before_dir: str, after_dir: str, diff_dir: str) -> int:
    os.makedirs(diff_dir, exist_ok=True)
    names = sorted(set(os.listdir(before_dir)) | set(os.listdir(after_dir)))
    rows, failed = [], False

    for name in names:
        if not name.endswith(".png"):
            continue
        before_path, after_path = os.path.join(before_dir, name), os.path.join(after_dir, name)
        if not os.path.exists(before_path):
            rows.append((name, "added", ""))
            failed = True
            continue
        if not os.path.exists(after_path):
            rows.append((name, "removed", ""))
            failed = True
            continue

        with Image.open(before_path) as before, Image.open(after_path) as after:
            fraction, highlight = changed_fraction(before, after)
            if fraction * 100 > THRESHOLD_PERCENT:
                highlight.save(os.path.join(diff_dir, name))
                rows.append((name, "changed", "%.3f%%" % (fraction * 100)))
                failed = True

    print("| screenshot | result | changed |")
    print("| --- | --- | --- |")
    if rows:
        for row in rows:
            print("| %s | %s | %s |" % row)
    else:
        print("| _all %d screenshots identical_ | | |" % len(names))
    return 1 if failed else 0


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(main(*sys.argv[1:]))
