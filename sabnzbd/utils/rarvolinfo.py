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
sabnzbd.utils.rarvolinfo - Find out volume number and/or original extension of a rar file. Useful with obfuscated files
"""

import rars


def get_rar_extension(myrarfile: str) -> tuple[int, str]:
    """
    Find out original extension of a rar file. Returns -1 and "" in case of file problems
    So ... returns:     "part001.rar", ... "part005.rar"
    or old number scheme (can only happen for rar3/rar4 files): "rar", r00, ... r89
    """
    # When things go wrong
    volumenumber = -1
    org_extension = ""

    try:
        with rars.RarFile(myrarfile, first_volume_only=True) as rarfile:
            if rarfile.volume_index is not None:
                volumenumber = rarfile.volume_index + 1
                if rarfile.family == rars.ArchiveFamily.RAR50_PLUS:
                    org_extension = "part%03d.rar" % volumenumber
                elif rarfile.volume_naming == rars.VolumeNaming.PART:
                    org_extension = "part%02d.rar" % volumenumber
                elif volumenumber == 1:
                    # 1, 2, 3, 4 resp refers to .rar, .r00, .r01, .r02 ...
                    org_extension = "rar"
                else:
                    org_extension = "r%02d" % (volumenumber - 2)
    except (rars.Error, OSError):
        volumenumber = -1
        org_extension = ""

    return volumenumber, org_extension


# Main
if __name__ == "__main__":
    import sys

    try:
        myfile = sys.argv[1]
        print("File:", myfile)
        print("Volume and extension:", get_rar_extension(myfile))
    except Exception:
        print("Please specify rar file as parameter")
