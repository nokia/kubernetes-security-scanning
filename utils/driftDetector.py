#
# Copyright (C) 2021 Nokia
# Licensed under the GNU General Public License v2.0 only
# SPDX-License-Identifier: GPL-2.0-only
#

import json
from pprint import pformat
from deepdiff import DeepDiff


def compare_files(prev_file, current_file):
    with open(prev_file) as file1, open(current_file) as file2:
        prev_file_dict = json.load(file1)
        current_file_dict = json.load(file2)
    return pformat(DeepDiff(current_file_dict, prev_file_dict))
