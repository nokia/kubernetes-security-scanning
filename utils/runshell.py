#
# Copyright (C) 2021 Nokia
# Licensed under the GNU General Public License v2.0 only
# SPDX-License-Identifier: GPL-2.0-only
#

import subprocess

# -----------------------------------------------------------
# Run shell command using these method
# -----------------------------------------------------------
def run_shell_cmd(cmd):
    try:
        output = subprocess.check_output(cmd, shell=True)
        return output
    except subprocess.CalledProcessError as e:
        print(e.output)


# def save_shell_output_file(filename, cmd):
#     try:
#         file_ = open(filename, "w")
#         subprocess.run(cmd, shell=True, stdout=file_)
#         file_.close()
#     except subprocess.CalledProcessError as e:
#         print(e.output)
