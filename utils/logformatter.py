#
# Copyright (C) 2021 Nokia
# Licensed under the GNU General Public License v2.0 only
# SPDX-License-Identifier: GPL-2.0-only
#

from colorlog import ColoredFormatter
import logging
import sys
from utils.fileutils import remove_file

# -------------------------------------------------------------
# Function to format commandline output and reulted file output
# -------------------------------------------------------------
def log_formatter(filename):
    filePath = "./output/{}".format(filename)
    remove_file(filePath)
    """Log formatter configurations"""
    LOG_LEVEL = logging.DEBUG
    LOGFORMAT = "  %(log_color)s%(levelname)-8s%(reset)s | %(log_color)s%(message)s%(reset)s"
    logging.root.setLevel(LOG_LEVEL)
    formatter = ColoredFormatter(LOGFORMAT)
    log = logging.getLogger("pythonConfig")
    log.setLevel(LOG_LEVEL)

    stream = logging.StreamHandler(sys.stdout)
    stream.setLevel(LOG_LEVEL)
    stream.setFormatter(formatter)
    file_handler = logging.FileHandler(filePath)
    file_handler.setLevel(LOG_LEVEL)
    file_formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    file_handler.setFormatter(file_formatter)

    log.addHandler(stream)
    log.addHandler(file_handler)

    return log
