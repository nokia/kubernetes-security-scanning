#
# Copyright (C) 2021 Nokia
# Licensed under the GNU General Public License v2.0 only
# SPDX-License-Identifier: GPL-2.0-only
#

import csv
import json
import os

# -----------------------------------------------------------
# Function to write data in csv file
# -----------------------------------------------------------
def csv_write(filename, operation, content):
    file_object = open(filename, operation)
    writer = csv.writer(file_object, delimiter=";")
    writer.writerow(content)
    file_object.close()


# -----------------------------------------------------------
# Function to write dictionarydata in csv file
# -----------------------------------------------------------
def csv_write_dict(filename, operation, header, data_dict):
    file_object = open(filename, operation)
    writer = csv.DictWriter(file_object, delimiter=";", fieldnames=header)
    writer.writeheader()
    for content in data_dict:
        writer.writerow(content)
    file_object.close()


# -----------------------------------------------------------
# Function to write data in json file
# ----------------------------------------------------------
def json_write(filename, operation, content):
    with open(filename, operation) as file:
        json_string = json.dumps(content, indent=4)
        file.write(json_string)


# -----------------------------------------------------------
# Function to load jsonFile
# -----------------------------------------------------------
def nonesafe_loads(obj):
    if obj is not None:
        return json.loads(obj)


# -----------------------------------------------------------
# Function to remove file
# -----------------------------------------------------------
def remove_file(filePath):
    if os.path.exists(filePath):
        os.remove(filePath)


# -----------------------------------------------------------
# Function to rename file
# ----------------------------------------------------------
def rename_file(src_file, dest_file):
    remove_file(dest_file)
    if os.path.exists(src_file):
        os.rename(src_file, dest_file)
