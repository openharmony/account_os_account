#!/usr/bin/env python
# coding: utf-8

"""
Copyright (c) 2026 Huawei Device Co., Ltd.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

"""

import json
import argparse
import os
import stat
import hashlib

PRIVILEGE_DEFINITION_PREFIX = '''
/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PRIVILEGES_DEFINITION_PARSER_H
#define PRIVILEGES_DEFINITION_PARSER_H

#include "privileges_map.h"

namespace OHOS {
namespace AccountSA {
'''

PRIVILEGE_DEFINITION_SUFFIX_1 = '''
};
'''

PRIVILEGE_DEFINITION_SUFFIX_2 = '''
const uint32_t MAX_PRIVILEGE_SIZE = sizeof(g_privilegeList) / sizeof(PrivilegeBriefDef);
} // namespace AccountSA
} // namespace OHOS
#endif // PRIVILEGES_DEFINITION_PARSER_H
'''

PRIVILEGE_NAME_STRING = "char PRIVILEGE_NAME_%i[] = \"%s\";\n"
PRIVILEGE_DESCRIPTION_STRING = "char PRIVILEGE_DESCRIPTION_%i[] = \"%s\";\n"

PRIVILEGE_LIST_DECLARE = "const static PrivilegeBriefDef g_privilegeList[] = {"

VERSION_STRING = "\nconst char* PRIVILEGES_DEFINITION_VERSION = \"%s\";"

PRIVILEGE_BRIEF_DEFINE_PATTERN = '''
{
    .privilegeName = PRIVILEGE_NAME_%i,
    .description = PRIVILEGE_DESCRIPTION_%i,
    .timeout = %d
},'''

BUFFER_SIZE = 4096


class PrivilegeDef(object):
    def __init__(self, privilege_def_dict, code):
        self.name = privilege_def_dict["name"]
        self.description = privilege_def_dict["description"]
        self.timeout = 300
        self.code = code

    def dump_privilege_name(self):
        return PRIVILEGE_NAME_STRING % (
            self.code, self.name
        )

    def dump_privilege_description(self):
        return PRIVILEGE_DESCRIPTION_STRING % (
            self.code, self.description
        )

    def dump_struct(self):
        entry = PRIVILEGE_BRIEF_DEFINE_PATTERN % (
            self.code, self.code, self.timeout
        )
        return entry


def parse_json(path):
    def_list = []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
        index = 0
        for priv in data["privileges"]:
            priv_def = PrivilegeDef(priv, index)
            def_list.append(priv_def)
            index += 1
    return def_list


def convert_to_cpp(path, privilege_list, hash_str):
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    mode = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(path, flags, mode), "w") as f:
        f.write(PRIVILEGE_DEFINITION_PREFIX)
        for priv in privilege_list:
            f.write(priv.dump_privilege_name())
            f.write(priv.dump_privilege_description())
        f.write(PRIVILEGE_LIST_DECLARE)
        for priv in privilege_list:
            f.write(priv.dump_struct())
        f.write(PRIVILEGE_DEFINITION_SUFFIX_1)
        f.write(VERSION_STRING % (hash_str))
        f.write(PRIVILEGE_DEFINITION_SUFFIX_2)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-path', help='the output cpp path', required=True)
    parser.add_argument('--input-json', help='json file for privilege definition', required=True)
    parser.add_argument('--target-platform', help='build target platform', required=False)
    return parser.parse_args()


def get_file_hash(path):
    hash_object = hashlib.sha256()
    with open(path, 'rb') as f:
        while line := f.read(BUFFER_SIZE):
            hash_object.update(line)
    return hash_object.hexdigest()

if __name__ == "__main__":
    input_args = parse_args()
    privilege_list = parse_json(input_args.input_json)
    hash_str = get_file_hash(input_args.input_json)
    convert_to_cpp(input_args.output_path, privilege_list, hash_str)
