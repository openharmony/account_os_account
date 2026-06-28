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

#include "commands.h"

#include <cstring>
#include <iostream>

using namespace OHOS::AccountSA::ACli;

constexpr int ARG_COUNT_HELP_ONLY = 2;
constexpr int ARG_COUNT_SUBCOMMAND_HELP = 3;
constexpr int MIN_REQUIRED_ARGS = 2;
constexpr int CMD_NAME_SKIP_COUNT = 2;
constexpr int SUBCMD_ARGV_INDEX = 2;

int main(int argc, char* argv[])
{
    G_PROGRAM_NAME = argv[0];

    if (argc < MIN_REQUIRED_ARGS) {
        return CmdHelp(argc, argv);
    }

    if (argc == ARG_COUNT_HELP_ONLY && std::strcmp(argv[1], "--help") == 0) {
        return CmdHelp(argc, argv);
    }

    std::string cmdName = argv[1];

    if (argc == ARG_COUNT_SUBCOMMAND_HELP && std::strcmp(argv[SUBCMD_ARGV_INDEX], "--help") == 0) {
        return CmdHelp(argc, argv);
    }

    const auto& commands = GetCommands();
    auto it = commands.find(cmdName);
    if (it == commands.end()) {
        return OutputError("ERR_UNKNOWN_COMMAND",
            "Unknown command: " + cmdName,
            "Use --help to see available commands");
    }

    return it->second.handler(argc - CMD_NAME_SKIP_COUNT, argv + CMD_NAME_SKIP_COUNT);
}
