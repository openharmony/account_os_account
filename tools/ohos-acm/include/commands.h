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

#ifndef OHOS_OS_ACCOUNT_CLI_COMMANDS_H
#define OHOS_OS_ACCOUNT_CLI_COMMANDS_H

#include <functional>
#include <iostream>
#include <string>
#include <unordered_map>

#include "cJSON.h"
#include "json_utils.h"

namespace OHOS {
namespace AccountSA {
namespace ACli {

extern const char* G_PROGRAM_NAME;
extern const char* TOOL_NAME;

inline void CLI_LOG(const std::string& msg)
{
    std::cout << msg << std::endl;
}

using CommandHandler = std::function<int(int, char**)>;

struct Command {
    const char* description;
    CommandHandler handler;
};

const std::unordered_map<std::string, Command>& GetCommands();

int CmdGetCurrentUserId(int argc, char** argv);
int CmdHelp(int argc, char** argv);

int OutputSuccess(CJsonUnique data);

int OutputError(const std::string& code, const std::string& message, const std::string& suggestion);

} // namespace ACli
} // namespace AccountSA
} // namespace OHOS

#endif // OHOS_OS_ACCOUNT_CLI_COMMANDS_H
