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

#include "os_account_manager.h"

namespace OHOS {
namespace AccountSA {
namespace ACli {

const char* G_PROGRAM_NAME = "";
const char* TOOL_NAME = "ohos-acm";

const std::unordered_map<std::string, Command>& GetCommands()
{
    static const std::unordered_map<std::string, Command> kCommands = {
        {"get-current-userid", {"Get the local ID of the current OS account", CmdGetCurrentUserId}},
        {"--help", {"Show help message", CmdHelp}},
    };
    return kCommands;
}

int OutputSuccess(CJsonUnique data)
{
    if (data == nullptr) {
        return 1;
    }
    auto response = CreateJson();
    if (response == nullptr) {
        return 1;
    }
    AddStringToJson(response, "type", "result");
    AddStringToJson(response, "status", "success");
    AddObjToJson(response, "data", data);
    std::string output = PackJsonToString(response);
    if (!output.empty()) {
        std::cout << output << std::endl;
    }
    return 0;
}

int OutputError(const std::string& code, const std::string& message, const std::string& suggestion)
{
    auto response = CreateJson();
    if (response == nullptr) {
        return 1;
    }
    AddStringToJson(response, "type", "result");
    AddStringToJson(response, "status", "failed");
    AddStringToJson(response, "errCode", code);
    AddStringToJson(response, "errMsg", message);
    AddStringToJson(response, "suggestion", suggestion);
    std::string output = PackJsonToString(response);
    if (!output.empty()) {
        std::cout << output << std::endl;
    }
    return 1;
}

int CmdGetCurrentUserId(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    int userId = -1;
    ErrCode ret = OsAccountManager::GetOsAccountLocalIdFromProcess(userId);
    if (ret != ERR_OK) {
        return OutputError("ERR_GET_CURRENT_USERID",
                           "Failed to get OS account local ID from process",
                           "Check if OS account service is running properly");
    }

    auto data = CreateJson();
    if (data == nullptr) {
        return OutputError("ERR_JSON_CREATE",
                           "Failed to create JSON object",
                           "Check system memory status");
    }
    AddIntToJson(data, "userId", userId);
    return OutputSuccess(std::move(data));
}

static std::string ParseTargetCommand(int argc, char** argv)
{
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-') {
            return argv[i];
        }
    }
    return "";
}

static int OutputHelpError(const std::string& targetCmd)
{
    return OutputError("ERR_UNKNOWN_COMMAND",
        "Unknown command: " + targetCmd,
        "Use --help to see available commands");
}

static void PrintFullHelp()
{
    const auto& commands = GetCommands();

    CLI_LOG(std::string("ohos-acm - OS Account management command-line utility"));
    CLI_LOG("");
    CLI_LOG("Usage:");
    CLI_LOG(std::string("  ") + G_PROGRAM_NAME + " <command> [options]");
    CLI_LOG("");
    CLI_LOG("Parameters:");
    CLI_LOG("  --help             Display this help message");
    CLI_LOG("");
    CLI_LOG("SubCommands:");

    constexpr size_t descriptionPadding = 2;
    size_t maxLen = 0;
    for (const auto& pair : commands) {
        if (pair.first != "--help" && pair.first.length() > maxLen) {
            maxLen = pair.first.length();
        }
    }

    for (const auto& pair : commands) {
        if (pair.first == "--help") {
            continue;
        }
        std::string line = "  " + pair.first;
        for (size_t i = pair.first.length(); i < maxLen + descriptionPadding; i++) {
            line += " ";
        }
        line += pair.second.description;
        CLI_LOG(line);
    }

    CLI_LOG("");
    CLI_LOG("Examples:");
    CLI_LOG(std::string("  ") + G_PROGRAM_NAME + " --help");
    CLI_LOG(std::string("  ") + G_PROGRAM_NAME + " get-current-userid");
    CLI_LOG(std::string("  ") + G_PROGRAM_NAME + " get-current-userid --help");
}

static int PrintCommandHelp(const std::string& targetCmd)
{
    const auto& commands = GetCommands();
    auto it = commands.find(targetCmd);
    if (it == commands.end()) {
        OutputHelpError(targetCmd);
        return 1;
    }

    CLI_LOG(std::string("ohos-acm ") + targetCmd + " - " + it->second.description);
    CLI_LOG("");
    CLI_LOG("Usage:");
    CLI_LOG(std::string("  ") + G_PROGRAM_NAME + " " + targetCmd + " [options]");
    CLI_LOG("");
    CLI_LOG("Parameters:");
    CLI_LOG("  --help             Display this help message");
    CLI_LOG("");
    CLI_LOG("Examples:");
    CLI_LOG(std::string("  ") + G_PROGRAM_NAME + " " + targetCmd);

    return 0;
}

int CmdHelp(int argc, char** argv)
{
    std::string targetCmd = ParseTargetCommand(argc, argv);
    if (targetCmd.empty()) {
        PrintFullHelp();
        return 0;
    }
    return PrintCommandHelp(targetCmd);
}

} // namespace ACli
} // namespace AccountSA
} // namespace OHOS
