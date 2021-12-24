/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef BASE_ACCOUNT_OS_ACCOUNT_TOOLS_ACM_INCLUDE_ACCOUNT_COMMAND_H
#define BASE_ACCOUNT_OS_ACCOUNT_TOOLS_ACM_INCLUDE_ACCOUNT_COMMAND_H

#include "os_account.h"
#include "shell_command.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::string TOOL_NAME = "acm";

const std::string HELP_MSG = "usage: acm <command> [<options>]\n"
                             "These are acm commands list:\n"
                             "  help                list available commands\n"
                             "  create              create a local account with options\n"
                             "  delete              delete a local account with options\n"
                             "  switch              switch to a local account with options\n"
                             "  dump                dump the info of local accounts\n";

const std::string HELP_MSG_CREATE =
    "usage: acm create <options>\n"
    "options list:\n"
    "  -h, --help                                       list available commands\n"
    "  -n <local-account-name> -t <type>                create a local account with a name and a type\n";

const std::string HELP_MSG_DELETE =
    "usage: acm delete <options>\n"
    "options list:\n"
    "  -h, --help                                       list available commands\n"
    "  -i <local-account-id>                            delete a local account with an id\n";

const std::string HELP_MSG_SWITCH =
    "usage: acm switch <options>\n"
    "options list:\n"
    "  -h, --help                                       list available commands\n"
    "  -i <local-account-id>                            switch a local account with an id\n";

const std::string HELP_MSG_DUMP =
    "usage: acm dump <options>\n"
    "options list:\n"
    "  -h, --help                                       list available commands\n"
    "  -a, --all                                        dump all local accounts\n"
    "  -i <local-account-id>                            dump a local account with an id\n";

const std::string HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT = "error: option requires an argument.";
const std::string HELP_MSG_NO_NAME_OPTION = "error: -n <local-account-name> is expected";
const std::string HELP_MSG_NO_TYPE_OPTION = "error: -t <type> is expected";
const std::string HELP_MSG_INVALID_TYPE_ARGUMENT = "error: invalid type argument";
const std::string HELP_MSG_INVALID_ID_ARGUMENT = "error: invalid id argument";

const std::string STRING_CREATE_OS_ACCOUNT_OK = "create the local account successfully.";
const std::string STRING_CREATE_OS_ACCOUNT_NG = "error: failed to create the local account.";

const std::string STRING_DELETE_OS_ACCOUNT_OK = "delete the local account successfully.";
const std::string STRING_DELETE_OS_ACCOUNT_NG = "error: failed to delete the local account.";

const std::string STRING_SWITCH_OS_ACCOUNT_OK = "switch the local account successfully.";
const std::string STRING_SWITCH_OS_ACCOUNT_NG = "error: failed to switch the local account.";

const std::string STRING_DUMP_OS_ACCOUNT_NG = "error: failed to dump state.";
}  // namespace

class AccountCommand : public OHOS::AAFwk::ShellCommand {
public:
    AccountCommand(int argc, char *argv[]);
    ~AccountCommand() = default;

private:
    virtual ErrCode CreateCommandMap() override;
    virtual ErrCode CreateMessageMap() override;
    virtual ErrCode init() override;

    ErrCode RunAsHelpCommand(void);
    ErrCode RunAsCreateCommand(void);
    ErrCode RunAsDeleteCommand(void);
    ErrCode RunAsSwitchCommand(void);
    ErrCode RunAsDumpCommand(void);

    ErrCode RunAsCreateCommandError();
    ErrCode RunAsCreateCommandMissingOptionArgument(void);
    ErrCode RunAsCreateCommandExistentOptionArgument(const int &option, std::string &name, OsAccountType &type);
    ErrCode RunAsDeleteCommandError();
    ErrCode RunAsDeleteCommandMissingOptionArgument(void);
    ErrCode RunAsDeleteCommandExistentOptionArgument(const int &option, int &id);
    ErrCode RunAsSwitchCommandError();
    ErrCode RunAsSwitchCommandMissingOptionArgument(void);
    ErrCode RunAsSwitchCommandExistentOptionArgument(const int &option, int &id);
    ErrCode RunAsDumpCommandError();
    ErrCode RunAsDumpCommandMissingOptionArgument(void);
    ErrCode RunAsDumpCommandExistentOptionArgument(const int &option, int &id);

    ErrCode AnalyzeTypeArgument(OsAccountType &type);
    ErrCode AnalyzeLocalIdArgument(int &id);

private:
    std::shared_ptr<OsAccount> osAccountPtr_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // BASE_ACCOUNT_OS_ACCOUNT_TOOLS_ACM_INCLUDE_ACCOUNT_COMMAND_H
