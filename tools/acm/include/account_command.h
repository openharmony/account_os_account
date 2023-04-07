/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_TOOLS_ACM_INCLUDE_ACCOUNT_COMMAND_H
#define OS_ACCOUNT_TOOLS_ACM_INCLUDE_ACCOUNT_COMMAND_H

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
#ifdef ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
                             "  stop                stop the local accounts\n"
#endif // ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
                             "  set                 set constraints of a local account\n"
                             "  dump                dump the info of local accounts\n";

const std::string HELP_MSG_CREATE =
    "usage: acm create <options>\n"
    "options list:\n"
    "  -h, --help                                       list available commands\n"
    "  -n <local-account-name> -t <type>                create a local account with a name and a type\n"
    "                                                   <type>: admin, normal, guest\n";

const std::string HELP_MSG_DELETE =
    "usage: acm delete <options>\n"
    "options list:\n"
    "  -h, --help                                       list available commands\n"
    "  -i <local-account-id>                            delete a local account with an id\n";

const std::string HELP_MSG_DUMP =
    "usage: acm dump <options>\n"
    "options list:\n"
    "  -h, --help                                       list available commands\n"
    "  -a, --all                                        dump all local accounts\n"
    "  -i <local-account-id>                            dump a local account with an id\n";

const std::string HELP_MSG_SET =
    "usage: acm set <options>\n"
    "options list:\n"
    "  -h, --help                                       list available commands\n"
    "  -i <local-account-id> -c <constraints> [-e]      set constraints for a local account\n";

const std::string HELP_MSG_SWITCH =
    "usage: acm switch <options>\n"
    "options list:\n"
    "  -h, --help                                       list available commands\n"
    "  -i <local-account-id>                            switch a local account with an id\n";

const std::string HELP_MSG_STOP =
    "usage: acm stop <options>\n"
    "options list:\n"
    "  -h, --help                                       list available commands\n"
    "  -i <local-account-id>                            stop a local account with an id\n";

const std::string HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT = "error: option requires an argument.";
const std::string HELP_MSG_NO_NAME_OPTION = "error: -n <local-account-name> is expected";
const std::string HELP_MSG_NO_TYPE_OPTION = "error: -t <type> is expected";
const std::string HELP_MSG_NO_ID_OPTION = "error: -i <local-account-id> is expected";
const std::string HELP_MSG_NO_CONSTRAINTS_OPTION = "error: -c <constraints> is expected";
const std::string HELP_MSG_INVALID_TYPE_ARGUMENT = "error: invalid type argument";
const std::string HELP_MSG_INVALID_ID_ARGUMENT = "error: invalid id argument";

const std::string STRING_CREATE_OS_ACCOUNT_OK = "create the local account successfully.";
const std::string STRING_CREATE_OS_ACCOUNT_NG = "error: failed to create the local account.";
const std::string STRING_DELETE_OS_ACCOUNT_OK = "delete the local account successfully.";
const std::string STRING_DELETE_OS_ACCOUNT_NG = "error: failed to delete the local account.";
const std::string STRING_DUMP_OS_ACCOUNT_NG = "error: failed to dump state.";
const std::string STRING_SET_OS_ACCOUNT_CONSTRAINTS_OK = "set constraints for the local account successfully.";
const std::string STRING_SET_OS_ACCOUNT_CONSTRAINTS_NG = "error: failed to set constraints for the local account.";
const std::string STRING_SWITCH_OS_ACCOUNT_OK = "switch the local account successfully.";
const std::string STRING_SWITCH_OS_ACCOUNT_NG = "error: failed to switch the local account.";
const std::string STRING_STOP_OS_ACCOUNT_OK = "stop the local account successfully.";
const std::string STRING_STOP_OS_ACCOUNT_NG = "error: failed to stop the local account.";
}  // namespace

class AccountCommand : public OHOS::AAFwk::ShellCommand {
public:
    AccountCommand(int argc, char *argv[]);
    ~AccountCommand() = default;

private:
    ErrCode CreateCommandMap() override;
    ErrCode CreateMessageMap() override;
    ErrCode init() override;

    ErrCode RunAsHelpCommand(void);
    ErrCode RunAsCreateCommand(void);
    ErrCode RunAsDeleteCommand(void);
    ErrCode RunAsSwitchCommand(void);
    ErrCode RunAsStopCommand(void);
    ErrCode RunAsDumpCommand(void);
    ErrCode RunAsSetCommand(void);

    ErrCode RunAsCreateCommandError(void);
    ErrCode RunAsCreateCommandMissingOptionArgument(void);
    ErrCode RunAsCreateCommandExistentOptionArgument(const int &option, std::string &name, OsAccountType &type);
    ErrCode RunAsDeleteCommandError(void);
    ErrCode RunAsDeleteCommandMissingOptionArgument(void);
    ErrCode RunAsDeleteCommandExistentOptionArgument(const int &option, int &id);
    ErrCode RunAsDumpCommandError(void);
    ErrCode RunAsDumpCommandMissingOptionArgument(void);
    ErrCode RunAsDumpCommandExistentOptionArgument(const int &option, int &id);
    ErrCode RunAsSetCommandError(void);
    ErrCode RunAsSetCommandMissingOptionArgument(void);
    ErrCode RunAsSetCommandExistentOptionArgument(
        const int &option, int &id, std::vector<std::string> &constraints, bool &enable);
    ErrCode RunAsSwitchCommandError(void);
    ErrCode RunAsSwitchCommandMissingOptionArgument(void);
    ErrCode RunAsSwitchCommandExistentOptionArgument(const int &option, int &id);
    ErrCode RunAsStopCommandError(void);
    ErrCode RunAsStopCommandMissingOptionArgument(void);
    ErrCode RunAsStopCommandExistentOptionArgument(const int &option, int &id);

    ErrCode AnalyzeTypeArgument(OsAccountType &type);
    ErrCode AnalyzeLocalIdArgument(int &id);
    ErrCode AnalyzeConstraintArgument(std::vector<std::string> &constraints);
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_TOOLS_ACM_INCLUDE_ACCOUNT_COMMAND_H
