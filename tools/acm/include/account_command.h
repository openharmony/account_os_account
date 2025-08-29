/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

namespace OHOS {
namespace AccountSA {
const std::string TOOL_NAME = "acm";
const std::string HELP_MSG_NO_OPTION = "error: you must specify an option at least.";
const std::string HELP_MSG = "usage: acm <command> [<options>]\n"
                             "These are acm commands list:\n"
                             "  help                list available commands\n"
                             "  create              create a local account with options\n"
                             "  delete              delete a local account with options\n"
                             "  switch              switch to a local account with options\n"
                             "  deactivate          deactivate to a local account with options\n"
                             "  set                 set constraints of a local account\n"
                             "  dump                dump the info of local accounts\n";

const std::string HELP_MSG_CREATE =
    "usage: acm create <options>\n"
    "options list:\n"
    "  -h, --help                 list available commands\n"
    "  -n <local-account-name> [-s] <shortName>\n"
    "  -t <type> [-d] <disallowed-pre-install-hap-bundles> [-p] <allowed-pre-install-hap-bundles>\n"
    "                             create a local account with a name and a type\n"
    "                             <type>: admin, normal, guest, private, maintenance\n"
    "                             <disallowed-pre-install-hap-bundles>: can set disallowed pre-installed hap bundles\n"
    "                             <allowed-pre-install-hap-bundles>: can set allowed pre-installed hap bundles\n";

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
    "  -i <local-account-id> [-d <display-id>]          switch a local account with id and\n"
    "                                                   display id(default 0)\n";

const std::string HELP_MSG_DEACTIVATE =
    "usage: acm deactivate <options>\n"
    "options list:\n"
    "  -a, --all                                        deactivate all local account\n"
    "  -h, --help                                       list available commands\n"
    "  -i <local-account-id>                            deactivate a local account with an id\n";

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
const std::string STRING_DEACTIVATE_OS_ACCOUNT_OK = "deactivate the local account successfully.";
const std::string STRING_DEACTIVATE_OS_ACCOUNT_NG = "error: failed to deactivate the local account.";
const std::string STRING_DEACTIVATE_ALL_OS_ACCOUNTS_OK = "deactivate all local account successfully.";
const std::string STRING_DEACTIVATE_ALL_OS_ACCOUNTS_NG = "error: failed to deactivate all local account.";

class AccountCommand {
public:
    AccountCommand(int argc, char *argv[]);
    ~AccountCommand() = default;
    std::string ExecCommand();

private:
    void CreateCommandMap();
    void OnCommand();
    std::string GetCommandErrorMsg() const;
    std::string GetUnknownOptionMsg(std::string& unknownOption) const;

    ErrCode RunAsHelpCommand(void);
    ErrCode RunAsCreateCommand(void);
    ErrCode RunAsDeleteCommand(void);
    ErrCode RunAsSwitchCommand(void);
    ErrCode RunAsDeactivateCommand(void);
    ErrCode RunAsDumpCommand(void);
    ErrCode RunAsSetCommand(void);

    ErrCode RunAsCreateCommandError(void);
    ErrCode RunAsCreateCommandMissingOptionArgument(void);
    ErrCode RunAsCreateCommandExistentOptionArgument(const int &option, std::string &name,
        std::string &shortName, OsAccountType &type, CreateOsAccountOptions &options);
    ErrCode RunAsSetCommandError(void);
    ErrCode RunAsSetCommandMissingOptionArgument(void);
    ErrCode RunAsSetCommandExistentOptionArgument(
        const int &option, int &id, std::vector<std::string> &constraints, bool &enable);
    ErrCode RunAsSwitchCommandMissingOptionArgument(void);
    ErrCode RunAsSwitchCommandExistentOptionArgument(const int &option, int &id, unsigned long &displayId);
    ErrCode RunAsCommonCommandExistentOptionArgument(const int &option, int &id);
    ErrCode RunAsCommonCommandMissingOptionArgument(const std::string &command);
    ErrCode RunCommandError(const std::string &command);

    void ParseCommandOpt(const std::string &command, ErrCode &result, int &id);
    void RunCommand(int &counter, ErrCode &result, bool &enable, int &id, std::vector<std::string> &constraints);
    ErrCode ParseCreateCommandOpt(std::string &name,
        std::string &shortName, OsAccountType &osAccountType, CreateOsAccountOptions &options);
    ErrCode ParseSwitchCommandOpt(int &id, unsigned long &displayId);
    
    ErrCode AnalyzeTypeArgument(OsAccountType &type);
    ErrCode AnalyzeListArgument(std::vector<std::string> &list);
    ErrCode AnalyzeLocalIdArgument(int &id);
    ErrCode AnalyzeConstraintArgument(std::vector<std::string> &constraints);

protected:
    int argc_ = 0;
    char** argv_ = nullptr;

    std::string cmd_;
    std::vector<std::string> argList_;

    std::string name_;
    std::map<std::string, std::function<int()>> commandMap_;

    std::string resultReceiver_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_TOOLS_ACM_INCLUDE_ACCOUNT_COMMAND_H
