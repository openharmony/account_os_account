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
#include "account_command.h"
#include <getopt.h>
#include "account_log_wrapper.h"
#include "singleton.h"

using namespace OHOS::AAFwk;

namespace OHOS {
namespace AccountSA {
namespace {
const std::string SHORT_OPTIONS = "hn:t:i:c:ea";
const struct option LONG_OPTIONS[] = {
    {"help", no_argument, nullptr, 'h'},
    {"name", required_argument, nullptr, 'n'},
    {"type", required_argument, nullptr, 't'},
    {"id", required_argument, nullptr, 'i'},
    {"constraint", required_argument, nullptr, 'c'},
    {"enable", no_argument, nullptr, 'e'},
    {"all", no_argument, nullptr, 'a'},
};
}  // namespace

AccountCommand::AccountCommand(int argc, char *argv[]) : ShellCommand(argc, argv, TOOL_NAME)
{
    ACCOUNT_LOGD("enter");

    for (int i = 0; i < argc_; i++) {
        ACCOUNT_LOGD("argv_[%{public}d]: %{public}s", i, argv_[i]);
    }
}

ErrCode AccountCommand::CreateCommandMap()
{
    ACCOUNT_LOGD("enter");

    commandMap_ = {
        {"help", std::bind(&AccountCommand::RunAsHelpCommand, this)},
        {"create", std::bind(&AccountCommand::RunAsCreateCommand, this)},
        {"delete", std::bind(&AccountCommand::RunAsDeleteCommand, this)},
        {"dump", std::bind(&AccountCommand::RunAsDumpCommand, this)},
        {"set", std::bind(&AccountCommand::RunAsSetCommand, this)},
        {"switch", std::bind(&AccountCommand::RunAsSwitchCommand, this)},
#ifdef ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
        {"stop", std::bind(&AccountCommand::RunAsStopCommand, this)},
#endif // ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
    };

    return ERR_OK;
}

ErrCode AccountCommand::CreateMessageMap()
{
    ACCOUNT_LOGD("enter");

    return ERR_OK;
}

ErrCode AccountCommand::init()
{
    ACCOUNT_LOGD("enter");

    return ERR_OK;
}

ErrCode AccountCommand::RunAsHelpCommand(void)
{
    ACCOUNT_LOGD("enter");

    resultReceiver_.append(HELP_MSG);

    return ERR_OK;
}

ErrCode AccountCommand::RunAsCreateCommand(void)
{
    ACCOUNT_LOGD("enter");

    ErrCode result = ERR_OK;

    int counter = 0;

    std::string name = "";
    OsAccountType osAccountType = static_cast<OsAccountType>(-1);

    while (true) {
        counter++;

        int option = getopt_long(argc_, argv_, SHORT_OPTIONS.c_str(), LONG_OPTIONS, nullptr);
        ACCOUNT_LOGD("option: %{public}d, optopt: %{public}d, optind: %{public}d", option, optopt, optind);

        if (option == -1) {
            if (counter == 1) {
                result = RunAsCreateCommandError();
            }
            break;
        }

        if (option == '?') {
            result = RunAsCreateCommandMissingOptionArgument();
            break;
        }

        result = RunAsCreateCommandExistentOptionArgument(option, name, osAccountType);
    }

    if (result == ERR_OK) {
        if (name.size() == 0 || osAccountType == static_cast<OsAccountType>(-1)) {
            ACCOUNT_LOGD("'acm create' without enough options");

            if (name.size() == 0) {
                resultReceiver_.append(HELP_MSG_NO_NAME_OPTION + "\n");
            }

            if (osAccountType == static_cast<OsAccountType>(-1)) {
                resultReceiver_.append(HELP_MSG_NO_TYPE_OPTION + "\n");
            }

            result = ERR_INVALID_VALUE;
        }
    }

    if (result != ERR_OK) {
        resultReceiver_.append(HELP_MSG_CREATE);
    } else {
        /* create */

        // make os account info
        OsAccountInfo osAccountInfo;

        // create an os account
        result = OsAccount::GetInstance().CreateOsAccount(name, osAccountType, osAccountInfo);
        if (result == ERR_OK) {
            resultReceiver_ = STRING_CREATE_OS_ACCOUNT_OK + "\n";
        } else {
            resultReceiver_ = STRING_CREATE_OS_ACCOUNT_NG + "\n";
        }
    }

    ACCOUNT_LOGD("result = %{public}d, name = %{public}s, type = %{public}d", result, name.c_str(), osAccountType);

    return result;
}

ErrCode AccountCommand::RunAsDeleteCommand(void)
{
    ACCOUNT_LOGD("enter");

    ErrCode result = ERR_OK;

    int counter = 0;

    int id = -1;

    while (true) {
        counter++;

        int option = getopt_long(argc_, argv_, SHORT_OPTIONS.c_str(), LONG_OPTIONS, nullptr);
        ACCOUNT_LOGD("option: %{public}d, optopt: %{public}d, optind: %{public}d", option, optopt, optind);

        if (option == -1) {
            if (counter == 1) {
                result = RunAsDeleteCommandError();
            }
            break;
        }

        if (option == '?') {
            result = RunAsDeleteCommandMissingOptionArgument();
            break;
        }

        result = RunAsDeleteCommandExistentOptionArgument(option, id);
    }

    if (result != ERR_OK) {
        resultReceiver_.append(HELP_MSG_DELETE);
    } else {
        /* delete */

        // delete an os account
        result = OsAccount::GetInstance().RemoveOsAccount(id);
        if (result == ERR_OK) {
            resultReceiver_ = STRING_DELETE_OS_ACCOUNT_OK + "\n";
        } else {
            resultReceiver_ = STRING_DELETE_OS_ACCOUNT_NG + "\n";
        }
    }

    ACCOUNT_LOGD("result = %{public}d, id = %{public}d", result, id);

    return result;
}

ErrCode AccountCommand::RunAsDumpCommand(void)
{
    ACCOUNT_LOGD("enter");

    ErrCode result = ERR_OK;

    int counter = 0;

    int id = -1;

    while (true) {
        counter++;

        int option = getopt_long(argc_, argv_, SHORT_OPTIONS.c_str(), LONG_OPTIONS, nullptr);
        ACCOUNT_LOGD("option: %{public}d, optopt: %{public}d, optind: %{public}d", option, optopt, optind);

        if (option == -1) {
            if (counter == 1) {
                result = RunAsDumpCommandError();
            }
            break;
        }

        if (option == '?') {
            result = RunAsDumpCommandMissingOptionArgument();
            break;
        }

        result = RunAsDumpCommandExistentOptionArgument(option, id);
    }

    if (result != ERR_OK) {
        resultReceiver_.append(HELP_MSG_DUMP);
    } else {
        /* dump */

        // dump state
        std::vector<std::string> state;
        result = OsAccount::GetInstance().DumpState(id, state);
        if (result == ERR_OK) {
            for (auto info : state) {
                resultReceiver_ += info + "\n";
            }
        } else {
            resultReceiver_ = STRING_DUMP_OS_ACCOUNT_NG + "\n";
        }
    }

    ACCOUNT_LOGD("result = %{public}d, id = %{public}d", result, id);

    return result;
}

ErrCode AccountCommand::RunAsSetCommand(void)
{
    ACCOUNT_LOGD("enter");

    ErrCode result = ERR_OK;

    int counter = 0;

    int id = -1;
    std::vector<std::string> constraints;
    bool enable = false;

    while (true) {
        counter++;

        int option = getopt_long(argc_, argv_, SHORT_OPTIONS.c_str(), LONG_OPTIONS, nullptr);
        ACCOUNT_LOGD("option: %{public}d, optopt: %{public}d, optind: %{public}d", option, optopt, optind);

        if (option == -1) {
            if (counter == 1) {
                result = RunAsSetCommandError();
            }
            break;
        }

        if (option == '?') {
            result = RunAsSetCommandMissingOptionArgument();
            break;
        }

        result = RunAsSetCommandExistentOptionArgument(option, id, constraints, enable);
    }

    if (result == ERR_OK) {
        if (id == -1 || constraints.size() == 0) {
            ACCOUNT_LOGD("'acm set' without enough options");

            if (id == -1) {
                resultReceiver_.append(HELP_MSG_NO_ID_OPTION + "\n");
            }

            if (constraints.size() == 0) {
                resultReceiver_.append(HELP_MSG_NO_CONSTRAINTS_OPTION + "\n");
            }

            result = ERR_INVALID_VALUE;
        }
    }

    if (result != ERR_OK) {
        resultReceiver_.append(HELP_MSG_SET);
    } else {
        /* set */

        // set os account constraints
        result = OsAccount::GetInstance().SetOsAccountConstraints(id, constraints, enable);
        if (result == ERR_OK) {
            resultReceiver_ = STRING_SET_OS_ACCOUNT_CONSTRAINTS_OK + "\n";
        } else {
            resultReceiver_ = STRING_SET_OS_ACCOUNT_CONSTRAINTS_NG + "\n";
        }
    }

    ACCOUNT_LOGD("result = %{public}d, id = %{public}d, enable = %{public}d", result, id, enable);
    for (auto constraint : constraints) {
        ACCOUNT_LOGD("constraint = %{public}s", constraint.c_str());
    }

    return result;
}

ErrCode AccountCommand::RunAsSwitchCommand(void)
{
    ACCOUNT_LOGD("enter");

    ErrCode result = ERR_OK;

    int counter = 0;

    int id = -1;

    while (true) {
        counter++;

        int option = getopt_long(argc_, argv_, SHORT_OPTIONS.c_str(), LONG_OPTIONS, nullptr);
        ACCOUNT_LOGD("option: %{public}d, optopt: %{public}d, optind: %{public}d", option, optopt, optind);

        if (option == -1) {
            if (counter == 1) {
                result = RunAsSwitchCommandError();
            }
            break;
        }

        if (option == '?') {
            result = RunAsSwitchCommandMissingOptionArgument();
            break;
        }

        result = RunAsSwitchCommandExistentOptionArgument(option, id);
    }

    if (result != ERR_OK) {
        resultReceiver_.append(HELP_MSG_SWITCH);
    } else {
        /* switch */

        // switch an os account
        result = OsAccount::GetInstance().ActivateOsAccount(id);
        if (result == ERR_OK) {
            resultReceiver_ = STRING_SWITCH_OS_ACCOUNT_OK + "\n";
        } else {
            resultReceiver_ = STRING_SWITCH_OS_ACCOUNT_NG + "\n";
        }
    }

    ACCOUNT_LOGD("result = %{public}d, id = %{public}d", result, id);

    return result;
}

ErrCode AccountCommand::RunAsStopCommand(void)
{
    ACCOUNT_LOGD("enter");

    ErrCode result = ERR_OK;

    int counter = 0;

    int id = -1;

    while (true) {
        counter++;

        int option = getopt_long(argc_, argv_, SHORT_OPTIONS.c_str(), LONG_OPTIONS, nullptr);
        ACCOUNT_LOGD("option: %{public}d, optopt: %{public}d, optind: %{public}d", option, optopt, optind);

        if (option == -1) {
            if (counter == 1) {
                result = RunAsStopCommandError();
            }
            break;
        }

        if (option == '?') {
            result = RunAsStopCommandMissingOptionArgument();
            break;
        }

        result = RunAsStopCommandExistentOptionArgument(option, id);
    }

    if (result != ERR_OK) {
        resultReceiver_.append(HELP_MSG_STOP);
    } else {
        /* stop */

        // stop an os account
        result = OsAccount::GetInstance().StopOsAccount(id);
        if (result == ERR_OK) {
            resultReceiver_ = STRING_STOP_OS_ACCOUNT_OK + "\n";
        } else {
            resultReceiver_ = STRING_STOP_OS_ACCOUNT_NG + "\n";
        }
    }

    ACCOUNT_LOGD("result = %{public}d, id = %{public}d", result, id);

    return result;
}

ErrCode AccountCommand::RunAsCreateCommandError(void)
{
    ACCOUNT_LOGD("enter");

    ErrCode result = ERR_OK;

    if (optind < 0 || optind >= argc_) {
        return ERR_INVALID_VALUE;
    }

    // When scanning the first argument
    if (strcmp(argv_[optind], cmd_.c_str()) == 0) {
        // 'acm create' with no option: acm create
        // 'acm create' with a wrong argument: acm create xxx
        ACCOUNT_LOGD("'acm create' with no option.");

        resultReceiver_.append(HELP_MSG_NO_OPTION + "\n");
        result = ERR_INVALID_VALUE;
    }

    ACCOUNT_LOGD("end, result = %{public}d", result);

    return result;
}

ErrCode AccountCommand::RunAsCreateCommandMissingOptionArgument(void)
{
    ACCOUNT_LOGD("enter");

    ErrCode result = ERR_OK;

    switch (optopt) {
        case 'n': {
            // 'acm create -n <name>' with no argument: acm create -n
            // 'acm create --name <name>' with no argument: acm create --name
            ACCOUNT_LOGD("'acm create -n' with no argument.");

            resultReceiver_.append(HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n");
            result = ERR_INVALID_VALUE;
            break;
        }
        case 't': {
            // 'acm create -t <type>' with no argument: acm create -t
            // 'acm create --type <type>' with no argument: acm create --type
            ACCOUNT_LOGD("'acm create -t' with no argument.");

            resultReceiver_.append(HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n");

            result = ERR_INVALID_VALUE;
            break;
        }
        default: {
            // 'acm create' with an unknown option: acm create -x
            // 'acm create' with an unknown option: acm create -xxx
            std::string unknownOption = "";
            std::string unknownOptionMsg = GetUnknownOptionMsg(unknownOption);

            ACCOUNT_LOGD("'acm create' with an unknown option.");

            resultReceiver_.append(unknownOptionMsg);
            result = ERR_INVALID_VALUE;
            break;
        }
    }

    ACCOUNT_LOGD("end, result = %{public}d", result);

    return result;
}

ErrCode AccountCommand::RunAsCreateCommandExistentOptionArgument(
    const int &option, std::string &name, OsAccountType &type)
{
    ACCOUNT_LOGD("enter");

    ErrCode result = ERR_OK;

    switch (option) {
        case 'h': {
            // 'acm create -h'
            // 'acm create --help'
            result = ERR_INVALID_VALUE;
            break;
        }
        case 'n': {
            // 'acm create -n <name>'
            // 'acm create --name <name>'
            name = optarg;
            break;
        }
        case 't': {
            // 'acm create -t <type>'
            // 'acm create --type <type>'
            result = AnalyzeTypeArgument(type);
            break;
        }
        default: {
            break;
        }
    }

    ACCOUNT_LOGD("end, result = %{public}d", result);

    return result;
}

ErrCode AccountCommand::RunAsDeleteCommandError(void)
{
    ACCOUNT_LOGD("enter");

    ErrCode result = ERR_OK;

    if (optind < 0 || optind >= argc_) {
        return ERR_INVALID_VALUE;
    }

    // When scanning the first argument
    if (strcmp(argv_[optind], cmd_.c_str()) == 0) {
        // 'acm delete' with no option: acm delete
        // 'acm delete' with a wrong argument: acm delete xxx
        ACCOUNT_LOGD("'acm delete' with no option.");

        resultReceiver_.append(HELP_MSG_NO_OPTION + "\n");
        result = ERR_INVALID_VALUE;
    }

    ACCOUNT_LOGD("end, result = %{public}d", result);

    return result;
}

ErrCode AccountCommand::RunAsDeleteCommandMissingOptionArgument(void)
{
    ACCOUNT_LOGD("enter");

    ErrCode result = ERR_OK;

    switch (optopt) {
        case 'i': {
            // 'acm delete -i <id>' with no argument: acm delete -i
            // 'acm delete --id <id>' with no argument: acm delete --id
            ACCOUNT_LOGD("'acm delete -i' with no argument.");

            resultReceiver_.append(HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n");
            result = ERR_INVALID_VALUE;
            break;
        }
        default: {
            // 'acm delete' with an unknown option: acm delete -x
            // 'acm delete' with an unknown option: acm delete -xxx
            std::string unknownOption = "";
            std::string unknownOptionMsg = GetUnknownOptionMsg(unknownOption);

            ACCOUNT_LOGD("'acm delete' with an unknown option.");

            resultReceiver_.append(unknownOptionMsg);
            result = ERR_INVALID_VALUE;
            break;
        }
    }

    return result;
}

ErrCode AccountCommand::RunAsDeleteCommandExistentOptionArgument(const int &option, int &id)
{
    ACCOUNT_LOGD("enter");

    ErrCode result = ERR_OK;

    switch (option) {
        case 'h': {
            // 'acm delete -h'
            // 'acm delete --help'
            result = ERR_INVALID_VALUE;
            break;
        }
        case 'i': {
            // 'acm delete -i <id>'
            // 'acm delete --id <id>'
            result = AnalyzeLocalIdArgument(id);
            break;
        }
        default: {
            break;
        }
    }

    return result;
}

ErrCode AccountCommand::RunAsDumpCommandError(void)
{
    ACCOUNT_LOGD("enter");

    ErrCode result = ERR_OK;

    if (optind < 0 || optind >= argc_) {
        return ERR_INVALID_VALUE;
    }

    // When scanning the first argument
    if (strcmp(argv_[optind], cmd_.c_str()) == 0) {
        // 'acm dump' with no option: acm dump
        // 'acm dump' with a wrong argument: acm dump xxx
        ACCOUNT_LOGD("'acm dump' with no option.");

        resultReceiver_.append(HELP_MSG_NO_OPTION + "\n");
        result = ERR_INVALID_VALUE;
    }

    ACCOUNT_LOGD("end, result = %{public}d", result);

    return result;
}

ErrCode AccountCommand::RunAsDumpCommandMissingOptionArgument(void)
{
    ACCOUNT_LOGD("enter");

    ErrCode result = ERR_OK;

    switch (optopt) {
        case 'i': {
            // 'acm dump -i <id>' with no argument: acm dump -i
            // 'acm dump --id <id>' with no argument: acm dump --id
            ACCOUNT_LOGD("'acm dump -i' with no argument.");

            resultReceiver_.append(HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n");
            result = ERR_INVALID_VALUE;
            break;
        }
        default: {
            // 'acm dump' with an unknown option: acm dump -x
            // 'acm dump' with an unknown option: acm dump -xxx
            std::string unknownOption = "";
            std::string unknownOptionMsg = GetUnknownOptionMsg(unknownOption);

            ACCOUNT_LOGD("'acm dump' with an unknown option.");

            resultReceiver_.append(unknownOptionMsg);
            result = ERR_INVALID_VALUE;
            break;
        }
    }

    return result;
}

ErrCode AccountCommand::RunAsDumpCommandExistentOptionArgument(const int &option, int &id)
{
    ACCOUNT_LOGD("enter");

    ErrCode result = ERR_OK;

    switch (option) {
        case 'h': {
            // 'acm dump -h'
            // 'acm dump --help'
            result = ERR_INVALID_VALUE;
            break;
        }
        case 'a': {
            // 'acm dump -a'
            // 'acm dump --all'
            break;
        }
        case 'i': {
            // 'acm dump -i <id>'
            // 'acm dump --id <id>'
            result = AnalyzeLocalIdArgument(id);
            break;
        }
        default: {
            break;
        }
    }

    ACCOUNT_LOGD("end, result = %{public}d, id = %{public}d", result, id);

    return result;
}

ErrCode AccountCommand::RunAsSetCommandError(void)
{
    ACCOUNT_LOGD("enter");

    ErrCode result = ERR_OK;

    if (optind < 0 || optind >= argc_) {
        return ERR_INVALID_VALUE;
    }

    // When scanning the first argument
    if (strcmp(argv_[optind], cmd_.c_str()) == 0) {
        // 'acm set' with no option: acm set
        // 'acm set' with a wrong argument: acm set xxx
        ACCOUNT_LOGD("'acm set' with no option.");

        resultReceiver_.append(HELP_MSG_NO_OPTION + "\n");
        result = ERR_INVALID_VALUE;
    }

    ACCOUNT_LOGD("end, result = %{public}d", result);

    return result;
}

ErrCode AccountCommand::RunAsSetCommandMissingOptionArgument(void)
{
    ACCOUNT_LOGD("enter");

    ErrCode result = ERR_OK;

    switch (optopt) {
        case 'i': {
            // 'acm set -i <id>' with no argument: acm set -i
            // 'acm set --id <id>' with no argument: acm set --id
            ACCOUNT_LOGD("'acm set -i' with no argument.");

            resultReceiver_.append(HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n");
            result = ERR_INVALID_VALUE;
            break;
        }
        case 'c': {
            // 'acm set -c <constraints>' with no argument: acm set -c
            // 'acm set --constraint <constraints>' with no argument: acm set --constraint
            ACCOUNT_LOGD("'acm set -c' with no argument.");

            resultReceiver_.append(HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n");
            result = ERR_INVALID_VALUE;
            break;
        }
        default: {
            // 'acm set' with an unknown option: acm set -x
            // 'acm set' with an unknown option: acm set -xxx
            std::string unknownOption = "";
            std::string unknownOptionMsg = GetUnknownOptionMsg(unknownOption);

            ACCOUNT_LOGD("'set dump' with an unknown option.");

            resultReceiver_.append(unknownOptionMsg);
            result = ERR_INVALID_VALUE;
            break;
        }
    }

    return result;
}

ErrCode AccountCommand::RunAsSetCommandExistentOptionArgument(
    const int &option, int &id, std::vector<std::string> &constraints, bool &enable)
{
    ACCOUNT_LOGD("enter");

    ErrCode result = ERR_OK;

    switch (option) {
        case 'h': {
            // 'acm set -h'
            // 'acm set --help'
            result = ERR_INVALID_VALUE;
            break;
        }
        case 'i': {
            // 'acm set -i <id>'
            // 'acm set --id <id>'
            result = AnalyzeLocalIdArgument(id);
            break;
        }
        case 'c': {
            // 'acm set -c <constraints>'
            // 'acm set --constraint <constraints>'
            result = AnalyzeConstraintArgument(constraints);
            break;
        }
        case 'e': {
            // 'acm set -e'
            // 'acm set --enable'
            enable = true;
            break;
        }
        default: {
            break;
        }
    }

    ACCOUNT_LOGD("end, result = %{public}d, id = %{public}d", result, id);

    return result;
}

ErrCode AccountCommand::RunAsSwitchCommandError(void)
{
    ACCOUNT_LOGD("enter");

    ErrCode result = ERR_OK;

    if (optind < 0 || optind >= argc_) {
        return ERR_INVALID_VALUE;
    }

    // When scanning the first argument
    if (strcmp(argv_[optind], cmd_.c_str()) == 0) {
        // 'acm switch' with no option: acm switch
        // 'acm switch' with a wrong argument: acm switch xxx
        ACCOUNT_LOGD("'acm switch' with no option.");

        resultReceiver_.append(HELP_MSG_NO_OPTION + "\n");
        result = ERR_INVALID_VALUE;
    }

    ACCOUNT_LOGD("end, result = %{public}d", result);

    return result;
}

ErrCode AccountCommand::RunAsStopCommandError(void)
{
    ACCOUNT_LOGD("enter");

    ErrCode result = ERR_OK;

    if (optind < 0 || optind >= argc_) {
        return ERR_INVALID_VALUE;
    }

    // When scanning the first argument
    if (strcmp(argv_[optind], cmd_.c_str()) == 0) {
        // 'acm stop' with no option: acm stop
        // 'acm stop' with a wrong argument: acm stop xxx
        ACCOUNT_LOGD("'acm stop' with no option.");

        resultReceiver_.append(HELP_MSG_NO_OPTION + "\n");
        result = ERR_INVALID_VALUE;
    }

    ACCOUNT_LOGD("end, result = %{public}d", result);

    return result;
}

ErrCode AccountCommand::RunAsSwitchCommandMissingOptionArgument(void)
{
    ACCOUNT_LOGD("enter");

    ErrCode result = ERR_OK;

    switch (optopt) {
        case 'i': {
            // 'acm switch -i <id>' with no argument: acm switch -i
            // 'acm switch --id <id>' with no argument: acm switch --id
            ACCOUNT_LOGD("'acm switch -i' with no argument.");

            resultReceiver_.append(HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n");
            result = ERR_INVALID_VALUE;
            break;
        }
        default: {
            // 'acm switch' with an unknown option: acm switch -x
            // 'acm switch' with an unknown option: acm switch -xxx
            std::string unknownOption = "";
            std::string unknownOptionMsg = GetUnknownOptionMsg(unknownOption);

            ACCOUNT_LOGD("'acm switch' with an unknown option.");

            resultReceiver_.append(unknownOptionMsg);
            result = ERR_INVALID_VALUE;
            break;
        }
    }

    return result;
}

ErrCode AccountCommand::RunAsStopCommandMissingOptionArgument(void)
{
    ACCOUNT_LOGD("enter");

    ErrCode result = ERR_OK;

    switch (optopt) {
        case 'i': {
            // 'acm stop -i <id>' with no argument: acm stop -i
            // 'acm stop --id <id>' with no argument: acm stop --id
            ACCOUNT_LOGD("'acm stop -i' with no argument.");

            resultReceiver_.append(HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n");
            result = ERR_INVALID_VALUE;
            break;
        }
        default: {
            // 'acm stop' with an unknown option: acm stop -x
            // 'acm stop' with an unknown option: acm stop -xxx
            std::string unknownOption = "";
            std::string unknownOptionMsg = GetUnknownOptionMsg(unknownOption);

            ACCOUNT_LOGD("'acm stop' with an unknown option.");

            resultReceiver_.append(unknownOptionMsg);
            result = ERR_INVALID_VALUE;
            break;
        }
    }

    return result;
}

ErrCode AccountCommand::RunAsSwitchCommandExistentOptionArgument(const int &option, int &id)
{
    ACCOUNT_LOGD("enter");

    ErrCode result = ERR_OK;

    switch (option) {
        case 'h': {
            // 'acm switch -h'
            // 'acm switch --help'
            result = ERR_INVALID_VALUE;
            break;
        }
        case 'i': {
            // 'acm switch -i <id>'
            // 'acm switch --id <id>'
            result = AnalyzeLocalIdArgument(id);
            break;
        }
        default: {
            break;
        }
    }

    return result;
}

ErrCode AccountCommand::RunAsStopCommandExistentOptionArgument(const int &option, int &id)
{
    ACCOUNT_LOGD("enter");

    ErrCode result = ERR_OK;

    switch (option) {
        case 'h': {
            // 'acm stop -h'
            // 'acm stop --help'
            result = ERR_INVALID_VALUE;
            break;
        }
        case 'i': {
            // 'acm stop -i <id>'
            // 'acm stop --id <id>'
            result = AnalyzeLocalIdArgument(id);
            break;
        }
        default: {
            break;
        }
    }

    return result;
}

ErrCode AccountCommand::AnalyzeTypeArgument(OsAccountType &type)
{
    ErrCode result = ERR_OK;

    std::string typeByUser = optarg;

    if (typeByUser == "admin") {
        type = OsAccountType::ADMIN;
    } else if (typeByUser == "normal") {
        type = OsAccountType::NORMAL;
    } else if (typeByUser == "guest") {
        type = OsAccountType::GUEST;
    } else {
        resultReceiver_.append(HELP_MSG_INVALID_TYPE_ARGUMENT + "\n");
        result = ERR_INVALID_VALUE;
    }

    return result;
}

ErrCode AccountCommand::AnalyzeLocalIdArgument(int &id)
{
    std::string idByUser = optarg;
    if (idByUser == "0") {
        id = 0;
        return ERR_OK;
    }

    if (atoi(optarg) == 0) {
        resultReceiver_.append(HELP_MSG_INVALID_ID_ARGUMENT + "\n");
        return ERR_INVALID_VALUE;
    }

    id = atoi(optarg);

    return ERR_OK;
}

ErrCode AccountCommand::AnalyzeConstraintArgument(std::vector<std::string> &constraints)
{
    ACCOUNT_LOGD("enter");

    std::string constraintsByUser = optarg;
    ACCOUNT_LOGD("constraintsByUser = %{public}s", constraintsByUser.c_str());

    constraints.clear();
    std::string constraint = "";
    std::string delimiter = ",";

    size_t last = 0;
    size_t next = 0;
    while ((next = constraintsByUser.find(delimiter, last)) != std::string::npos) {
        constraint = constraintsByUser.substr(last, next - last);
        ACCOUNT_LOGD("constraint = %{public}s", constraint.c_str());

        constraints.emplace_back(constraint);
        last = next + 1;
    }
    constraint = constraintsByUser.substr(last);
    ACCOUNT_LOGD("constraint = %{public}s", constraint.c_str());
    constraints.emplace_back(constraint);

    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
