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
#include "account_command.h"
#include <fstream>
#include <getopt.h>
#include <sys/stat.h>
#include "account_log_wrapper.h"
#include "singleton.h"

using namespace OHOS::AAFwk;

namespace OHOS {
namespace AccountSA {
namespace {
const std::string SHORT_OPTIONS = "hn:t:i:s:l:c:ea";
const struct option LONG_OPTIONS[] = {
    {"help", no_argument, nullptr, 'h'},
    {"name", required_argument, nullptr, 'n'},
    {"type", required_argument, nullptr, 't'},
    {"id", required_argument, nullptr, 'i'},
    {"shortName", optional_argument, nullptr, 's'},
    {"disallowedlist", optional_argument, nullptr, 'l'},
    {"constraint", required_argument, nullptr, 'c'},
    {"enable", no_argument, nullptr, 'e'},
    {"all", no_argument, nullptr, 'a'},
    {nullptr, no_argument, nullptr, no_argument}
};

static const std::string DEACTIVATE_COMMAND = "deactivate";
static const std::string DELETE_COMMAND = "delete";
static const std::string SWITCH_COMMAND = "switch";
static const std::string DUMP_COMMAND = "dump";
static const std::string SET_COMMAND = "set";
static const std::string CREATE_COMMAND = "create";

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
        {"deactivate", std::bind(&AccountCommand::RunAsDeactivateCommand, this)},
    };

    return ERR_OK;
}

ErrCode AccountCommand::CreateMessageMap()
{
    return ERR_OK;
}

ErrCode AccountCommand::init()
{
    return ERR_OK;
}

ErrCode AccountCommand::RunAsHelpCommand(void)
{
    ACCOUNT_LOGD("enter");
    resultReceiver_.append(HELP_MSG);
    return ERR_OK;
}

ErrCode AccountCommand::ParseCreateCommandOpt(std::string &name,
    std::string &shortName, OsAccountType &osAccountType, std::vector<std::string> &disallowedList)
{
    int counter = 0;
    ErrCode result = ERR_OK;
    while (true) {
        counter++;

        int option = getopt_long(argc_, argv_, SHORT_OPTIONS.c_str(), LONG_OPTIONS, nullptr);
        ACCOUNT_LOGD("option: %{public}d, optopt: %{public}d, optind: %{public}d", option, optopt, optind);

        if (option == -1) {
            if (counter == 1) {
                result = RunCommandError(CREATE_COMMAND);
            }
            break;
        }

        if (option == '?') {
            result = RunAsCreateCommandMissingOptionArgument();
            break;
        }

        result = RunAsCreateCommandExistentOptionArgument(option, name, shortName, osAccountType, disallowedList);
    }
    return result;
}

ErrCode AccountCommand::RunAsCreateCommand(void)
{
    ACCOUNT_LOGD("enter");
    ErrCode result = ERR_OK;
    std::string name = "";
    std::string shortName = "";
    OsAccountType osAccountType = static_cast<OsAccountType>(-1);
    CreateOsAccountOptions options;
    result = ParseCreateCommandOpt(name, shortName, osAccountType, options.disallowedHapList);
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

    if (result != ERR_OK && result != ERR_ACCOUNT_COMMON_FILE_OPEN_FAILED) {
        resultReceiver_.append(HELP_MSG_CREATE);
    } else {
        /* create */

        // make os account info
        OsAccountInfo osAccountInfo;
        if (shortName.empty()) {
            shortName = name;
        }
        // create an os account
        result = OsAccount::GetInstance().CreateOsAccount(name, shortName, osAccountType, osAccountInfo, options);
        switch (result) {
            case ERR_OK:
                resultReceiver_ = STRING_CREATE_OS_ACCOUNT_OK + "\n";
                break;
            case ERR_OSACCOUNT_SERVICE_MANAGER_NOT_ENABLE_MULTI_ERROR:
                resultReceiver_ = "create failed, reason: multiple-os-account feature not enabled\n";
                break;
            default:
                resultReceiver_ = STRING_CREATE_OS_ACCOUNT_NG + "\n";
        }
    }

    ACCOUNT_LOGD("result = %{public}d, name = %{public}s, type = %{public}d", result, name.c_str(), osAccountType);
    return result;
}

ErrCode AccountCommand::RunAsDeleteCommand(void)
{
    ErrCode result = ERR_OK;
    int id = -1;

    ParseCommandOpt(DELETE_COMMAND, result, id);

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
    ErrCode result = ERR_OK;
    int id = -1;

    ParseCommandOpt(DUMP_COMMAND, result, id);

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

void AccountCommand::RunCommand(
    int &counter, ErrCode &result, bool &enable, int &id, std::vector<std::string> &constraints)
{
    while (true) {
        counter++;

        int option = getopt_long(argc_, argv_, SHORT_OPTIONS.c_str(), LONG_OPTIONS, nullptr);
        ACCOUNT_LOGD("option: %{public}d, optopt: %{public}d, optind: %{public}d", option, optopt, optind);

        if (option == -1) {
            if (counter == 1) {
                result = RunCommandError(SET_COMMAND);
            }
            break;
        }

        if (option == '?') {
            result = RunAsSetCommandMissingOptionArgument();
            break;
        }

        result = RunAsSetCommandExistentOptionArgument(option, id, constraints, enable);
    }
}

ErrCode AccountCommand::RunAsSetCommand(void)
{
    ErrCode result = ERR_OK;
    int counter = 0;
    int id = -1;
    std::vector<std::string> constraints;
    bool enable = false;

    RunCommand(counter, result, enable, id, constraints);

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

void AccountCommand::ParseCommandOpt(const std::string &command, ErrCode &result, int &id)
{
    int counter = 0;
    while (true) {
        counter++;

        int option = getopt_long(argc_, argv_, SHORT_OPTIONS.c_str(), LONG_OPTIONS, nullptr);
        ACCOUNT_LOGD("option: %{public}d, optopt: %{public}d, optind: %{public}d", option, optopt, optind);

        if (option == -1) {
            if (counter == 1) {
                result = RunCommandError(command);
            }
            break;
        }

        if (option == '?') {
            result = RunAsCommonCommandMissingOptionArgument(command);
            break;
        }

        result = RunAsCommonCommandExistentOptionArgument(option, id);
    }
}

ErrCode AccountCommand::RunAsSwitchCommand(void)
{
    ErrCode result = ERR_OK;
    int id = -1;
    ParseCommandOpt(SWITCH_COMMAND, result, id);

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

ErrCode AccountCommand::RunAsDeactivateCommand(void)
{
    ErrCode result = ERR_OK;
    int id = -1;

    ParseCommandOpt(DEACTIVATE_COMMAND, result, id);

    if (result != ERR_OK) {
        resultReceiver_.append(HELP_MSG_DEACTIVATE);
    } else if (id != -1) {
        /* deactivate */

        // deactivate an os account
        result = OsAccount::GetInstance().DeactivateOsAccount(id);
        if (result == ERR_OK) {
            resultReceiver_ = STRING_DEACTIVATE_OS_ACCOUNT_OK + "\n";
        } else {
            resultReceiver_ = STRING_DEACTIVATE_OS_ACCOUNT_NG + "\n";
        }
    } else {
        result = OsAccount::GetInstance().DeactivateAllOsAccounts();
        if (result == ERR_OK) {
            resultReceiver_ = STRING_DEACTIVATE_ALL_OS_ACCOUNTS_OK + "\n";
        } else {
            resultReceiver_ = STRING_DEACTIVATE_ALL_OS_ACCOUNTS_NG + "\n";
        }
    }

    ACCOUNT_LOGD("result = %{public}d, id = %{public}d", result, id);

    return result;
}

ErrCode AccountCommand::RunAsCreateCommandMissingOptionArgument(void)
{
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

ErrCode AccountCommand::RunAsCreateCommandExistentOptionArgument(const int &option, std::string &name,
    std::string &shortName, OsAccountType &type, std::vector<std::string> &disallowedList)
{
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
        case 's': {
            // 'acm create -s <shortName>'
            // 'acm create --shortName <shortName>'
            shortName = optarg;
            break;
        }
        case 'l': {
            // 'acm create -l <disallowedlist>'
            // 'acm create --disallowedlist <disallowedlist>'
            result = AnalyzeDisallowedListArgument(disallowedList);
            break;
        }
        default: {
            break;
        }
    }

    ACCOUNT_LOGD("end, result = %{public}d", result);
    return result;
}

ErrCode AccountCommand::RunAsCommonCommandMissingOptionArgument(const std::string &command)
{
    ErrCode result = ERR_OK;

    switch (optopt) {
        case 'i': {
            // 'acm command -i <id>' with no argument: acm command -i
            // 'acm command --id <id>' with no argument: acm command --id
            ACCOUNT_LOGD("'acm %{public}s -i' with no argument.", command.c_str());

            resultReceiver_.append(HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n");
            result = ERR_INVALID_VALUE;
            break;
        }
        default: {
            // 'acm delete' with an unknown option: acm delete -x
            // 'acm delete' with an unknown option: acm delete -xxx
            std::string unknownOption = "";
            std::string unknownOptionMsg = GetUnknownOptionMsg(unknownOption);

            ACCOUNT_LOGD("'acm %{public}s' with an unknown option.",  command.c_str());

            resultReceiver_.append(unknownOptionMsg);
            result = ERR_INVALID_VALUE;
            break;
        }
    }
    ACCOUNT_LOGD("end, result = %{public}d", result);
    return result;
}

ErrCode AccountCommand::RunCommandError(const std::string &command)
{
    ErrCode result = ERR_OK;

    if (optind < 0 || optind >= argc_) {
        ACCOUNT_LOGD("optind %{public}d invalid", optind);
        return ERR_INVALID_VALUE;
    }

    // When scanning the first argument
    if (strcmp(argv_[optind], cmd_.c_str()) == 0) {
        // 'acm command' with no option: acm command
        // 'acm command' with a wrong argument: acm command xxx
        ACCOUNT_LOGD("'acm %{public}s' with no option.", command.c_str());

        resultReceiver_.append(HELP_MSG_NO_OPTION + "\n");
        result = ERR_INVALID_VALUE;
    }

    ACCOUNT_LOGD("end, result = %{public}d", result);

    return result;
}

ErrCode AccountCommand::RunAsSetCommandMissingOptionArgument(void)
{
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
    ACCOUNT_LOGD("end, result = %{public}d", result);
    return result;
}

ErrCode AccountCommand::RunAsSetCommandExistentOptionArgument(
    const int &option, int &id, std::vector<std::string> &constraints, bool &enable)
{
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

ErrCode AccountCommand::RunAsCommonCommandExistentOptionArgument(const int &option, int &id)
{
    ErrCode result = ERR_OK;

    switch (option) {
        case 'h': {
            // 'acm command -h'
            // 'acm command --help'
            // command includes stop, switch, deactivate, dump, delete
            result = ERR_INVALID_VALUE;
            break;
        }
        case 'i': {
            // 'acm command -i <id>'
            // 'acm command --id <id>
            // command includes stop, switch, deactivate, dump, delete
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
    } else if (typeByUser == "private") {
        type = OsAccountType::PRIVATE;
    } else {
        resultReceiver_.append(HELP_MSG_INVALID_TYPE_ARGUMENT + "\n");
        result = ERR_INVALID_VALUE;
    }

    return result;
}

static bool IsExistFile(const std::string &path)
{
    if (path.empty()) {
        return false;
    }

    struct stat buf = {};
    if (stat(path.c_str(), &buf) != 0) {
        return false;
    }

    return S_ISREG(buf.st_mode);
}

static ErrCode GetDisallowedListByPath(const std::string &path, std::vector<std::string> &disallowedList)
{
    if (!IsExistFile(path)) {
        ACCOUNT_LOGE("cannot find file, path = %{public}s", path.c_str());
        return ERR_ACCOUNT_COMMON_FILE_OPEN_FAILED;
    }
    std::ifstream readFile;
    readFile.open(path.c_str(), std::ios::in);
    if (!readFile.is_open()) {
        ACCOUNT_LOGE("cannot open file, path = %{public}s", path.c_str());
        return ERR_ACCOUNT_COMMON_FILE_OPEN_FAILED;
    }
    std::string str;
    while (getline(readFile, str)) {
        ACCOUNT_LOGI("read file, str = %{public}s", str.c_str());
        disallowedList.emplace_back(str);
    }
    readFile.close();
    return ERR_OK;
}

ErrCode AccountCommand::AnalyzeDisallowedListArgument(std::vector<std::string> &disallowedList)
{
    std::string listPath = optarg;
    return GetDisallowedListByPath(listPath, disallowedList);
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