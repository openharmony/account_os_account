/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include "os_account_manager_service.h"
#include <algorithm>
#include <cstddef>
#include <stack>
#include "account_constants.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "account_hisysevent_adapter.h"
#include "hitrace_adapter.h"
#include "iinner_os_account_manager.h"
#include "ipc_skeleton.h"
#include "os_account_constants.h"
#ifdef HICOLLIE_ENABLE
#include "account_timer.h"
#include "xcollie/xcollie.h"
#endif // HICOLLIE_ENABLE
#include "os_account_info_json_parser.h"

namespace OHOS {
namespace AccountSA {
namespace {
#ifdef HICOLLIE_ENABLE
thread_local std::stack<int32_t> g_timerIdStack;
#endif
const std::string DUMP_TAB_CHARACTER = "\t";
const std::map<OsAccountType, std::string> DUMP_TYPE_MAP = {
    {OsAccountType::ADMIN, "admin"},
    {OsAccountType::NORMAL, "normal"},
    {OsAccountType::GUEST, "guest"},
    {OsAccountType::PRIVATE, "private"},
    {OsAccountType::MAINTENANCE, "maintenance"},
};
const char CONSTANT_CREATE[] = "constraint.os.account.create";
const char CONSTANT_CREATE_DIRECTLY[] = "constraint.os.account.create.directly";
const char CONSTANT_REMOVE[] = "constraint.os.account.remove";
const char CONSTANT_ACTIVATE[] = "constraint.os.account.activate";
const char CONSTANT_SET_ICON[] = "constraint.os.account.set.icon";
#ifndef IS_RELEASE_VERSION
const std::int32_t ROOT_UID = 0;
#endif
const char DEFAULT_ANON_STR[] = "**********";
const size_t INTERCEPT_HEAD_PART_LEN_FOR_NAME = 1;

const char MANAGE_LOCAL_ACCOUNTS[] = "ohos.permission.MANAGE_LOCAL_ACCOUNTS";
const char GET_LOCAL_ACCOUNTS[] = "ohos.permission.GET_LOCAL_ACCOUNTS";
const char INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION[] =
    "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION";
const char INTERACT_ACROSS_LOCAL_ACCOUNTS[] = "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS";
const std::string GET_DOMAIN_ACCOUNTS = "ohos.permission.GET_DOMAIN_ACCOUNTS";
const std::string MANAGE_EDM_POLICY = "ohos.permission.MANAGE_EDM_POLICY";
const std::set<uint32_t> uidWhiteListForCreation { 3057 };
const std::string SPECIAL_CHARACTER_ARRAY = "<>|\":*?/\\";
const std::vector<std::string> SHORT_NAME_CANNOT_BE_NAME_ARRAY = {".", ".."};
#ifdef HICOLLIE_ENABLE
constexpr std::int32_t RECOVERY_TIMEOUT = 6; // timeout 6s
#endif
const std::set<uint32_t> WATCH_DOG_WHITE_LIST = {
    static_cast<uint32_t>(IOsAccountIpcCode::COMMAND_CREATE_OS_ACCOUNT),
    static_cast<uint32_t>(
        IOsAccountIpcCode::
            COMMAND_CREATE_OS_ACCOUNT_IN_STRING_IN_STRING_IN_INT_OUT_STRINGRAWDATA_IN_CREATEOSACCOUNTOPTIONS),
    static_cast<uint32_t>(
        IOsAccountIpcCode::
            COMMAND_CREATE_OS_ACCOUNT_IN_STRING_IN_STRING_IN_INT_OUT_STRINGRAWDATA),
    static_cast<uint32_t>(
        IOsAccountIpcCode::COMMAND_CREATE_OS_ACCOUNT_WITH_FULL_INFO),
    static_cast<uint32_t>(
        IOsAccountIpcCode::
            COMMAND_CREATE_OS_ACCOUNT_WITH_FULL_INFO_IN_OSACCOUNTINFO),
    static_cast<uint32_t>(
        IOsAccountIpcCode::COMMAND_CREATE_OS_ACCOUNT_FOR_DOMAIN),
    static_cast<uint32_t>(
        IOsAccountIpcCode::
            COMMAND_CREATE_OS_ACCOUNT_FOR_DOMAIN_IN_INT_IN_DOMAINACCOUNTINFO_IN_IDOMAINACCOUNTCALLBACK),
};

std::string AnonymizeNameStr(const std::string& nameStr)
{
    if (nameStr.empty()) {
        return nameStr;
    }
    std::string retStr = nameStr.substr(0, INTERCEPT_HEAD_PART_LEN_FOR_NAME) + DEFAULT_ANON_STR;
    return retStr;
}

ErrCode CheckLocalId(int localId)
{
    if (localId < 0) {
        ACCOUNT_LOGE("Id %{public}d is invalid", localId);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    return ERR_OK;
}

bool IsTypeOutOfRange(const OsAccountType& type)
{
    if (type == OsAccountType::MAINTENANCE) {
#ifndef IS_RELEASE_VERSION
        // root check in none release version for test
        if (!AccountPermissionManager::CheckSaCall() && !AccountPermissionManager::CheckShellCall()) {
#else
        if (!AccountPermissionManager::CheckSaCall()) {
#endif
            return true;
        }
        return false;
    }
    if ((type < OsAccountType::ADMIN) || (type >= OsAccountType::END)) {
        return true;
    }
    if ((type > OsAccountType::GUEST) && (type < OsAccountType::PRIVATE)) {
        return true;
    }
    return false;
}

void WriteOsAccountInfo(StringRawData& stringRawData, const OsAccountInfo& osAccountInfo)
{
    std::string accountJson = osAccountInfo.ToString();
    stringRawData.Marshalling(accountJson);
}

bool WriteOsAccountInfoVector(StringRawData& stringRawData, const std::vector<OsAccountInfo>& osAccountInfos)
{
    auto accountJsons = CreateJsonArray();
    for (const auto& accountItem : osAccountInfos) {
        auto accountJson = ToJson(accountItem);
        if (accountJson != nullptr) {
            AddObjToArray(accountJsons, accountJson);
        }
    }
    std::string accountStr = PackJsonToString(accountJsons);
    if (accountStr.size() >= Constants::IPC_WRITE_RAW_DATA_MAX_SIZE) {
        ACCOUNT_LOGE("AccountArrayJson is too long");
        return false;
    }
    stringRawData.Marshalling(accountStr);
    return true;
}

ErrCode CheckOsAccountConstraint(const std::string &constraint)
{
    if (constraint.empty() || constraint.size() > Constants::CONSTRAINT_MAX_SIZE) {
        ACCOUNT_LOGE("Failed to read string for constraint, please check constraint length %{public}zu.",
            constraint.size());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    return ERR_OK;
}
}  // namespace

OsAccountManagerService::OsAccountManagerService() : innerManager_(IInnerOsAccountManager::GetInstance()),
    constraintManger_(OsAccountConstraintManager::GetInstance())
{}

OsAccountManagerService::~OsAccountManagerService()
{}

ErrCode OsAccountManagerService::CreateOsAccount(
    const std::string &name, const OsAccountType &type, OsAccountInfo &osAccountInfo)
{
    ErrCode errCode = ValidateAccountCreateParamAndPermission(name, type);
    if (errCode != ERR_OK) {
        return errCode;
    }
    return innerManager_.CreateOsAccount(name, type, osAccountInfo);
}

ErrCode OsAccountManagerService::CreateOsAccount(
    const std::string &name, int32_t typeValue, StringRawData& stringRawData)
{
    ErrCode result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", result);
        return result;
    }

    auto type = static_cast<OsAccountType>(typeValue);
    OsAccountInfo osAccountInfo;
    auto errCode = CreateOsAccount(name, type, osAccountInfo);
    if (errCode == ERR_OK) {
        WriteOsAccountInfo(stringRawData, osAccountInfo);
    }
    return errCode;
}

ErrCode OsAccountManagerService::ValidateShortName(const std::string &shortName)
{
    size_t shortNameSize = shortName.size();
    if (shortNameSize == 0 || shortNameSize > Constants::SHORT_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("CreateOsAccount short name length %{public}zu is invalid!", shortNameSize);
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    if (shortName.find_first_of(SPECIAL_CHARACTER_ARRAY) != std::string::npos) {
        ACCOUNT_LOGE("CreateOsAccount short name is invalidate, short name is %{public}s !", shortName.c_str());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    for (size_t i = 0; i < SHORT_NAME_CANNOT_BE_NAME_ARRAY.size(); i++) {
        if (shortName == SHORT_NAME_CANNOT_BE_NAME_ARRAY[i]) {
            ACCOUNT_LOGE("CreateOsAccount short name is invalidate, short name is %{public}s !", shortName.c_str());
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        }
    }
    return ERR_OK;
}

ErrCode OsAccountManagerService::CreateOsAccount(const std::string &localName, const std::string &shortName,
    const OsAccountType &type, OsAccountInfo &osAccountInfo, const CreateOsAccountOptions &options)
{
#ifdef ENABLE_ACCOUNT_SHORT_NAME
    OsAccountInfo accountInfoOld;
    ErrCode code = innerManager_.GetRealOsAccountInfoById(Constants::START_USER_ID, accountInfoOld);
    if (code != ERR_OK) {
        ACCOUNT_LOGE("QueryOsAccountById error, errCode %{public}d.", code);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    DomainAccountInfo domainAccountInfo;
    accountInfoOld.GetDomainInfo(domainAccountInfo);
    if (accountInfoOld.GetShortName().empty() && domainAccountInfo.accountName_.empty()) {
        if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
            ACCOUNT_LOGE("Account manager service, permission denied!");
            return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
        }
        accountInfoOld.SetType(type);
        accountInfoOld.SetLocalName(localName);
        accountInfoOld.SetShortName(shortName);
        code = innerManager_.UpdateFirstOsAccountInfo(accountInfoOld, osAccountInfo);
        return code;
    }
#endif // ENABLE_ACCOUNT_SHORT_NAME
    ErrCode errCode = ValidateAccountCreateParamAndPermission(localName, type);
    if (errCode != ERR_OK) {
        return errCode;
    }

    if (options.hasShortName) {
        errCode = ValidateShortName(shortName);
        if (errCode != ERR_OK) {
            return errCode;
        }
    }

    return innerManager_.CreateOsAccount(localName, shortName, type, osAccountInfo, options);
}

ErrCode OsAccountManagerService::CreateOsAccount(const std::string &localName, const std::string &shortName,
    int32_t typeValue, StringRawData& stringRawData)
{
    CreateOsAccountOptions options = {};
    return CreateOsAccount(localName, shortName, typeValue, stringRawData, options);
}

ErrCode OsAccountManagerService::CreateOsAccount(const std::string &localName, const std::string &shortName,
    int32_t typeValue, StringRawData& stringRawData, const CreateOsAccountOptions &options)
{
    ErrCode result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", result);
        return result;
    }

    auto type = static_cast<OsAccountType>(typeValue);
    OsAccountInfo osAccountInfo;
    auto errCode = CreateOsAccount(localName, shortName, type, osAccountInfo, options);
    if (errCode == ERR_OK) {
        WriteOsAccountInfo(stringRawData, osAccountInfo);
    }
    return errCode;
}

ErrCode OsAccountManagerService::ValidateAccountCreateParamAndPermission(const std::string &localName,
    const OsAccountType &type)
{
    // permission check
    if (!CheckCreateOsAccountWhiteList() &&
        (!PermissionCheck("", CONSTANT_CREATE_DIRECTLY) ||
        !PermissionCheck(MANAGE_LOCAL_ACCOUNTS, CONSTANT_CREATE))) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    bool isMultiOsAccountEnable = false;
    IsMultiOsAccountEnable(isMultiOsAccountEnable);
    if (!isMultiOsAccountEnable) {
        ACCOUNT_LOGE("System is not multi os account enable error");
        return ERR_OSACCOUNT_SERVICE_MANAGER_NOT_ENABLE_MULTI_ERROR;
    }

    size_t localNameSize = localName.size();
    if ((localNameSize == 0) || (localNameSize > Constants::LOCAL_NAME_MAX_SIZE)) {
        ACCOUNT_LOGE("CreateOsAccount local name length %{public}zu is invalid!", localNameSize);
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    if (IsTypeOutOfRange(type)) {
        ACCOUNT_LOGE("Os account type is invalid");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    bool isAllowedCreateAdmin = false;
    ErrCode errCode = innerManager_.IsAllowedCreateAdmin(isAllowedCreateAdmin);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Query allowed create admin error");
        return errCode;
    }
    if (!isAllowedCreateAdmin && type == OsAccountType::ADMIN) {
        ACCOUNT_LOGE("Cannot create admin account error");
        return ERR_OSACCOUNT_SERVICE_MANAGER_CREATE_OSACCOUNT_TYPE_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountManagerService::CreateOsAccountWithFullInfo(const OsAccountInfo& osAccountInfo)
{
    CreateOsAccountOptions options = {};
    return CreateOsAccountWithFullInfo(osAccountInfo, options);
}

ErrCode OsAccountManagerService::CreateOsAccountWithFullInfo(const OsAccountInfo& osAccountInfo,
    const CreateOsAccountOptions &options)
{
    ErrCode code = const_cast<OsAccountInfo *>(&osAccountInfo)->ParamCheck();
    if (code != ERR_OK) {
        ACCOUNT_LOGE("OsAccountInfo required field is invalidate, code = %{public}u.", code);
        return code;
    }
    ErrCode result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", result);
        return result;
    }

    bool isMultiOsAccountEnable = false;
    innerManager_.IsMultiOsAccountEnable(isMultiOsAccountEnable);
    if (!isMultiOsAccountEnable) {
        ACCOUNT_LOGE("System is not multi os account enable error");
        return ERR_OSACCOUNT_SERVICE_MANAGER_NOT_ENABLE_MULTI_ERROR;
    }

    if ((!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, CONSTANT_CREATE)) ||
        (!PermissionCheck("", CONSTANT_CREATE_DIRECTLY))) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    bool isAllowedCreateAdmin = false;
    ErrCode errCode = innerManager_.IsAllowedCreateAdmin(isAllowedCreateAdmin);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Query allowed create admin error");
        return errCode;
    }
    if (!isAllowedCreateAdmin && (osAccountInfo.GetType() == OsAccountType::ADMIN)) {
        ACCOUNT_LOGE("Cannot create admin account error");
        return ERR_OSACCOUNT_SERVICE_MANAGER_CREATE_OSACCOUNT_TYPE_ERROR;
    }

    auto convertOsAccountInfo = osAccountInfo;
    return innerManager_.CreateOsAccountWithFullInfo(convertOsAccountInfo, options);
}

ErrCode OsAccountManagerService::UpdateOsAccountWithFullInfo(const OsAccountInfo& osAccountInfo)
{
    ErrCode code = const_cast<OsAccountInfo *>(&osAccountInfo)->ParamCheck();
    if (code != ERR_OK) {
        ACCOUNT_LOGE("OsAccountInfo required field is invalidate, code = %{public}u.", code);
        return code;
    }
    ErrCode result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", result);
        return result;
    }

    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    bool isAllowedCreateAdmin = false;
    ErrCode errCode = innerManager_.IsAllowedCreateAdmin(isAllowedCreateAdmin);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Query allowed update admin error");
        return errCode;
    }
    if (!isAllowedCreateAdmin && osAccountInfo.GetType() == OsAccountType::ADMIN) {
        ACCOUNT_LOGE("Cannot update admin account error");
        return ERR_OSACCOUNT_SERVICE_MANAGER_CREATE_OSACCOUNT_TYPE_ERROR;
    }

    auto convertOsAccountInfo = osAccountInfo;
    return innerManager_.UpdateOsAccountWithFullInfo(convertOsAccountInfo);
}

ErrCode OsAccountManagerService::CreateOsAccountForDomain(const OsAccountType &type,
    const DomainAccountInfo &domainInfo, const sptr<IDomainAccountCallback> &callback,
    const CreateOsAccountForDomainOptions &options)
{
    ACCOUNT_LOGI("Start");
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, CONSTANT_CREATE)) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    // parameters check
    if (IsTypeOutOfRange(type)) {
        ACCOUNT_LOGE("Os account type is invalid");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (domainInfo.accountName_.empty() || domainInfo.domain_.empty()) {
        ACCOUNT_LOGE("Domain account name is empty or domain is empty");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (domainInfo.accountName_.size() > Constants::LOCAL_NAME_MAX_SIZE ||
        domainInfo.domain_.size() > Constants::DOMAIN_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("Domain account name is overlength or domain is overlength");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    if (options.hasShortName || (options.shortName != "")) {
        ErrCode code = ValidateShortName(options.shortName);
        if (code != ERR_OK) {
            ACCOUNT_LOGE("Failed to create os account for domain, shortName=%{public}s is invalid!",
                options.shortName.c_str());
            return code;
        }
    }

    bool isAllowedCreateAdmin = false;
    ErrCode errCode = innerManager_.IsAllowedCreateAdmin(isAllowedCreateAdmin);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to get allowed create admin permission, code=%{public}d.", errCode);
        return errCode;
    }
    if (!isAllowedCreateAdmin && type == OsAccountType::ADMIN) {
        ACCOUNT_LOGE("Do not allowed create admin.");
        return ERR_OSACCOUNT_SERVICE_MANAGER_CREATE_OSACCOUNT_TYPE_ERROR;
    }
    return innerManager_.CreateOsAccountForDomain(type, domainInfo, callback, options);
}

ErrCode OsAccountManagerService::CreateOsAccountForDomain(int32_t typeValue, const DomainAccountInfo &domainInfo,
    const sptr<IDomainAccountCallback> &callback)
{
    CreateOsAccountForDomainOptions options = {};
    return CreateOsAccountForDomain(typeValue, domainInfo, callback, options);
}

ErrCode OsAccountManagerService::CreateOsAccountForDomain(int32_t typeValue,
    const DomainAccountInfo &domainInfo, const sptr<IDomainAccountCallback> &callback,
    const CreateOsAccountForDomainOptions &options)
{
    ErrCode result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", result);
        return result;
    }
    auto type = static_cast<OsAccountType>(typeValue);
    return CreateOsAccountForDomain(type, domainInfo, callback, options);
}

ErrCode OsAccountManagerService::RemoveOsAccount(int32_t id)
{
    ErrCode result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", result);
        return result;
    }
    // parameters check
    ErrCode res = CheckLocalId(id);
    if (res != ERR_OK) {
        return res;
    }
    if (id == Constants::START_USER_ID) {
        ACCOUNT_LOGE("Cannot remove system preinstalled user");
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    res = CheckLocalIdRestricted(id);
    if (res != ERR_OK) {
        ACCOUNT_LOGW("Check local id restricted, result = %{public}d, localId = %{public}d.", res, id);
        return res;
    }
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, CONSTANT_REMOVE)) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.RemoveOsAccount(id);
}

ErrCode OsAccountManagerService::IsOsAccountExists(int32_t id, bool &isOsAccountExists)
{
    return innerManager_.IsOsAccountExists(id, isOsAccountExists);
}

ErrCode OsAccountManagerService::IsOsAccountActived(int32_t id, bool &isOsAccountActived)
{
    // check current account state
    int callerUserId = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    if (callerUserId == id) {
        return innerManager_.IsOsAccountActived(id, isOsAccountActived);
    }

    // check other account state, check permission first
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "") && !PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.IsOsAccountActived(id, isOsAccountActived);
}

ErrCode OsAccountManagerService::IsOsAccountConstraintEnable(
    int32_t id, const std::string &constraint, bool &isConstraintEnable)
{
    ErrCode res = CheckOsAccountConstraint(constraint);
    if (res != ERR_OK) {
        return res;
    }
    res = CheckLocalId(id);
    if (res != ERR_OK) {
        return res;
    }
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.IsOsAccountConstraintEnable(id, constraint, isConstraintEnable);
}

ErrCode OsAccountManagerService::CheckOsAccountConstraintEnabled(
    int32_t id, const std::string &constraint, bool &isEnabled)
{
    ErrCode res = CheckOsAccountConstraint(constraint);
    if (res != ERR_OK) {
        return res;
    }
    res = CheckLocalId(id);
    if (res != ERR_OK) {
        return res;
    }

    // check current account state
    int callerUserId = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    if (callerUserId == id) {
        return innerManager_.IsOsAccountConstraintEnable(id, constraint, isEnabled);
    }

    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "") && !PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.IsOsAccountConstraintEnable(id, constraint, isEnabled);
}

ErrCode OsAccountManagerService::IsOsAccountVerified(int32_t id, bool &isVerified)
{
    ErrCode res = CheckLocalId(id);
    if (res != ERR_OK) {
        return res;
    }
    // check current account state
    int callerUserId = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    if (callerUserId == id) {
        return innerManager_.IsOsAccountVerified(id, isVerified);
    }

    // check other account state, check permission first
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "") && !PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.IsOsAccountVerified(id, isVerified);
}

ErrCode OsAccountManagerService::IsOsAccountDeactivating(int32_t id, bool &isDeactivating)
{
    ErrCode res = CheckLocalId(id);
    if (res != ERR_OK) {
        return res;
    }
    // check current account state
    int callerUserId = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    if (callerUserId == id) {
        return innerManager_.IsOsAccountDeactivating(id, isDeactivating);
    }

    // check other account state, check permission first
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "") && !PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.IsOsAccountDeactivating(id, isDeactivating);
}

ErrCode OsAccountManagerService::GetCreatedOsAccountsCount(unsigned int &osAccountsCount)
{
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.GetCreatedOsAccountsCount(osAccountsCount);
}

ErrCode OsAccountManagerService::GetOsAccountLocalIdFromProcess(int &id)
{
#ifdef HICOLLIE_ENABLE
    unsigned int flag = HiviewDFX::XCOLLIE_FLAG_LOG | HiviewDFX::XCOLLIE_FLAG_RECOVERY;
    XCollieCallback callbackFunc = [callingPid = IPCSkeleton::GetCallingPid(),
        callingUid = IPCSkeleton::GetCallingUid()](void *) {
        ACCOUNT_LOGE("ProcGetOsAccountLocalIdFromProcess failed, callingPid: %{public}d, callingUid: %{public}d.",
            callingPid, callingUid);
        ReportOsAccountOperationFail(callingUid, "watchDog", -1, "Get osaccount local id time out");
    };
    int timerId = HiviewDFX::XCollie::GetInstance().SetTimer(
        TIMER_NAME, RECOVERY_TIMEOUT, callbackFunc, nullptr, flag);
#endif // HICOLLIE_ENABLE
    const std::int32_t uid = IPCSkeleton::GetCallingUid();
    id = uid / UID_TRANSFORM_DIVISOR;
#ifdef HICOLLIE_ENABLE
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
    return ERR_OK;
}

ErrCode OsAccountManagerService::IsMainOsAccount(bool &isMainOsAccount)
{
    ErrCode result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", result);
        return result;
    }
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGW("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    const std::int32_t uid = IPCSkeleton::GetCallingUid();
    isMainOsAccount = ((uid / UID_TRANSFORM_DIVISOR) == MAIN_OS_ACCOUNT_LOCAL_ID);
    return ERR_OK;
}

ErrCode OsAccountManagerService::GetOsAccountLocalIdFromDomain(const DomainAccountInfo &domainInfo, int &id)
{
    if (domainInfo.domain_.empty() || domainInfo.domain_.size() > Constants::DOMAIN_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("Domain name length invalid. length %{public}zu.", domainInfo.domain_.size());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    if (domainInfo.accountName_.empty() || domainInfo.accountName_.size() > Constants::LOCAL_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("AccountName length invalid. length %{public}zu.", domainInfo.accountName_.size());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.GetOsAccountLocalIdFromDomain(domainInfo, id);
}

ErrCode OsAccountManagerService::QueryMaxOsAccountNumber(uint32_t &maxOsAccountNumber)
{
    ErrCode result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", result);
        return result;
    }
    return innerManager_.QueryMaxOsAccountNumber(maxOsAccountNumber);
}

ErrCode OsAccountManagerService::QueryMaxLoggedInOsAccountNumber(uint32_t &maxNum)
{
    ErrCode result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", result);
        return result;
    }
    return innerManager_.QueryMaxLoggedInOsAccountNumber(maxNum);
}

ErrCode OsAccountManagerService::GetOsAccountAllConstraints(int32_t id, std::vector<std::string> &constraints)
{
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.GetOsAccountAllConstraints(id, constraints);
}

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
ErrCode OsAccountManagerService::QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos)
{
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    ErrCode result = innerManager_.QueryAllCreatedOsAccounts(osAccountInfos);
    if (result != ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(IPCSkeleton::GetCallingUid(), Constants::OPERATION_LOG_ERROR,
            result, "Query all created os account failed.");
        return result;
    }
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    for (auto& info : osAccountInfos) {
        result = GetServerConfigInfo(info);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("Failed to get domain server config, error=%{public}d", result);
            ReportOsAccountOperationFail(info.GetLocalId(), Constants::OPERATION_GET_INFO,
                result, "Failed to get domain server config");
            continue;
        }
    }
#endif // SUPPORT_DOMAIN_ACCOUNTS
    return ERR_OK;
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
ErrCode OsAccountManagerService::QueryAllCreatedOsAccounts(StringRawData& osAccountInfos)
{
    ErrCode checkResult = AccountPermissionManager::CheckSystemApp();
    if (checkResult != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", checkResult);
        return checkResult;
    }
    std::vector<OsAccountInfo> osAccountVec;
    ErrCode errCode = QueryAllCreatedOsAccounts(osAccountVec);
    if (errCode == ERR_OK && !WriteOsAccountInfoVector(osAccountInfos, osAccountVec)) {
        ACCOUNT_LOGE("WriteOsAccountInfoVector failed, please check osAccountInfos");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return errCode;
}

ErrCode OsAccountManagerService::QueryCurrentOsAccount(OsAccountInfo &osAccountInfo)
{
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "") && (!PermissionCheck(GET_LOCAL_ACCOUNTS, ""))) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    int id = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    ErrCode errCode = innerManager_.QueryOsAccountById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return errCode;
    }
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    errCode = GetServerConfigInfo(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to get domain server config, error=%{public}d", errCode);
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_GET_INFO,
            errCode, "Failed to get domain server config");
        return ERR_OK;
    }
#endif // SUPPORT_DOMAIN_ACCOUNTS
    return ERR_OK;
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

ErrCode OsAccountManagerService::QueryCurrentOsAccount(StringRawData& stringRawData)
{
    OsAccountInfo osAccountInfo;
    auto errCode = QueryCurrentOsAccount(osAccountInfo);
    if (errCode == ERR_OK) {
        WriteOsAccountInfo(stringRawData, osAccountInfo);
    }
    return errCode;
}

ErrCode OsAccountManagerService::QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo)
{
    // parameters check
    ErrCode res = CheckLocalId(id);
    if (res != ERR_OK) {
        return res;
    }
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "") &&
        !PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    ErrCode errCode = innerManager_.QueryOsAccountById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return errCode;
    }
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    errCode = GetServerConfigInfo(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to get domain server config, error=%{public}d", errCode);
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_GET_INFO,
            errCode, "Failed to get domain server config");
        return ERR_OK;
    }
#endif // SUPPORT_DOMAIN_ACCOUNTS
    return ERR_OK;
}

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
ErrCode OsAccountManagerService::QueryOsAccountById(int32_t id, StringRawData& stringRawData)
{
    ErrCode result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", result);
        return result;
    }
    OsAccountInfo osAccountInfo;
    auto errCode = QueryOsAccountById(id, osAccountInfo);
    if (errCode == ERR_OK) {
        WriteOsAccountInfo(stringRawData, osAccountInfo);
    }
    return errCode;
}

ErrCode OsAccountManagerService::GetOsAccountTypeFromProcess(int32_t& typeValue)
{
    int id = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    auto type = static_cast<OsAccountType>(typeValue);
    ErrCode result = innerManager_.GetOsAccountType(id, type);
    if (result == ERR_OK) {
        typeValue = static_cast<int32_t>(type);
    } else {
        REPORT_OS_ACCOUNT_FAIL(IPCSkeleton::GetCallingUid(), Constants::OPERATION_LOG_ERROR,
            result, "Query os account type failed.");
    }
    return result;
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

ErrCode OsAccountManagerService::GetOsAccountType(int32_t id, int32_t& typeValue)
{
    ErrCode result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", result);
        return result;
    }
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "") && !PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Check permission failed.");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    auto type = static_cast<OsAccountType>(typeValue);
    auto res = innerManager_.GetOsAccountType(id, type);
    typeValue = static_cast<int32_t>(type);
    return res;
}

ErrCode OsAccountManagerService::GetOsAccountProfilePhoto(const int id, std::string &photo)
{
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    // get current account photo
    int callerUserId = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    if (callerUserId == id) {
        return innerManager_.GetOsAccountProfilePhoto(id, photo);
    }

    // get other account photo, check permission first
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.GetOsAccountProfilePhoto(id, photo);
}

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
ErrCode OsAccountManagerService::GetOsAccountProfilePhoto(int32_t id, StringRawData& stringRawData)
{
    ErrCode checkResult = AccountPermissionManager::CheckSystemApp();
    if (checkResult != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", checkResult);
        return checkResult;
    }
    std::string photo;
    auto errCode = GetOsAccountProfilePhoto(id, photo);
    if (errCode == ERR_OK) {
        stringRawData.Marshalling(photo);
    }
    return errCode;
}

ErrCode OsAccountManagerService::IsMultiOsAccountEnable(bool &isMultiOsAccountEnable)
{
    return innerManager_.IsMultiOsAccountEnable(isMultiOsAccountEnable);
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

ErrCode OsAccountManagerService::SetOsAccountName(int32_t id, const std::string &name)
{
    ErrCode result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", result);
        return result;
    }
    // parameters check
    ErrCode res = CheckLocalId(id);
    if (res != ERR_OK) {
        return res;
    }
    res = CheckLocalIdRestricted(id);
    if (res != ERR_OK) {
        ACCOUNT_LOGW("Check local id restricted, result = %{public}d, localId = %{public}d.", res, id);
        return res;
    }
    if (name.size() > Constants::LOCAL_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("Set os account name is out of allowed size");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (name.size() <= 0) {
        ACCOUNT_LOGE("Os account name is empty");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.SetOsAccountName(id, name);
}

void OsAccountManagerService::ConstraintPublish(const std::vector<std::string> &oldConstraints,
    const std::vector<std::string> &constraints, int32_t localId, bool isEnabled)
{
    // Create a set to store constraints that need to be published
    std::set<std::string> constraintsSet;
    std::vector<std::string> newConstraints;
    ErrCode errCode = innerManager_.GetOsAccountAllConstraints(localId, newConstraints);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Call getOsAccountAllConstraints failed, errCode=%{public}d.", errCode);
        return;
    }
    // Iterate through each constraint in the new constraints list
    for (auto const &constraint : constraints) {
        // Check if the constraint is currently enabled for the account
        bool isEnabledNew =
            std::find(newConstraints.begin(), newConstraints.end(), constraint) != newConstraints.end();
        if (isEnabledNew != isEnabled) {
            ACCOUNT_LOGD("%{public}s not publish, enable=%{public}d.", constraint.c_str(), isEnabled);
            continue;
        }
        bool isEnabledOld = std::find(oldConstraints.begin(), oldConstraints.end(), constraint) != oldConstraints.end();
        if (isEnabledOld != isEnabledNew) {
            constraintsSet.emplace(constraint);
        }
    }
    // Publish the final set of constraints with the specified enable state
    return constraintManger_.Publish(localId, constraintsSet, isEnabled);
}

ErrCode OsAccountManagerService::SetOsAccountConstraints(
    int32_t id, const std::vector<std::string> &constraints, bool enable)
{
    ErrCode result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", result);
        return result;
    }
    ErrCode res = CheckLocalId(id);
    if (res != ERR_OK) {
        return res;
    }
    res = CheckLocalIdRestricted(id);
    if (res != ERR_OK) {
        ACCOUNT_LOGW("Check local id restricted, result = %{public}d, localId = %{public}d.", res, id);
        return res;
    }
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    std::vector<std::string> oldConstraints;
    result = innerManager_.GetOsAccountAllConstraints(id, oldConstraints);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("GetOsAccountAllConstraints failed, result=%{public}d", result);
        return result;
    }
    result = innerManager_.SetBaseOsAccountConstraints(id, constraints, enable);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SetBaseOsAccountConstraints failed, result=%{public}d", result);
        return result;
    }
    ConstraintPublish(oldConstraints, constraints, id, enable);
    return result;
}

ErrCode OsAccountManagerService::SetOsAccountProfilePhoto(const int id, const std::string &photo)
{
    // parameters check
    ErrCode res = CheckLocalId(id);
    if (res != ERR_OK) {
        return res;
    }
    res = CheckLocalIdRestricted(id);
    if (res != ERR_OK) {
        ACCOUNT_LOGW("Check local id restricted, result = %{public}d, localId = %{public}d.", res, id);
        return res;
    }
    if (photo.size() > Constants::LOCAL_PHOTO_MAX_SIZE) {
        ACCOUNT_LOGE("Photo out of allowed size");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (photo.empty()) {
        ACCOUNT_LOGE("Photo is empty");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, CONSTANT_SET_ICON)) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.SetOsAccountProfilePhoto(id, photo);
}

ErrCode OsAccountManagerService::SetOsAccountProfilePhoto(int32_t id, const StringRawData& stringRawData)
{
    ErrCode result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", result);
        return result;
    }
    std::string photo;
    stringRawData.Unmarshalling(photo);
    return SetOsAccountProfilePhoto(id, photo);
}

ErrCode OsAccountManagerService::ActivateOsAccount(int32_t id)
{
    return ActivateOsAccountCommon(id, Constants::DEFAULT_DISPLAY_ID);
}

ErrCode OsAccountManagerService::ActivateOsAccount(int32_t id, const uint64_t displayId)
{
    return ActivateOsAccountCommon(id, displayId);
}

ErrCode OsAccountManagerService::ActivateOsAccountCommon(int32_t id, const uint64_t displayId)
{
    ErrCode result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", result);
        return result;
    }
    StartTraceAdapter("AccountManager ActivateAccount");
    // parameters check
    ErrCode res = CheckLocalId(id);
    if (res != ERR_OK) {
        FinishTraceAdapter();
        return res;
    }
    res = CheckLocalIdRestricted(id);
    if (res != ERR_OK) {
        ACCOUNT_LOGW("Check local id restricted, result = %{public}d, localId = %{public}d.", res, id);
        FinishTraceAdapter();
        return res;
    }
    // permission check
    if (!PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, CONSTANT_ACTIVATE)) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        FinishTraceAdapter();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    res = innerManager_.ActivateOsAccount(id, true, displayId);
    FinishTraceAdapter();
    return res;
}

ErrCode OsAccountManagerService::DeactivateOsAccount(int32_t id)
{
    ErrCode result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", result);
        return result;
    }
    // parameters check
    ErrCode res = CheckLocalId(id);
    if (res != ERR_OK) {
        return res;
    }
    res = CheckLocalIdRestricted(id);
    if (res != ERR_OK) {
        ACCOUNT_LOGW("Check local id restricted, result = %{public}d, localId = %{public}d.", res, id);
        return res;
    }
    // permission check
    if (!PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    int32_t currentId = Constants::START_USER_ID;
    GetCurrentLocalId(currentId);

#ifndef SUPPORT_STOP_MAIN_OS_ACCOUNT
    if (id == Constants::START_USER_ID) {
        ACCOUNT_LOGW("The %{public}d os account can't stop", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_STOP_ACTIVE_ERROR;
    }
#endif // SUPPORT_STOP_OS_ACCOUNT

    res = innerManager_.DeactivateOsAccount(id);

    if (currentId == id) { // if stop current account
#ifndef ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
#ifdef SUPPORT_STOP_MAIN_OS_ACCOUNT
        innerManager_.ActivateOsAccount(id, false, Constants::DEFAULT_DISPLAY_ID, true);
#else
        innerManager_.ActivateOsAccount(Constants::START_USER_ID, false, Constants::DEFAULT_DISPLAY_ID);
#endif // SUPPORT_STOP_MAIN_OS_ACCOUNT
#endif // ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
    }
    return res;
}

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
ErrCode OsAccountManagerService::DeactivateAllOsAccounts()
{
    ErrCode checkResult = AccountPermissionManager::CheckSystemApp();
    if (checkResult != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", checkResult);
        return checkResult;
    }
    // permission check
    if (!PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, "")) {
        ACCOUNT_LOGE("Permission check failed.");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    std::vector<int32_t> userIds;
    ErrCode res = innerManager_.QueryActiveOsAccountIds(userIds);
    if (res != ERR_OK) {
        ACCOUNT_LOGE("Get activated os account ids failed.");
        return res;
    }
    if (userIds.empty()) {
        ACCOUNT_LOGI("Activated os account list is empty.");
        return ERR_OK;
    }
    ErrCode result = ERR_OK;
    for (auto osAccountId : userIds) {
        ACCOUNT_LOGI("DeactivateAllOsAccounts, id=%{public}d", osAccountId);
#ifdef ENABLE_U1_ACCOUNT
        if (osAccountId == Constants::U1_ID) {
            continue;
        }
#endif // ENABLE_U1_ACCOUNT
        res = innerManager_.DeactivateOsAccount(osAccountId);
        if (res != ERR_OK) {
            ACCOUNT_LOGE("Deactivate os account id failed, id=%{public}d", osAccountId);
            result = res;
        }
    }
    return result;
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
void OsAccountManagerService::GetCurrentLocalId(int32_t &userId)
{
    std::vector<int32_t> userIds;
    if ((innerManager_.QueryActiveOsAccountIds(userIds) != ERR_OK) || userIds.empty()) {
        ACCOUNT_LOGE("Fail to get activated os account ids");
        return;
    }
    userId = userIds[0];
    return;
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

ErrCode OsAccountManagerService::StartOsAccount(int32_t id)
{
    return innerManager_.StartOsAccount(id);
}

ErrCode OsAccountManagerService::SubscribeOsAccount(
    const OsAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener)
{
#ifdef HICOLLIE_ENABLE
    unsigned int flag = HiviewDFX::XCOLLIE_FLAG_LOG | HiviewDFX::XCOLLIE_FLAG_RECOVERY;
    XCollieCallback callbackFunc = [callingPid = IPCSkeleton::GetCallingPid(),
        callingUid = IPCSkeleton::GetCallingUid()](void *) {
        ACCOUNT_LOGE("ProcSubscribeOsAccount failed, callingPid: %{public}d, callingUid: %{public}d.",
            callingPid, callingUid);
        ReportOsAccountOperationFail(callingUid, "watchDog", -1, "Subscribe osaccount time out");
    };
    int timerId = HiviewDFX::XCollie::GetInstance().SetTimer(TIMER_NAME, RECOVERY_TIMEOUT, callbackFunc, nullptr, flag);
#endif // HICOLLIE_ENABLE
    ErrCode checkResult = AccountPermissionManager::CheckSystemApp();
    if (checkResult != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", checkResult);
#ifdef HICOLLIE_ENABLE
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
        return checkResult;
    }

    // permission check
    OS_ACCOUNT_SUBSCRIBE_TYPE osAccountSubscribeType;
    subscribeInfo.GetOsAccountSubscribeType(osAccountSubscribeType);
    std::set<OsAccountState> states;
    subscribeInfo.GetStates(states);
    if (osAccountSubscribeType == OsAccountState::INVALID_TYPE && states.empty()) {
        ACCOUNT_LOGE("Invalid subscriber information");
#ifdef HICOLLIE_ENABLE
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    // permission check
    if (!(PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "") ||
          PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, "") ||
          PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS, ""))) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
#ifdef HICOLLIE_ENABLE
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    ErrCode result = innerManager_.SubscribeOsAccount(subscribeInfo, eventListener);
    if (result != ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(IPCSkeleton::GetCallingUid(), Constants::OPERATION_LOG_ERROR,
            result, "Subscribe os account failed.");
    }
#ifdef HICOLLIE_ENABLE
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
    return result;
}

ErrCode OsAccountManagerService::UnsubscribeOsAccount(const sptr<IRemoteObject> &eventListener)
{
    ErrCode checkResult = AccountPermissionManager::CheckSystemApp();
    if (checkResult != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", checkResult);
        return checkResult;
    }

    // permission check
    if (!(PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "") ||
          PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, "") ||
          PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS, ""))) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    ErrCode result =  innerManager_.UnsubscribeOsAccount(eventListener);
    if (result != ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(IPCSkeleton::GetCallingUid(), Constants::OPERATION_LOG_ERROR,
            result, "Unsubscribe os account failed.");
    }
    return result;
}

ErrCode OsAccountManagerService::GetOsAccountLocalIdBySerialNumber(const int64_t serialNumber, int &id)
{
    return innerManager_.GetOsAccountLocalIdBySerialNumber(serialNumber, id);
}

ErrCode OsAccountManagerService::GetSerialNumberByOsAccountLocalId(int32_t id, int64_t &serialNumber)
{
    return innerManager_.GetSerialNumberByOsAccountLocalId(id, serialNumber);
}

ErrCode OsAccountManagerService::GetOsAccountSwitchMod(int32_t &switchMod)
{
    switchMod = static_cast<int32_t>(innerManager_.GetOsAccountSwitchMod());
    return ERR_OK;
}

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
ErrCode OsAccountManagerService::IsCurrentOsAccountVerified(bool &isVerified)
{
    int id = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    return innerManager_.IsOsAccountVerified(id, isVerified);
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

ErrCode OsAccountManagerService::IsOsAccountCompleted(int32_t id, bool &isOsAccountCompleted)
{
    ErrCode result = innerManager_.IsOsAccountCompleted(id, isOsAccountCompleted);
    if (result != ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(IPCSkeleton::GetCallingUid(), Constants::OPERATION_LOG_ERROR,
            result, "Get os account completed failed.");
    }
    return result;
}

ErrCode OsAccountManagerService::SetCurrentOsAccountIsVerified(bool isVerified)
{
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    // parameters check
    int id = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    ErrCode res = CheckLocalId(id);
    if (res != ERR_OK) {
        return res;
    }
    res = CheckLocalIdRestricted(id);
    if (res != ERR_OK) {
        ACCOUNT_LOGW("Check local id restricted, result = %{public}d, localId = %{public}d.", res, id);
        return res;
    }
    return innerManager_.SetOsAccountIsVerified(id, isVerified);
}

ErrCode OsAccountManagerService::SetOsAccountIsVerified(int32_t id, bool isVerified)
{
    // parameters check
    ErrCode res = CheckLocalId(id);
    if (res != ERR_OK) {
        return res;
    }
    res = CheckLocalIdRestricted(id);
    if (res != ERR_OK) {
        ACCOUNT_LOGW("Check local id restricted, result = %{public}d, localId = %{public}d.", res, id);
        return res;
    }
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.SetOsAccountIsVerified(id, isVerified);
}

ErrCode OsAccountManagerService::DumpState(int32_t id, std::vector<std::string> &state)
{
    state.clear();

    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    ErrCode result = ERR_OK;
    std::vector<OsAccountInfo> osAccountInfos;

    if (id == -1) {
        result = innerManager_.QueryAllCreatedOsAccounts(osAccountInfos);
        if (result != ERR_OK) {
            return result;
        }
#ifdef ENABLE_U1_ACCOUNT
        OsAccountInfo osAccountInfo;
        result = innerManager_.GetRealOsAccountInfoById(Constants::U1_ID, osAccountInfo);
        if (result == ERR_OK) {
            osAccountInfos.insert(osAccountInfos.begin(), osAccountInfo);
        }
#endif // ENABLE_U1_ACCOUNT
    } else {
        OsAccountInfo osAccountInfo;
        result = innerManager_.GetRealOsAccountInfoById(id, osAccountInfo);
        if (result != ERR_OK) {
            return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
        }

        osAccountInfos.emplace_back(osAccountInfo);
    }

    return DumpStateByAccounts(osAccountInfos, state);
}

ErrCode OsAccountManagerService::DumpOsAccountInfo(std::vector<std::string> &state)
{
    state.clear();

    ErrCode result = ERR_OK;
    std::vector<OsAccountInfo> osAccountInfos;
    result = innerManager_.QueryAllCreatedOsAccounts(osAccountInfos);
    if (result != ERR_OK) {
        return result;
    }

    return DumpStateByAccounts(osAccountInfos, state);
}

ErrCode OsAccountManagerService::GetCreatedOsAccountNumFromDatabase(const std::string& storeID,
    int &createdOsAccountNum)
{
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.GetCreatedOsAccountNumFromDatabase(storeID, createdOsAccountNum);
}

ErrCode OsAccountManagerService::GetSerialNumberFromDatabase(const std::string& storeID,
    int64_t &serialNumber)
{
    return innerManager_.GetSerialNumberFromDatabase(storeID, serialNumber);
}

ErrCode OsAccountManagerService::GetMaxAllowCreateIdFromDatabase(const std::string& storeID, int &id)
{
    return innerManager_.GetMaxAllowCreateIdFromDatabase(storeID, id);
}

ErrCode OsAccountManagerService::GetOsAccountFromDatabase(const std::string& storeID,
    const int id, OsAccountInfo &osAccountInfo)
{
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    ErrCode errCode = innerManager_.GetOsAccountFromDatabase(storeID, id, osAccountInfo);
    if (errCode != ERR_OK) {
        return errCode;
    }
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    errCode = GetServerConfigInfo(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to get domain server config, error=%{public}d", errCode);
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_GET_INFO,
            errCode, "Failed to get domain server config");
        return ERR_OK;
    }
#endif
    return ERR_OK;
}

ErrCode OsAccountManagerService::GetOsAccountFromDatabase(const std::string& storeID,
    int32_t id, StringRawData& stringRawData)
{
    OsAccountInfo osAccountInfo;
    auto errCode = GetOsAccountFromDatabase(storeID, id, osAccountInfo);
    if (errCode == ERR_OK) {
        WriteOsAccountInfo(stringRawData, osAccountInfo);
    }
    return errCode;
}

ErrCode OsAccountManagerService::GetOsAccountListFromDatabase(const std::string& storeID,
    std::vector<OsAccountInfo> &osAccountList)
{
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    ErrCode errCode = innerManager_.GetOsAccountListFromDatabase(storeID, osAccountList);
    if (errCode != ERR_OK) {
        return errCode;
    }
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    for (auto &info : osAccountList) {
        errCode = GetServerConfigInfo(info);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("Failed to get domain server config, error=%{public}d", errCode);
            ReportOsAccountOperationFail(info.GetLocalId(), Constants::OPERATION_GET_INFO,
                errCode, "Failed to get domain server config");
            continue;
        }
    }
#endif
    return ERR_OK;
}

ErrCode OsAccountManagerService::GetOsAccountListFromDatabase(const std::string& storeID,
    StringRawData& osAccountInfos)
{
    std::vector<OsAccountInfo> osAccountVec;
    auto errCode = GetOsAccountListFromDatabase(storeID, osAccountVec);
    if (errCode == ERR_OK && !WriteOsAccountInfoVector(osAccountInfos, osAccountVec)) {
        ACCOUNT_LOGE("WriteOsAccountInfoVector failed, please check osAccountInfos");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return errCode;
}

ErrCode OsAccountManagerService::DumpStateByAccounts(
    const std::vector<OsAccountInfo> &osAccountInfos, std::vector<std::string> &state)
{
    ACCOUNT_LOGD("Enter");
    for (auto osAccountInfo : osAccountInfos) {
        std::string info = "";

        std::string localId = std::to_string(osAccountInfo.GetLocalId());
        state.emplace_back("ID: " + localId);

        std::string localName = osAccountInfo.GetLocalName();
        state.emplace_back(DUMP_TAB_CHARACTER + "Name: " + AnonymizeNameStr(localName));

        std::string type = "";
        auto it = DUMP_TYPE_MAP.find(osAccountInfo.GetType());
        if (it != DUMP_TYPE_MAP.end()) {
            type = it->second;
        } else {
            type = "unknown";
        }
        state.emplace_back(DUMP_TAB_CHARACTER + "Type: " + type);
        state.emplace_back(DUMP_TAB_CHARACTER + "Status: " +
            (osAccountInfo.GetIsActived() ? "active" : "inactive"));
        state.emplace_back(DUMP_TAB_CHARACTER + "isForeground: " + std::to_string(osAccountInfo.GetIsForeground()));
        state.emplace_back(DUMP_TAB_CHARACTER + "dispalyId: " + std::to_string(osAccountInfo.GetDisplayId()));

        state.emplace_back(DUMP_TAB_CHARACTER + "Constraints:");
        auto constraints = osAccountInfo.GetConstraints();
        std::transform(constraints.begin(), constraints.end(), std::back_inserter(state),
            [](auto constraint) {return DUMP_TAB_CHARACTER + DUMP_TAB_CHARACTER + constraint; });

        state.emplace_back(DUMP_TAB_CHARACTER + "Verified: " +
            (osAccountInfo.GetIsVerified() ? "true" : "false"));

        int64_t serialNumber = osAccountInfo.GetSerialNumber();
        state.emplace_back(DUMP_TAB_CHARACTER + "Serial Number: " + std::to_string(serialNumber));
        state.emplace_back(DUMP_TAB_CHARACTER + "Create Completed: " +
            (osAccountInfo.GetIsCreateCompleted() ? "true" : "false"));
        state.emplace_back(DUMP_TAB_CHARACTER + "To Be Removed: " +
            (osAccountInfo.GetToBeRemoved() ? "true" : "false"));
        state.emplace_back("\n");
    }

    return ERR_OK;
}

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
ErrCode OsAccountManagerService::QueryActiveOsAccountIds(std::vector<int32_t>& ids)
{
#ifdef HICOLLIE_ENABLE
    unsigned int flag = HiviewDFX::XCOLLIE_FLAG_LOG | HiviewDFX::XCOLLIE_FLAG_RECOVERY;
    XCollieCallback callbackFunc = [callingPid = IPCSkeleton::GetCallingPid(),
        callingUid = IPCSkeleton::GetCallingUid()](void *) {
        ACCOUNT_LOGE("ProcQueryActiveOsAccountIds failed, callingPid: %{public}d, callingUid: %{public}d.",
            callingPid, callingUid);
        ReportOsAccountOperationFail(callingUid, "watchDog", -1, "Query active account id time out");
    };
    int timerId = HiviewDFX::XCollie::GetInstance().SetTimer(
        TIMER_NAME, RECOVERY_TIMEOUT, callbackFunc, nullptr, flag);
#endif // HICOLLIE_ENABLE
    ErrCode result = innerManager_.QueryActiveOsAccountIds(ids);
    if (result != ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(IPCSkeleton::GetCallingUid(), Constants::OPERATION_LOG_ERROR,
            result, "Query active os accountIds failed.");
    }
#ifdef HICOLLIE_ENABLE
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
    return result;
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

ErrCode OsAccountManagerService::GetUnlockedOsAccountLocalIds(std::vector<int32_t>& ids)
{
    return innerManager_.GetUnlockedOsAccountLocalIds(ids);
}

ErrCode OsAccountManagerService::QueryOsAccountConstraintSourceTypes(int32_t id,
    const std::string &constraint, std::vector<ConstraintSourceTypeInfo> &constraintSourceTypeInfos)
{
    ErrCode result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", result);
        return result;
    }
    // parameters check
    ErrCode res = CheckLocalId(id);
    if (res != ERR_OK) {
        return res;
    }
    if (constraint.empty() || constraint.size() > Constants::CONSTRAINT_MAX_SIZE) {
        ACCOUNT_LOGE("Constraint length is invalid. length %{public}zu.", constraint.size());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.QueryOsAccountConstraintSourceTypes(id, constraint, constraintSourceTypeInfos);
}

ErrCode OsAccountManagerService::SetGlobalOsAccountConstraints(const std::vector<std::string> &constraints,
    bool enable, int32_t enforcerId, bool isDeviceOwner)
{
    if (enforcerId < 0) {
        ACCOUNT_LOGE("Failed to read localId, please check enforcerId");
        return ERR_OSACCOUNT_KIT_READ_IN_LOCAL_ID_ERROR;
    }
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "") || !PermissionCheck(MANAGE_EDM_POLICY, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    std::vector<OsAccountInfo> osAccountInfos;
    ErrCode result = innerManager_.QueryAllCreatedOsAccounts(osAccountInfos);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("QueryAllCreatedOsAccounts failed, result=%{public}d", result);
        return result;
    }
    std::map<int32_t, std::vector<std::string>> oldConstraintsMap;
    for (auto const&info : osAccountInfos) {
        std::vector<std::string> oldConstraints;
        result = innerManager_.GetOsAccountAllConstraints(info.GetLocalId(), oldConstraints);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("GetOsAccountAllConstraints failed, result=%{public}d", result);
            return result;
        }
        oldConstraintsMap.emplace(info.GetLocalId(), oldConstraints);
    }

    result = innerManager_.SetGlobalOsAccountConstraints(constraints, enable, enforcerId, isDeviceOwner);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SetGlobalOsAccountConstraints failed, result=%{public}d", result);
        return result;
    }
    for (const auto& item : oldConstraintsMap) {
        ConstraintPublish(item.second, constraints, item.first, enable);
    }
    return result;
}

ErrCode OsAccountManagerService::SetSpecificOsAccountConstraints(const std::vector<std::string> &constraints,
    bool enable, int32_t targetId, int32_t enforcerId, bool isDeviceOwner)
{
    if (targetId < 0) {
        ACCOUNT_LOGE("Failed to read targetId, please check targetId");
        return ERR_OSACCOUNT_KIT_READ_IN_LOCAL_ID_ERROR;
    }
    if (enforcerId < 0) {
        ACCOUNT_LOGE("Failed to read enforcerId, please check enforcerId");
        return ERR_OSACCOUNT_KIT_READ_IN_LOCAL_ID_ERROR;
    }
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "") || !PermissionCheck(MANAGE_EDM_POLICY, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    // parameters check
    if (targetId < Constants::START_USER_ID || enforcerId < Constants::START_USER_ID) {
        ACCOUNT_LOGE("Invalid input account id %{public}d or %{public}d.", targetId, enforcerId);
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    std::vector<std::string> oldConstraints;
    ErrCode result = innerManager_.GetOsAccountAllConstraints(targetId, oldConstraints);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("GetOsAccountAllConstraints failed, result=%{public}d", result);
        return result;
    }
    result = innerManager_.SetSpecificOsAccountConstraints(
        constraints, enable, targetId, enforcerId, isDeviceOwner);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SetSpecificOsAccountConstraints failed, result=%{public}d", result);
        return result;
    }
    ConstraintPublish(oldConstraints, constraints, targetId, enable);
    return result;
}

ErrCode OsAccountManagerService::SubscribeOsAccountConstraints(const OsAccountConstraintSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &eventListener)
{
    // permission check
    if (!PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
#ifdef HICOLLIE_ENABLE
    unsigned int flag = HiviewDFX::XCOLLIE_FLAG_LOG;
    XCollieCallback callbackFunc = [callingPid = IPCSkeleton::GetCallingPid(),
        callingUid = IPCSkeleton::GetCallingUid()](void *) {
        ACCOUNT_LOGE("SubscribeOsAccountConstraints failed, callingPid: %{public}d, callingUid: %{public}d.",
            callingPid, callingUid);
        ReportOsAccountOperationFail(callingUid, "watchDog", -1, "Subscribe constraint time out");
    };
    int timerId = HiviewDFX::XCollie::GetInstance().SetTimer(
        TIMER_NAME, TIMEOUT, callbackFunc, nullptr, flag);
#endif // HICOLLIE_ENABLE
    ErrCode result = constraintManger_.SubscribeOsAccountConstraints(subscribeInfo, eventListener);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Subscribe constraint failed, callingUid: %{public}d, code: %{public}d.",
            IPCSkeleton::GetCallingUid(), result);
        REPORT_OS_ACCOUNT_FAIL(IPCSkeleton::GetCallingUid(), Constants::OPERATION_LOG_ERROR,
            result, "Subscribe constraint failed.");
    }
#ifdef HICOLLIE_ENABLE
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
    return result;
}

ErrCode OsAccountManagerService::UnsubscribeOsAccountConstraints(const OsAccountConstraintSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &eventListener)
{
    // permission check
    if (!PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    ErrCode result = constraintManger_.UnsubscribeOsAccountConstraints(subscribeInfo, eventListener);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Unsubscribe constraint failed, callingUid: %{public}d, code: %{public}d.",
            IPCSkeleton::GetCallingUid(), result);
        REPORT_OS_ACCOUNT_FAIL(IPCSkeleton::GetCallingUid(), Constants::OPERATION_LOG_ERROR,
            result, "Unsubscribe constraint failed.");
    }
    return result;
}

ErrCode OsAccountManagerService::SetDefaultActivatedOsAccount(int32_t id)
{
    // parameters check
    ErrCode ret = CheckLocalId(id);
    if (ret != ERR_OK) {
        return ret;
    }

    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    if (id < Constants::START_USER_ID) {
        ACCOUNT_LOGE("Not allow set id:%{public}d default activated account!", id);
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    return innerManager_.SetDefaultActivatedOsAccount(id);
}

ErrCode OsAccountManagerService::SetDefaultActivatedOsAccount(const uint64_t displayId, const int32_t id)
{
    // parameters check
    ErrCode ret = CheckLocalId(id);
    if (ret != ERR_OK) {
        return ret;
    }

    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    return innerManager_.SetDefaultActivatedOsAccount(displayId, id);
}

ErrCode OsAccountManagerService::GetDefaultActivatedOsAccount(int32_t &id)
{
    return innerManager_.GetDefaultActivatedOsAccount(id);
}

ErrCode OsAccountManagerService::GetDefaultActivatedOsAccount(const uint64_t displayId, int32_t &id)
{
    return innerManager_.GetDefaultActivatedOsAccount(displayId, id);
}

ErrCode OsAccountManagerService::GetAllDefaultActivatedOsAccounts(std::map<uint64_t, int32_t> &activatedIds)
{
    return innerManager_.GetAllDefaultActivatedOsAccounts(activatedIds);
}

ErrCode OsAccountManagerService::GetOsAccountShortNameCommon(const int32_t id, std::string &shortName)
{
    ErrCode errCode = innerManager_.GetOsAccountShortName(id, shortName);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetOsAccountShortName error %{public}d", errCode);
        return errCode;
    }
    return ERR_OK;
}

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
ErrCode OsAccountManagerService::GetOsAccountShortName(std::string &shortName)
{
    ErrCode result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", result);
        return result;
    }
    int32_t id = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    return GetOsAccountShortNameCommon(id, shortName);
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
ErrCode OsAccountManagerService::GetOsAccountName(std::string &name)
{
    int32_t id = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    ErrCode errCode = innerManager_.GetOsAccountName(id, name);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed get account name, errCode=%{public}d, uid=%{public}d", errCode,
            IPCSkeleton::GetCallingUid());
        return errCode;
    }
    return ERR_OK;
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

ErrCode OsAccountManagerService::GetOsAccountNameById(int32_t id, std::string &name)
{
    ErrCode result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", result);
        return result;
    }
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "") && !PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Check permission failed.");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    ErrCode errCode = innerManager_.GetOsAccountName(id, name);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed get account name, errCode=%{public}d, id=%{public}d", errCode, id);
        return errCode;
    }
    return ERR_OK;
}

ErrCode OsAccountManagerService::GetOsAccountShortNameById(int32_t id, std::string &shortName)
{
    ErrCode result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", result);
        return result;
    }
    if (!PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Check permission failed, please check your permission.");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    return GetOsAccountShortNameCommon(id, shortName);
}

bool OsAccountManagerService::PermissionCheck(const std::string& permissionName, const std::string& constraintName)
{
    int callerUid = IPCSkeleton::GetCallingUid();
#ifndef IS_RELEASE_VERSION
    // root check in none release version for test
    if (callerUid == ROOT_UID) {
        return true;
    }
#endif

    // constraints check
    if (!constraintName.empty()) {
        int callerUserId = callerUid / UID_TRANSFORM_DIVISOR;
        bool isEnable = true;
        innerManager_.IsOsAccountConstraintEnable(callerUserId, constraintName, isEnable);
        if (isEnable) {
            ACCOUNT_LOGE("Constraint check %{public}s failed.", constraintName.c_str());
            ReportPermissionFail(callerUid, IPCSkeleton::GetCallingRealPid(), constraintName);
            return false;
        }
    }

    // permission check
    if ((permissionName.empty()) || (AccountPermissionManager::VerifyPermission(permissionName) == ERR_OK)) {
        return true;
    }

    return false;
}

bool OsAccountManagerService::CheckCreateOsAccountWhiteList()
{
    return uidWhiteListForCreation.find(GetCallingUid()) != uidWhiteListForCreation.end();
}

ErrCode OsAccountManagerService::IsOsAccountForeground(int32_t localId, const uint64_t displayId,
                                                       bool &isForeground)
{
    ErrCode checkResult = AccountPermissionManager::CheckSystemApp();
    if (checkResult != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", checkResult);
        return checkResult;
    }
    int32_t callerId = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    int32_t id = (localId == -1) ? callerId : localId;
    if (id < Constants::ADMIN_LOCAL_ID) {
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    bool isOsAccountExists = false;
    ErrCode result = IsOsAccountExists(id, isOsAccountExists);
    if (result != ERR_OK) {
        return result;
    }
    if (!isOsAccountExists) {
        ACCOUNT_LOGE("LocalId %{public}d not exist.", id);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    if (id >= Constants::ADMIN_LOCAL_ID && id < Constants::START_USER_ID) {
        ACCOUNT_LOGI("LocalId %{public}d is always in backgroud.", id);
        isForeground = false;
        return ERR_OK;
    }
    return innerManager_.IsOsAccountForeground(id, displayId, isForeground);
}

ErrCode OsAccountManagerService::GetForegroundOsAccountLocalId(int32_t &localId)
{
    return innerManager_.GetForegroundOsAccountLocalId(Constants::DEFAULT_DISPLAY_ID, localId);
}


ErrCode OsAccountManagerService::GetForegroundOsAccountLocalId(const uint64_t displayId, int32_t &localId)
{
    // permission check
    if (!PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    return innerManager_.GetForegroundOsAccountLocalId(displayId, localId);
}

ErrCode OsAccountManagerService::GetForegroundOsAccountDisplayId(const int32_t localId, uint64_t &displayId)
{
    // permission check
    if (!PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    int32_t id = (localId == -1) ? (IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR) : localId;
    if (id < Constants::ADMIN_LOCAL_ID) {
        ACCOUNT_LOGE("LocalId %{public}d is invalid.", id);
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    bool isOsAccountExists = false;
    ErrCode result = IsOsAccountExists(id, isOsAccountExists);
    if (result != ERR_OK) {
        return result;
    }
    if (!isOsAccountExists) {
        ACCOUNT_LOGE("LocalId %{public}d not exist.", id);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    return innerManager_.GetForegroundOsAccountDisplayId(localId, displayId);
}

ErrCode OsAccountManagerService::GetForegroundOsAccounts(std::vector<ForegroundOsAccount> &accounts)
{
    ErrCode checkResult = AccountPermissionManager::CheckSystemApp();
    if (checkResult != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", checkResult);
        return checkResult;
    }
    ErrCode result = innerManager_.GetForegroundOsAccounts(accounts);
    if (result != ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(IPCSkeleton::GetCallingUid(), Constants::OPERATION_LOG_ERROR,
            result, "Get foreground os accounts failed.");
    }
    return result;
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
ErrCode OsAccountManagerService::GetBackgroundOsAccountLocalIds(std::vector<int32_t> &localIds)
{
    return innerManager_.GetBackgroundOsAccountLocalIds(localIds);
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

ErrCode OsAccountManagerService::SetOsAccountToBeRemoved(int32_t localId, bool toBeRemoved)
{
    ErrCode result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Is not system application, result = %{public}u.", result);
        return result;
    }
    ErrCode res = CheckLocalId(localId);
    if (res != ERR_OK) {
        return res;
    }
    if (localId == Constants::START_USER_ID) {
        ACCOUNT_LOGE("Cannot remove system preinstalled user.");
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    res = CheckLocalIdRestricted(localId);
    if (res != ERR_OK) {
        ACCOUNT_LOGW("Check local id restricted, result = %{public}d, localId = %{public}d.", res, localId);
        return res;
    }
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Permission denied.");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    return innerManager_.SetOsAccountToBeRemoved(localId, toBeRemoved);
}

ErrCode OsAccountManagerService::GetOsAccountDomainInfo(int32_t localId, DomainAccountInfo &domainInfo)
{
    if (!(PermissionCheck(GET_DOMAIN_ACCOUNTS, "") &&
        PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS, ""))) {
        ACCOUNT_LOGE("Permission denied.");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    ErrCode res = CheckLocalId(localId);
    if (res != ERR_OK) {
        return res;
    }
    return innerManager_.GetOsAccountDomainInfo(localId, domainInfo);
}

#ifdef SUPPORT_LOCK_OS_ACCOUNT
ErrCode OsAccountManagerService::PublishOsAccountLockEvent(const int32_t localId, bool isLocking)
{
    ErrCode result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("CheckSystemApp failed, please check permission, result = %{public}u.", result);
        return result;
    }
    ErrCode res = CheckLocalId(localId);
    if (res != ERR_OK) {
        return res;
    }

    if (localId < Constants::START_USER_ID) {
        ACCOUNT_LOGE("Not allow to lock account id:%{public}d!", localId);
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }

    if (!PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, "")) {
        ACCOUNT_LOGE("Permission denied.");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.PublishOsAccountLockEvent(localId, isLocking);
}

ErrCode OsAccountManagerService::LockOsAccount(const int32_t localId)
{
    ErrCode result = AccountPermissionManager::CheckSystemApp();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("CheckSystemApp failed, please check permission, result = %{public}u.", result);
        return result;
    }
    ErrCode res = CheckLocalId(localId);
    if (res != ERR_OK) {
        return res;
    }

    if (localId < Constants::START_USER_ID) {
        ACCOUNT_LOGE("Not allow to lock account id:%{public}d!", localId);
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }

    if (!PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, "")) {
        ACCOUNT_LOGE("Permission denied.");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.LockOsAccount(localId);
}
#endif

ErrCode OsAccountManagerService::BindDomainAccount(
    const int32_t localId, const DomainAccountInfo &domainInfo, const sptr<IDomainAccountCallback> &callback)
{
    ErrCode res = AccountPermissionManager::CheckSystemApp();
    if (res != ERR_OK) {
        ACCOUNT_LOGE("Caller is not system application, result = %{public}d.", res);
        return res;
    }
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Permission denied.");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    res = CheckLocalId(localId);
    if (res != ERR_OK) {
        return res;
    }
    res = CheckLocalIdRestricted(localId);
    if (res != ERR_OK) {
        ACCOUNT_LOGW("Check local id restricted, result = %{public}d, localId = %{public}d.", res, localId);
        return res;
    }
    if (domainInfo.accountName_.empty() || domainInfo.domain_.empty()) {
        ACCOUNT_LOGE("Domain account name is empty or domain is empty");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (domainInfo.accountName_.size() > Constants::LOCAL_NAME_MAX_SIZE ||
        domainInfo.domain_.size() > Constants::DOMAIN_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("Domain account name is overlength or domain is overlength");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (callback == nullptr) {
        ACCOUNT_LOGE("Callback is null");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    auto work = [localId = localId, domainInfo = domainInfo, callback] {
        ErrCode res = InnerDomainAccountManager::GetInstance().BindDomainAccount(localId, domainInfo, callback);
        if (res != ERR_OK) {
            ACCOUNT_LOGE("Bind domain account failed, res = %{public}d.", res);
        }
    };
    std::thread taskThread(work);
    pthread_setname_np(taskThread.native_handle(), "BindDomainAccount");
    taskThread.detach();
    return ERR_OK;
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

ErrCode OsAccountManagerService::CheckLocalIdRestricted(int32_t localId)
{
    if (localId == Constants::ADMIN_LOCAL_ID) {
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    if (localId >= Constants::START_USER_ID) {
        return ERR_OK;
    }
    bool hasAccount = false;
    ErrCode ret = innerManager_.IsOsAccountExists(localId, hasAccount);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Is OsAccount Exists failed, ret = %{public}d, localId = %{public}d", ret, localId);
        return ret;
    }
    if (hasAccount) {
        ACCOUNT_LOGW("Os account exists, return restricted account, localId = %{public}d", localId);
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    ACCOUNT_LOGW("Os account not exists, return account not found, localId = %{public}d", localId);
    return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
}

ErrCode OsAccountManagerService::CallbackEnter([[maybe_unused]] uint32_t code)
{
#ifdef HICOLLIE_ENABLE
    if (WATCH_DOG_WHITE_LIST.find(code) == WATCH_DOG_WHITE_LIST.end()) {
        g_timerIdStack.push(HiviewDFX::XCollie::GetInstance().SetTimer(TIMER_NAME, TIMEOUT,
            nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG));
    }
#endif // HICOLLIE_ENABLE
    return ERR_OK;
}

ErrCode OsAccountManagerService::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
#ifdef HICOLLIE_ENABLE
    if (WATCH_DOG_WHITE_LIST.find(code) != WATCH_DOG_WHITE_LIST.end()) {
        return ERR_OK;
    }
    if (!g_timerIdStack.empty()) {
        HiviewDFX::XCollie::GetInstance().CancelTimer(g_timerIdStack.top());
        g_timerIdStack.pop();
    }
#endif // HICOLLIE_ENABLE
    return ERR_OK;
}

#ifdef SUPPORT_DOMAIN_ACCOUNTS
ErrCode OsAccountManagerService::GetServerConfigInfo(OsAccountInfo &osAccountInfo)
{
    if (!osAccountInfo.GetIsCreateCompleted() || osAccountInfo.GetToBeRemoved()) {
        return ERR_OK;
    }
    DomainAccountInfo info;
    osAccountInfo.GetDomainInfo(info);
    if (info.accountName_.empty() || info.serverConfigId_.empty()) {
        return ERR_OK;
    }
    DomainServerConfig config;
    ErrCode errCode = InnerDomainAccountManager::GetInstance().GetAccountServerConfig(info.accountName_,
        info.serverConfigId_, config);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetAccountServerConfig failed, errCode=%{public}d", errCode);
        return errCode;
    }
    info.domain_ = config.domain_;
    info.serverConfigId_ = config.id_;
    osAccountInfo.SetDomainInfo(info);
    return ERR_OK;
}
#endif
}  // namespace AccountSA
}  // namespace OHOS
