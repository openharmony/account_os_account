/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include "account_constants.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "account_hisysevent_adapter.h"
#include "iinner_os_account_manager.h"
#include "ipc_skeleton.h"
#include "os_account_constants.h"

namespace OHOS {
namespace AccountSA {
namespace {
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
const std::set<uint32_t> uidWhiteListForCreation { 3057 };
const std::int32_t EDM_UID = 3057;
const std::string SPECIAL_CHARACTER_ARRAY = "<>|\":*?/\\";
const std::vector<std::string> SHORT_NAME_CANNOT_BE_NAME_ARRAY = {".", ".."};

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
}  // namespace

OsAccountManagerService::OsAccountManagerService() : innerManager_(IInnerOsAccountManager::GetInstance())
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

ErrCode OsAccountManagerService::ValidateAccountCreateParamAndPermission(const std::string &localName,
    const OsAccountType &type)
{
    // permission check
    if (!CheckCreateOsAccountWhiteList() &&
        (!PermissionCheck("", CONSTANT_CREATE_DIRECTLY) ||
        !PermissionCheck(MANAGE_LOCAL_ACCOUNTS, CONSTANT_CREATE))) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
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

ErrCode OsAccountManagerService::CreateOsAccountWithFullInfo(OsAccountInfo &osAccountInfo,
    const CreateOsAccountOptions &options)
{
    bool isMultiOsAccountEnable = false;
    innerManager_.IsMultiOsAccountEnable(isMultiOsAccountEnable);
    if (!isMultiOsAccountEnable) {
        ACCOUNT_LOGE("System is not multi os account enable error");
        return ERR_OSACCOUNT_SERVICE_MANAGER_NOT_ENABLE_MULTI_ERROR;
    }

    if ((!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, CONSTANT_CREATE)) ||
        (!PermissionCheck("", CONSTANT_CREATE_DIRECTLY))) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
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

    return innerManager_.CreateOsAccountWithFullInfo(osAccountInfo, options);
}

ErrCode OsAccountManagerService::UpdateOsAccountWithFullInfo(OsAccountInfo &osAccountInfo)
{
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
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

    return innerManager_.UpdateOsAccountWithFullInfo(osAccountInfo);
}

ErrCode OsAccountManagerService::CreateOsAccountForDomain(const OsAccountType &type,
    const DomainAccountInfo &domainInfo, const sptr<IDomainAccountCallback> &callback,
    const CreateOsAccountForDomainOptions &options)
{
    ACCOUNT_LOGI("Start");
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, CONSTANT_CREATE)) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
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

ErrCode OsAccountManagerService::RemoveOsAccount(const int id)
{
    // parameters check
    ErrCode res = CheckLocalId(id);
    if (res != ERR_OK) {
        return res;
    }
    if ((id == Constants::START_USER_ID) || (id == Constants::ADMIN_LOCAL_ID)) {
        ACCOUNT_LOGE("Cannot remove system preinstalled user");
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, CONSTANT_REMOVE)) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.RemoveOsAccount(id);
}

ErrCode OsAccountManagerService::IsOsAccountExists(const int id, bool &isOsAccountExists)
{
    ErrCode result = innerManager_.IsOsAccountExists(id, isOsAccountExists);
    if (result == ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(IPCSkeleton::GetCallingUid(), Constants::OPERATION_LOG_ERROR,
            result, "Failed to query os account exists, id=" + std::to_string(id));
    }
    return result;
}

ErrCode OsAccountManagerService::IsOsAccountActived(const int id, bool &isOsAccountActived)
{
    // check current account state
    int callerUserId = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    if (callerUserId == id) {
        return innerManager_.IsOsAccountActived(id, isOsAccountActived);
    }

    // check other account state, check permission first
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "") && !PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.IsOsAccountActived(id, isOsAccountActived);
}

ErrCode OsAccountManagerService::IsOsAccountConstraintEnable(
    const int id, const std::string &constraint, bool &isConstraintEnable)
{
    ErrCode res = CheckLocalId(id);
    if (res != ERR_OK) {
        return res;
    }
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.IsOsAccountConstraintEnable(id, constraint, isConstraintEnable);
}

ErrCode OsAccountManagerService::CheckOsAccountConstraintEnabled(
    const int id, const std::string &constraint, bool &isEnabled)
{
    ErrCode res = CheckLocalId(id);
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
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.IsOsAccountConstraintEnable(id, constraint, isEnabled);
}

ErrCode OsAccountManagerService::IsOsAccountVerified(const int id, bool &isVerified)
{
    ErrCode res = CheckLocalId(id);
    if (res != ERR_OK) {
        return res;
    }
    // check current account state
    int callerUserId = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    if (callerUserId == id) {
        ErrCode result = innerManager_.IsOsAccountVerified(id, isVerified);
        if (result != ERR_OK) {
            REPORT_OS_ACCOUNT_FAIL(IPCSkeleton::GetCallingUid(), Constants::OPERATION_LOG_ERROR,
                result, "Is os account verified failed.");
        }
        return result;
    }

    // check other account state, check permission first
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "") && !PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    ErrCode result = innerManager_.IsOsAccountVerified(id, isVerified);
    if (result != ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(IPCSkeleton::GetCallingUid(), Constants::OPERATION_LOG_ERROR,
            result, "Is os account verified failed.");
    }
    return result;
}

ErrCode OsAccountManagerService::IsOsAccountDeactivating(const int id, bool &isDeactivating)
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
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.IsOsAccountDeactivating(id, isDeactivating);
}

ErrCode OsAccountManagerService::GetCreatedOsAccountsCount(unsigned int &osAccountsCount)
{
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.GetCreatedOsAccountsCount(osAccountsCount);
}

ErrCode OsAccountManagerService::GetOsAccountLocalIdFromProcess(int &id)
{
    const std::int32_t uid = IPCSkeleton::GetCallingUid();
    id = uid / UID_TRANSFORM_DIVISOR;
    return ERR_OK;
}

ErrCode OsAccountManagerService::IsMainOsAccount(bool &isMainOsAccount)
{
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGW("Account manager service, permission denied!");
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
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.GetOsAccountLocalIdFromDomain(domainInfo, id);
}

ErrCode OsAccountManagerService::QueryMaxOsAccountNumber(uint32_t &maxOsAccountNumber)
{
    return innerManager_.QueryMaxOsAccountNumber(maxOsAccountNumber);
}

ErrCode OsAccountManagerService::QueryMaxLoggedInOsAccountNumber(uint32_t &maxNum)
{
    return innerManager_.QueryMaxLoggedInOsAccountNumber(maxNum);
}

ErrCode OsAccountManagerService::GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints)
{
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.GetOsAccountAllConstraints(id, constraints);
}

ErrCode OsAccountManagerService::QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos)
{
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    ErrCode result = innerManager_.QueryAllCreatedOsAccounts(osAccountInfos);
    if (result != ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(IPCSkeleton::GetCallingUid(), Constants::OPERATION_LOG_ERROR,
            result, "Query all created os account failed.");
    }
    return result;
}

ErrCode OsAccountManagerService::QueryCurrentOsAccount(OsAccountInfo &osAccountInfo)
{
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "") && (!PermissionCheck(GET_LOCAL_ACCOUNTS, ""))) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    int id = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    return innerManager_.QueryOsAccountById(id, osAccountInfo);
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
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.QueryOsAccountById(id, osAccountInfo);
}

ErrCode OsAccountManagerService::GetOsAccountTypeFromProcess(OsAccountType &type)
{
    int id = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    ErrCode result = innerManager_.GetOsAccountType(id, type);
    if (result != ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(IPCSkeleton::GetCallingUid(), Constants::OPERATION_LOG_ERROR,
            result, "Query os account type failed.");
    }
    return result;
}

ErrCode OsAccountManagerService::GetOsAccountType(const int id, OsAccountType& type)
{
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "") && !PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Check permission failed.");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    return innerManager_.GetOsAccountType(id, type);
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
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.GetOsAccountProfilePhoto(id, photo);
}

ErrCode OsAccountManagerService::IsMultiOsAccountEnable(bool &isMultiOsAccountEnable)
{
    return innerManager_.IsMultiOsAccountEnable(isMultiOsAccountEnable);
}

ErrCode OsAccountManagerService::SetOsAccountName(const int id, const std::string &name)
{
    // parameters check
    ErrCode res = CheckLocalId(id);
    if (res != ERR_OK) {
        return res;
    }
    if (id == Constants::ADMIN_LOCAL_ID) {
        ACCOUNT_LOGE("Cannot set name for system preinstalled user");
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
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
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.SetOsAccountName(id, name);
}

ErrCode OsAccountManagerService::SetOsAccountConstraints(
    const int id, const std::vector<std::string> &constraints, const bool enable)
{
    ErrCode res = CheckLocalId(id);
    if (res != ERR_OK) {
        return res;
    }
    if (id == Constants::ADMIN_LOCAL_ID) {
        ACCOUNT_LOGE("Cannot set constraints for system preinstalled user");
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.SetBaseOsAccountConstraints(id, constraints, enable);
}

ErrCode OsAccountManagerService::SetOsAccountProfilePhoto(const int id, const std::string &photo)
{
    // parameters check
    ErrCode res = CheckLocalId(id);
    if (res != ERR_OK) {
        return res;
    }
    if (id == Constants::ADMIN_LOCAL_ID) {
        ACCOUNT_LOGE("Cannot set photo for system preinstalled user");
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
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
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.SetOsAccountProfilePhoto(id, photo);
}

ErrCode OsAccountManagerService::ActivateOsAccount(const int id)
{
    // parameters check
    ErrCode res = CheckLocalId(id);
    if (res != ERR_OK) {
        return res;
    }
    if (id == Constants::ADMIN_LOCAL_ID) {
        ACCOUNT_LOGE("Cannot activate name for system preinstalled user");
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    // permission check
    if (!PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, CONSTANT_ACTIVATE)) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.ActivateOsAccount(id);
}

ErrCode OsAccountManagerService::DeactivateOsAccount(const int id)
{
    // parameters check
    ErrCode res = CheckLocalId(id);
    if (res != ERR_OK) {
        return res;
    }
    if (id == Constants::ADMIN_LOCAL_ID) {
        ACCOUNT_LOGE("Cannot deactivate name for system preinstalled user");
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    // permission check
    if (!PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
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
#ifdef SUPPORT_STOP_MAIN_OS_ACCOUNT
        innerManager_.ActivateOsAccount(id, false, Constants::DEFAULT_DISPALY_ID, true);
#else
        innerManager_.ActivateOsAccount(Constants::START_USER_ID, false, Constants::DEFAULT_DISPALY_ID);
#endif // SUPPORT_STOP_MAIN_OS_ACCOUNT
    }
    return res;
}

ErrCode OsAccountManagerService::DeactivateAllOsAccounts()
{
    // permission check
    if (!PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, "")) {
        ACCOUNT_LOGE("Permission check failed.");
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
        res = innerManager_.DeactivateOsAccount(osAccountId);
        if (res != ERR_OK) {
            ACCOUNT_LOGE("Deactivate os account id failed, id=%{public}d", osAccountId);
            result = res;
        }
    }
    return result;
}

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

ErrCode OsAccountManagerService::StartOsAccount(const int id)
{
    return innerManager_.StartOsAccount(id);
}

ErrCode OsAccountManagerService::SubscribeOsAccount(
    const OsAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener)
{
    // permission check
    OS_ACCOUNT_SUBSCRIBE_TYPE osAccountSubscribeType;
    subscribeInfo.GetOsAccountSubscribeType(osAccountSubscribeType);
    std::set<OsAccountState> states;
    subscribeInfo.GetStates(states);
    if (osAccountSubscribeType == OsAccountState::INVALID_TYPE && states.empty()) {
        ACCOUNT_LOGE("Invalid subscriber information");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    // permission check
    if (!(PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "") ||
          PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, "") ||
          (AccountPermissionManager::CheckSaCall() && PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS, "")))) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    ErrCode result = innerManager_.SubscribeOsAccount(subscribeInfo, eventListener);
    if (result != ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(IPCSkeleton::GetCallingUid(), Constants::OPERATION_LOG_ERROR,
            result, "Subscribe os account failed.");
    }
    return result;
}

ErrCode OsAccountManagerService::UnsubscribeOsAccount(const sptr<IRemoteObject> &eventListener)
{
    // permission check
    if (!(PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "") ||
          PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, "") ||
          (AccountPermissionManager::CheckSaCall() && PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS, "")))) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
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

ErrCode OsAccountManagerService::GetSerialNumberByOsAccountLocalId(const int &id, int64_t &serialNumber)
{
    return innerManager_.GetSerialNumberByOsAccountLocalId(id, serialNumber);
}

OS_ACCOUNT_SWITCH_MOD OsAccountManagerService::GetOsAccountSwitchMod()
{
    return innerManager_.GetOsAccountSwitchMod();
}

ErrCode OsAccountManagerService::IsCurrentOsAccountVerified(bool &isVerified)
{
    int id = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    return innerManager_.IsOsAccountVerified(id, isVerified);
}

ErrCode OsAccountManagerService::IsOsAccountCompleted(const int id, bool &isOsAccountCompleted)
{
    ErrCode result = innerManager_.IsOsAccountCompleted(id, isOsAccountCompleted);
    if (result != ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(IPCSkeleton::GetCallingUid(), Constants::OPERATION_LOG_ERROR,
            result, "Get os account completed failed.");
    }
    return result;
}

ErrCode OsAccountManagerService::SetCurrentOsAccountIsVerified(const bool isVerified)
{
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    // parameters check
    int id = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    ErrCode res = CheckLocalId(id);
    if (res != ERR_OK) {
        return res;
    }
    if (id == Constants::ADMIN_LOCAL_ID) {
        ACCOUNT_LOGE("Cannot set verified status for system preinstalled user");
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    return innerManager_.SetOsAccountIsVerified(id, isVerified);
}

ErrCode OsAccountManagerService::SetOsAccountIsVerified(const int id, const bool isVerified)
{
    // parameters check
    ErrCode res = CheckLocalId(id);
    if (res != ERR_OK) {
        return res;
    }
    if (id == Constants::ADMIN_LOCAL_ID) {
        ACCOUNT_LOGE("Cannot set verified status for system preinstalled user");
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.SetOsAccountIsVerified(id, isVerified);
}

ErrCode OsAccountManagerService::DumpState(const int &id, std::vector<std::string> &state)
{
    state.clear();

    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    ErrCode result = ERR_OK;
    std::vector<OsAccountInfo> osAccountInfos;

    if (id == -1) {
        result = innerManager_.QueryAllCreatedOsAccounts(osAccountInfos);
        if (result != ERR_OK) {
            return result;
        }
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
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.GetOsAccountFromDatabase(storeID, id, osAccountInfo);
}

ErrCode OsAccountManagerService::GetOsAccountListFromDatabase(const std::string& storeID,
    std::vector<OsAccountInfo> &osAccountList)
{
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.GetOsAccountListFromDatabase(storeID, osAccountList);
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

ErrCode OsAccountManagerService::QueryActiveOsAccountIds(std::vector<int32_t>& ids)
{
    ErrCode result = innerManager_.QueryActiveOsAccountIds(ids);
    if (result != ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(IPCSkeleton::GetCallingUid(), Constants::OPERATION_LOG_ERROR,
            result, "Query active os accountIds failed.");
    }
    return result;
}

ErrCode OsAccountManagerService::QueryOsAccountConstraintSourceTypes(const int32_t id,
    const std::string &constraint, std::vector<ConstraintSourceTypeInfo> &constraintSourceTypeInfos)
{
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
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.QueryOsAccountConstraintSourceTypes(id, constraint, constraintSourceTypeInfos);
}

ErrCode OsAccountManagerService::SetGlobalOsAccountConstraints(const std::vector<std::string> &constraints,
    const bool enable, const int32_t enforcerId, const bool isDeviceOwner)
{
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.SetGlobalOsAccountConstraints(constraints, enable, enforcerId, isDeviceOwner);
}

static bool ContainsAnyConstraint(const std::vector<std::string> &constraints,
    const std::vector<std::string> &constraintList)
{
    for (const auto &constraint : constraintList) {
        if (std::find(constraints.begin(), constraints.end(), constraint) != constraints.end()) {
            return true;
        }
    }
    return false;
}

ErrCode OsAccountManagerService::SetSpecificOsAccountConstraints(const std::vector<std::string> &constraints,
    const bool enable, const int32_t targetId, const int32_t enforcerId, const bool isDeviceOwner)
{
    // check EDM uid
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    std::vector<std::string> createConstraintList = {CONSTANT_CREATE, CONSTANT_CREATE_DIRECTLY};
    if (ContainsAnyConstraint(constraints, createConstraintList) && callingUid != EDM_UID) {
        ACCOUNT_LOGE("Permission denied, callingUid=%{public}d.", callingUid);
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    // parameters check
    if (targetId < Constants::START_USER_ID || enforcerId < Constants::START_USER_ID) {
        ACCOUNT_LOGE("Invalid input account id %{public}d or %{public}d.", targetId, enforcerId);
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }

    return innerManager_.SetSpecificOsAccountConstraints(constraints, enable, targetId, enforcerId, isDeviceOwner);
}

ErrCode OsAccountManagerService::SetDefaultActivatedOsAccount(const int32_t id)
{
    // parameters check
    ErrCode ret = CheckLocalId(id);
    if (ret != ERR_OK) {
        return ret;
    }

    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.SetDefaultActivatedOsAccount(id);
}

ErrCode OsAccountManagerService::GetDefaultActivatedOsAccount(int32_t &id)
{
    return innerManager_.GetDefaultActivatedOsAccount(id);
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

ErrCode OsAccountManagerService::GetOsAccountShortName(std::string &shortName)
{
    int32_t id = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    return GetOsAccountShortNameCommon(id, shortName);
}

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

ErrCode OsAccountManagerService::GetOsAccountNameById(int32_t id, std::string &name)
{
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "") && !PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Check permission failed.");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    ErrCode errCode = innerManager_.GetOsAccountName(id, name);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed get account name, errCode=%{public}d, id=%{public}d", errCode, id);
        return errCode;
    }
    return ERR_OK;
}

ErrCode OsAccountManagerService::GetOsAccountShortNameById(const int32_t id, std::string &shortName)
{
    if (!PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Check permission failed, please check your permission.");
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

    ReportPermissionFail(callerUid, IPCSkeleton::GetCallingRealPid(), permissionName);
    return false;
}

bool OsAccountManagerService::CheckCreateOsAccountWhiteList()
{
    return uidWhiteListForCreation.find(GetCallingUid()) != uidWhiteListForCreation.end();
}

ErrCode OsAccountManagerService::IsOsAccountForeground(const int32_t localId, const uint64_t displayId,
                                                       bool &isForeground)
{
    int32_t callerId = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    int32_t id = (localId == -1) ? callerId : localId;
    if (id < Constants::ADMIN_LOCAL_ID) {
        ACCOUNT_LOGE("LocalId %{public}d is invlaid.", id);
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (displayId != Constants::DEFAULT_DISPALY_ID) {
        ACCOUNT_LOGE("DisplayId %{public}llu not exist.", static_cast<unsigned long long>(displayId));
        return ERR_ACCOUNT_COMMON_DISPLAY_ID_NOT_EXIST_ERROR;
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

ErrCode OsAccountManagerService::GetForegroundOsAccountLocalId(const uint64_t displayId, int32_t &localId)
{
    if (displayId != Constants::DEFAULT_DISPALY_ID) {
        ACCOUNT_LOGE("DisplayId %{public}llu not exist.", static_cast<unsigned long long>(displayId));
        return ERR_ACCOUNT_COMMON_DISPLAY_ID_NOT_EXIST_ERROR;
    }
    ErrCode result = innerManager_.GetForegroundOsAccountLocalId(displayId, localId);
    if (result != ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(IPCSkeleton::GetCallingUid(), Constants::OPERATION_LOG_ERROR,
            result, "Get foreground os account local id failed, displayid=" + std::to_string(displayId));
    }
    return result;
}

ErrCode OsAccountManagerService::GetForegroundOsAccounts(std::vector<ForegroundOsAccount> &accounts)
{
    ErrCode result = innerManager_.GetForegroundOsAccounts(accounts);
    if (result != ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(IPCSkeleton::GetCallingUid(), Constants::OPERATION_LOG_ERROR,
            result, "Get foreground os accounts failed.");
    }
    return result;
}

ErrCode OsAccountManagerService::GetBackgroundOsAccountLocalIds(std::vector<int32_t> &localIds)
{
    return innerManager_.GetBackgroundOsAccountLocalIds(localIds);
}

ErrCode OsAccountManagerService::SetOsAccountToBeRemoved(int32_t localId, bool toBeRemoved)
{
    ErrCode res = CheckLocalId(localId);
    if (res != ERR_OK) {
        return res;
    }
    if ((localId == Constants::START_USER_ID) || (localId == Constants::ADMIN_LOCAL_ID)) {
        ACCOUNT_LOGE("Cannot remove system preinstalled user.");
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("Permission denied.");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    return innerManager_.SetOsAccountToBeRemoved(localId, toBeRemoved);
}

ErrCode OsAccountManagerService::GetOsAccountDomainInfo(const int32_t localId, DomainAccountInfo &domainInfo)
{
    if (!(PermissionCheck(GET_DOMAIN_ACCOUNTS, "") &&
        PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS, ""))) {
        ACCOUNT_LOGE("Permission denied.");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    ErrCode res = CheckLocalId(localId);
    if (res != ERR_OK) {
        return res;
    }
    return innerManager_.GetOsAccountDomainInfo(localId, domainInfo);
}
}  // namespace AccountSA
}  // namespace OHOS
