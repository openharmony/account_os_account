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
#include "os_account_manager_service.h"
#include <algorithm>
#include <cstddef>
#include "account_info.h"
#include "account_log_wrapper.h"
#include "hisysevent_adapter.h"
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
};
const std::string CONSTANT_CREATE = "constraint.os.account.create";
const std::string CONSTANT_CREATE_DIRECTLY = "constraint.os.account.create.directly";
const std::string CONSTANT_REMOVE = "constraint.os.account.remove";
const std::string CONSTANT_START = "constraint.os.account.start";
const std::string CONSTANT_SET_ICON = "constraint.os.account.set.icon";
const std::int32_t ROOT_UID = 0;
const std::string DEFAULT_ANON_STR = "**********";
const size_t INTERCEPT_HEAD_PART_LEN_FOR_NAME = 1;

const std::string MANAGE_LOCAL_ACCOUNTS = "ohos.permission.MANAGE_LOCAL_ACCOUNTS";
const std::string GET_LOCAL_ACCOUNTS = "ohos.permission.GET_LOCAL_ACCOUNTS";
const std::string INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION =
    "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION";
const std::string INTERACT_ACROSS_LOCAL_ACCOUNTS = "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS";
const std::set<uint32_t> uidWhiteListForCreation { 3057 };

std::string AnonymizeNameStr(const std::string& nameStr)
{
    if (nameStr.empty()) {
        return nameStr;
    }
    std::string retStr = nameStr.substr(0, INTERCEPT_HEAD_PART_LEN_FOR_NAME) + DEFAULT_ANON_STR;
    return retStr;
}

ErrCode CheckInvalidLocalId(int localId)
{
    if (localId > Constants::MAX_USER_ID) {
        ACCOUNT_LOGE("id %{public}d is out of range", localId);
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    return ERR_OK;
}

ErrCode CheckLocalId(int localId)
{
    if (localId < Constants::START_USER_ID) {
        ACCOUNT_LOGE("id %{public}d is system reserved", localId);
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    return CheckInvalidLocalId(localId);
}
}  // namespace

OsAccountManagerService::OsAccountManagerService() : innerManager_(IInnerOsAccountManager::GetInstance())
{}

OsAccountManagerService::~OsAccountManagerService()
{}

ErrCode OsAccountManagerService::CreateOsAccount(
    const std::string &name, const OsAccountType &type, OsAccountInfo &osAccountInfo)
{
    // parameters check
    size_t localNameSize = name.size();
    if (localNameSize == 0 || localNameSize > Constants::LOCAL_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("CreateOsAccount local name length %{public}zu is invalid!", localNameSize);
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    std::string shortName;
#ifdef ENABLE_USER_SHORT_NAME
    shortName = name;
    for (size_t i = 0; i < strlen(Constants::SPECIAL_CHARACTER_ARRAY); i++) {
        int position = shortName.find(Constants::SPECIAL_CHARACTER_ARRAY[i]);
        while (position > 0) {
            shortName = shortName.erase(position, 1);
            position = shortName.find(Constants::SPECIAL_CHARACTER_ARRAY[i]);
        }
    }

    if (shortName.size() > Constants::SHORT_NAME_MAX_SIZE) {
        shortName = shortName.substr(0, Constants::SHORT_NAME_MAX_SIZE);
    }

    for (size_t i = 0; i < sizeof(Constants::SHORT_NAME_CANNOT_BE_NAME_ARRAY); i++) {
        if (shortName.compare(Constants::SHORT_NAME_CANNOT_BE_NAME_ARRAY[i]) == 0) {
            shortName = Constants::STANDARD_LOCAL_NAME + std::to_string(i);
            break;
        }
    }
#endif // ENABLE_USER_SHORT_NAME
    return CreateOsAccount(name, shortName, type, osAccountInfo);
}

ErrCode OsAccountManagerService::CreateOsAccount(
    const std::string &localName, const std::string &shortName, const OsAccountType &type, OsAccountInfo &osAccountInfo)
{
    bool isMultiOsAccountEnable = false;
    innerManager_.IsMultiOsAccountEnable(isMultiOsAccountEnable);
    if (!isMultiOsAccountEnable) {
        ACCOUNT_LOGE("system is not multi os account enable error");
        return ERR_OSACCOUNT_SERVICE_MANAGER_NOT_ENABLE_MULTI_ERROR;
    }

    // permission check
    if (!CheckCreateOsAccountWhiteList() &&
        (!PermissionCheck("", CONSTANT_CREATE_DIRECTLY) || !PermissionCheck(MANAGE_LOCAL_ACCOUNTS, CONSTANT_CREATE))) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    size_t localNameSize = localName.size();
    if (localNameSize == 0 || localNameSize > Constants::LOCAL_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("CreateOsAccount local name length %{public}zu is invalid!", localNameSize);
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
#ifdef ENABLE_USER_SHORT_NAME
    ErrCode code = ValidateShortName(shortName);
    if (code != ERR_OK) {
        return code;
    }
#endif // ENABLE_USER_SHORT_NAME
    if (type < OsAccountType::ADMIN || type >= OsAccountType::END) {
        ACCOUNT_LOGE("os account type is invalid");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    bool isAllowedCreateAdmin = false;
    ErrCode errCode = innerManager_.IsAllowedCreateAdmin(isAllowedCreateAdmin);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("query allowed create admin error");
        return errCode;
    }
    if (!isAllowedCreateAdmin && type == OsAccountType::ADMIN) {
        ACCOUNT_LOGE("cannot create admin account error");
        return ERR_OSACCOUNT_SERVICE_MANAGER_CREATE_OSACCOUNT_TYPE_ERROR;
    }

    return innerManager_.CreateOsAccount(localName, shortName, type, osAccountInfo);
}

ErrCode OsAccountManagerService::ValidateShortName(const std::string &shortName)
{
    size_t shortNameSize = shortName.size();
    if (shortNameSize == 0 || shortNameSize > Constants::SHORT_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("CreateOsAccount short name length %{public}zu is invalid!", shortNameSize);
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    for (size_t i = 0; i < strlen(Constants::SPECIAL_CHARACTER_ARRAY); i++) {
        if (shortName.find(Constants::SPECIAL_CHARACTER_ARRAY[i]) != std::string::npos) {
            ACCOUNT_LOGE("CreateOsAccount short name is invalidate, short name is %{public}s !", shortName.c_str());
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        }
    }

    for (size_t i = 0; i < sizeof(Constants::SHORT_NAME_CANNOT_BE_NAME_ARRAY); i++) {
        if (shortName.compare(Constants::SHORT_NAME_CANNOT_BE_NAME_ARRAY[i]) == 0) {
            ACCOUNT_LOGE("CreateOsAccount short name is invalidate, short name is %{public}s !", shortName.c_str());
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        }
    }
    return ERR_OK;
}

ErrCode OsAccountManagerService::CreateOsAccountWithFullInfo(OsAccountInfo &osAccountInfo)
{
    bool isMultiOsAccountEnable = false;
    innerManager_.IsMultiOsAccountEnable(isMultiOsAccountEnable);
    if (!isMultiOsAccountEnable) {
        ACCOUNT_LOGE("system is not multi os account enable error");
        return ERR_OSACCOUNT_SERVICE_MANAGER_NOT_ENABLE_MULTI_ERROR;
    }

    if ((!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, CONSTANT_CREATE)) ||
        (!PermissionCheck("", CONSTANT_CREATE_DIRECTLY))) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    bool isAllowedCreateAdmin = false;
    ErrCode errCode = innerManager_.IsAllowedCreateAdmin(isAllowedCreateAdmin);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("query allowed create admin error");
        return errCode;
    }
    if (!isAllowedCreateAdmin && (osAccountInfo.GetType() == OsAccountType::ADMIN)) {
        ACCOUNT_LOGE("cannot create admin account error");
        return ERR_OSACCOUNT_SERVICE_MANAGER_CREATE_OSACCOUNT_TYPE_ERROR;
    }

    return innerManager_.CreateOsAccountWithFullInfo(osAccountInfo);
}

ErrCode OsAccountManagerService::UpdateOsAccountWithFullInfo(OsAccountInfo &osAccountInfo)
{
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    bool isAllowedCreateAdmin = false;
    ErrCode errCode = innerManager_.IsAllowedCreateAdmin(isAllowedCreateAdmin);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("query allowed update admin error");
        return errCode;
    }
    if (!isAllowedCreateAdmin && osAccountInfo.GetType() == OsAccountType::ADMIN) {
        ACCOUNT_LOGE("cannot update admin account error");
        return ERR_OSACCOUNT_SERVICE_MANAGER_CREATE_OSACCOUNT_TYPE_ERROR;
    }

    return innerManager_.UpdateOsAccountWithFullInfo(osAccountInfo);
}

ErrCode OsAccountManagerService::CreateOsAccountForDomain(const OsAccountType &type,
    const DomainAccountInfo &domainInfo, const sptr<IDomainAccountCallback> &callback)
{
    ACCOUNT_LOGI("start");
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, CONSTANT_CREATE)) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    // parameters check
    if ((type < OsAccountType::ADMIN) || (type >= OsAccountType::END)) {
        ACCOUNT_LOGE("os account type is invalid");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (domainInfo.accountName_.empty() || domainInfo.domain_.empty()) {
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (domainInfo.accountName_.size() > Constants::DOMAIN_ACCOUNT_NAME_MAX_SIZE ||
        domainInfo.domain_.size() > Constants::DOMAIN_NAME_MAX_SIZE) {
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    bool isAllowedCreateAdmin = false;
    ErrCode errCode = innerManager_.IsAllowedCreateAdmin(isAllowedCreateAdmin);
    if (errCode != ERR_OK) {
        return errCode;
    }
    if (!isAllowedCreateAdmin && type == OsAccountType::ADMIN) {
        return ERR_OSACCOUNT_SERVICE_MANAGER_CREATE_OSACCOUNT_TYPE_ERROR;
    }
    return innerManager_.CreateOsAccountForDomain(type, domainInfo, callback);
}

ErrCode OsAccountManagerService::RemoveOsAccount(const int id)
{
    // parameters check
    if (id <= Constants::START_USER_ID) {
        ACCOUNT_LOGE("cannot remove system preinstalled user");
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    if (id > Constants::MAX_USER_ID) {
        ACCOUNT_LOGE("localId %{public}d is out of range", id);
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, CONSTANT_REMOVE)) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.RemoveOsAccount(id);
}

ErrCode OsAccountManagerService::IsOsAccountExists(const int id, bool &isOsAccountExists)
{
    return innerManager_.IsOsAccountExists(id, isOsAccountExists);
}

ErrCode OsAccountManagerService::IsOsAccountActived(const int id, bool &isOsAccountActived)
{
    ErrCode res = CheckInvalidLocalId(id);
    if (res != ERR_OK) {
        return res;
    }

    // check current account state
    int callerUserId = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    if (callerUserId == id) {
        return innerManager_.IsOsAccountActived(id, isOsAccountActived);
    }

    // check other account state, check permission first
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "") && !PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
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
        ACCOUNT_LOGE("account manager service, permission denied!");
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
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "") && !PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.IsOsAccountConstraintEnable(id, constraint, isEnabled);
}

ErrCode OsAccountManagerService::IsOsAccountVerified(const int id, bool &isVerified)
{
    ErrCode res = CheckInvalidLocalId(id);
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
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.IsOsAccountVerified(id, isVerified);
}

ErrCode OsAccountManagerService::GetCreatedOsAccountsCount(unsigned int &osAccountsCount)
{
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
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
        ACCOUNT_LOGW("account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    const std::int32_t uid = IPCSkeleton::GetCallingUid();
    isMainOsAccount = ((uid / UID_TRANSFORM_DIVISOR) == MAIN_OS_ACCOUNT_LOCAL_ID);
    return ERR_OK;
}

ErrCode OsAccountManagerService::GetOsAccountLocalIdFromDomain(const DomainAccountInfo &domainInfo, int &id)
{
    if (domainInfo.domain_.empty() || domainInfo.domain_.size() > Constants::DOMAIN_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("domain name length invalid. length %{public}zu.", domainInfo.domain_.size());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    if (domainInfo.accountName_.empty() || domainInfo.accountName_.size() > Constants::DOMAIN_ACCOUNT_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("accountName length invalid. length %{public}zu.", domainInfo.accountName_.size());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.GetOsAccountLocalIdFromDomain(domainInfo, id);
}

ErrCode OsAccountManagerService::QueryMaxOsAccountNumber(int &maxOsAccountNumber)
{
    return innerManager_.QueryMaxOsAccountNumber(maxOsAccountNumber);
}

ErrCode OsAccountManagerService::GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints)
{
    ErrCode res = CheckInvalidLocalId(id);
    if (res != ERR_OK) {
        return res;
    }
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.GetOsAccountAllConstraints(id, constraints);
}

ErrCode OsAccountManagerService::QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos)
{
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.QueryAllCreatedOsAccounts(osAccountInfos);
}

ErrCode OsAccountManagerService::QueryCurrentOsAccount(OsAccountInfo &osAccountInfo)
{
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "") && (!PermissionCheck(GET_LOCAL_ACCOUNTS, ""))) {
        ACCOUNT_LOGE("account manager service, permission denied!");
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
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.QueryOsAccountById(id, osAccountInfo);
}

ErrCode OsAccountManagerService::GetOsAccountTypeFromProcess(OsAccountType &type)
{
    int id = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
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
        ACCOUNT_LOGE("account manager service, permission denied!");
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
    if (name.size() > Constants::LOCAL_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("set os account name is out of allowed size");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (name.size() <= 0) {
        ACCOUNT_LOGE("os account name is empty");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
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

    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
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
    if (photo.size() > Constants::LOCAL_PHOTO_MAX_SIZE) {
        ACCOUNT_LOGE("photo out of allowed size");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (photo.empty()) {
        ACCOUNT_LOGE("photo is empty");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, CONSTANT_SET_ICON)) {
        ACCOUNT_LOGE("account manager service, permission denied!");
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

    // permission check
    if (!PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, CONSTANT_START)) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.ActivateOsAccount(id);
}

ErrCode OsAccountManagerService::StartOsAccount(const int id)
{
    return innerManager_.StartOsAccount(id);
}

ErrCode OsAccountManagerService::StopOsAccount(const int id)
{
    return innerManager_.StopOsAccount(id);
}

ErrCode OsAccountManagerService::SubscribeOsAccount(
    const OsAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener)
{
    // permission check
    if (!PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.SubscribeOsAccount(subscribeInfo, eventListener);
}

ErrCode OsAccountManagerService::UnsubscribeOsAccount(const sptr<IRemoteObject> &eventListener)
{
    // permission check
    if (!PermissionCheck(INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.UnsubscribeOsAccount(eventListener);
}

ErrCode OsAccountManagerService::GetOsAccountLocalIdBySerialNumber(const int64_t serialNumber, int &id)
{
    return innerManager_.GetOsAccountLocalIdBySerialNumber(serialNumber, id);
}

ErrCode OsAccountManagerService::GetSerialNumberByOsAccountLocalId(const int &id, int64_t &serialNumber)
{
    ErrCode result = CheckInvalidLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
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
    return innerManager_.IsOsAccountCompleted(id, isOsAccountCompleted);
}

ErrCode OsAccountManagerService::SetCurrentOsAccountIsVerified(const bool isVerified)
{
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    // parameters check
    int id = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    ErrCode res = CheckLocalId(id);
    if (res != ERR_OK) {
        return res;
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

    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.SetOsAccountIsVerified(id, isVerified);
}

ErrCode OsAccountManagerService::DumpState(const int &id, std::vector<std::string> &state)
{
    state.clear();

    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
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
        result = innerManager_.QueryOsAccountById(id, osAccountInfo);
        if (result != ERR_OK) {
            return result;
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
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.GetCreatedOsAccountNumFromDatabase(storeID, createdOsAccountNum);
}

void OsAccountManagerService::CreateBasicAccounts()
{
    ACCOUNT_LOGI("enter!");
    innerManager_.Init();
    ACCOUNT_LOGI("exit!");
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
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.GetOsAccountFromDatabase(storeID, id, osAccountInfo);
}

ErrCode OsAccountManagerService::GetOsAccountListFromDatabase(const std::string& storeID,
    std::vector<OsAccountInfo> &osAccountList)
{
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.GetOsAccountListFromDatabase(storeID, osAccountList);
}

ErrCode OsAccountManagerService::DumpStateByAccounts(
    const std::vector<OsAccountInfo> &osAccountInfos, std::vector<std::string> &state)
{
    ACCOUNT_LOGD("enter");
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
    return innerManager_.QueryActiveOsAccountIds(ids);
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
        ACCOUNT_LOGE("constraint length is invalid. length %{public}zu.", constraint.size());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.QueryOsAccountConstraintSourceTypes(id, constraint, constraintSourceTypeInfos);
}

ErrCode OsAccountManagerService::SetGlobalOsAccountConstraints(const std::vector<std::string> &constraints,
    const bool enable, const int32_t enforcerId, const bool isDeviceOwner)
{
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.SetGlobalOsAccountConstraints(constraints, enable, enforcerId, isDeviceOwner);
}

ErrCode OsAccountManagerService::SetSpecificOsAccountConstraints(const std::vector<std::string> &constraints,
    const bool enable, const int32_t targetId, const int32_t enforcerId, const bool isDeviceOwner)
{
    // permission check
    if (!PermissionCheck(MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    // parameters check
    if (targetId < Constants::START_USER_ID || enforcerId < Constants::START_USER_ID) {
        ACCOUNT_LOGE("invalid input account id %{public}d or %{public}d.", targetId, enforcerId);
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
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return innerManager_.SetDefaultActivatedOsAccount(id);
}

ErrCode OsAccountManagerService::GetDefaultActivatedOsAccount(int32_t &id)
{
    return innerManager_.GetDefaultActivatedOsAccount(id);
}

ErrCode OsAccountManagerService::GetOsAccountShortName(std::string &shortName)
{
    int32_t id = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    ErrCode errCode = innerManager_.GetOsAccountShortName(id, shortName);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetOsAccountShortName error %{public}d", errCode);
        return errCode;
    }
    return ERR_OK;
}

bool OsAccountManagerService::PermissionCheck(const std::string& permissionName, const std::string& constraintName)
{
    int callerUid = IPCSkeleton::GetCallingUid();
    // root check
    if (callerUid == ROOT_UID) {
        return true;
    }

    // constraints check
    if (!constraintName.empty()) {
        int callerUserId = callerUid / UID_TRANSFORM_DIVISOR;
        bool isEnable = true;
        innerManager_.IsOsAccountConstraintEnable(callerUserId, constraintName, isEnable);
        if (isEnable) {
            ACCOUNT_LOGE("constraint check %{public}s failed.", constraintName.c_str());
            ReportPermissionFail(callerUid, IPCSkeleton::GetCallingPid(), constraintName);
            return false;
        }
    }

    // permission check
    if ((permissionName.empty()) || (AccountPermissionManager::VerifyPermission(permissionName) == ERR_OK)) {
        return true;
    }

    ACCOUNT_LOGE("failed to verify permission for %{public}s.", permissionName.c_str());
    ReportPermissionFail(callerUid, IPCSkeleton::GetCallingPid(), permissionName);
    return false;
}

bool OsAccountManagerService::CheckCreateOsAccountWhiteList()
{
    return uidWhiteListForCreation.find(GetCallingUid()) != uidWhiteListForCreation.end();
}
}  // namespace AccountSA
}  // namespace OHOS
