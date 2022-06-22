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
#include "os_account_manager_service.h"
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
const std::string CONSTANT_REMOVE = "constraint.os.account.remove";
const std::string CONSTANT_START = "constraint.os.account.start";
const std::string CONSTANT_SET_ICON = "constraint.os.account.set.icon";
const std::int32_t ROOT_UID = 0;
const std::string DEFAULT_ANON_STR = "**********";
const size_t INTERCEPT_HEAD_PART_LEN_FOR_NAME = 1;
std::string AnonymizeNameStr(const std::string& nameStr)
{
    if (nameStr.empty()) {
        return nameStr;
    }
    std::string retStr = nameStr.substr(0, INTERCEPT_HEAD_PART_LEN_FOR_NAME) + DEFAULT_ANON_STR;
    return retStr;
}
}  // namespace

OsAccountManagerService::OsAccountManagerService()
{
    innerManager_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    permissionManagerPtr_ = DelayedSingleton<AccountPermissionManager>::GetInstance();
}
OsAccountManagerService::~OsAccountManagerService()
{}

ErrCode OsAccountManagerService::CreateOsAccount(
    const std::string &name, const OsAccountType &type, OsAccountInfo &osAccountInfo)
{
    bool isMultiOsAccountEnable = false;
    innerManager_->IsMultiOsAccountEnable(isMultiOsAccountEnable);
    if (!isMultiOsAccountEnable) {
        ACCOUNT_LOGE("system is not multi os account enable error");
        return ERR_OSACCOUNT_SERVICE_MANAGER_NOT_ENABLE_MULTI_ERROR;
    }

    // permission check
    if (!PermissionCheck(AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, CONSTANT_CREATE)) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    // parameters check
    if (name.size() > Constants::LOCAL_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("os account name out of max allowed size");
        return ERR_OSACCOUNT_SERVICE_MANAGER_NAME_SIZE_OVERFLOW_ERROR;
    }
    if (name.size() <= 0) {
        ACCOUNT_LOGE("os account name is empty");
        return ERR_OSACCOUNT_SERVICE_MANAGER_NAME_SIZE_EMPTY_ERROR;
    }

    bool isAllowedCreateAdmin = false;
    ErrCode errCode = innerManager_->IsAllowedCreateAdmin(isAllowedCreateAdmin);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("query allowed create admin error");
        return errCode;
    }
    if (!isAllowedCreateAdmin && type == OsAccountType::ADMIN) {
        ACCOUNT_LOGE("cannot create admin account error");
        return ERR_OSACCOUNT_SERVICE_MANAGER_CREATE_OSACCOUNT_TYPE_ERROR;
    }
    return innerManager_->CreateOsAccount(name, type, osAccountInfo);
}

ErrCode OsAccountManagerService::CreateOsAccountForDomain(
    const OsAccountType &type, const DomainAccountInfo &domainInfo, OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("start");
    bool isMultiOsAccountEnable = false;
    innerManager_->IsMultiOsAccountEnable(isMultiOsAccountEnable);
    if (!isMultiOsAccountEnable) {
        return ERR_OSACCOUNT_SERVICE_MANAGER_NOT_ENABLE_MULTI_ERROR;
    }

    // permission check
    if (!PermissionCheck(AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, CONSTANT_CREATE)) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    // parameters check
    if (domainInfo.accountName_.empty() || domainInfo.domain_.empty()) {
        return ERR_OSACCOUNT_SERVICE_MANAGER_NAME_SIZE_EMPTY_ERROR;
    }
    if (domainInfo.accountName_.size() > Constants::DOMAIN_ACCOUNT_NAME_MAX_SIZE ||
        domainInfo.domain_.size() > Constants::DOMAIN_NAME_MAX_SIZE) {
        return ERR_OSACCOUNT_SERVICE_MANAGER_NAME_SIZE_OVERFLOW_ERROR;
    }

    bool isAllowedCreateAdmin = false;
    ErrCode errCode = innerManager_->IsAllowedCreateAdmin(isAllowedCreateAdmin);
    if (errCode != ERR_OK) {
        return errCode;
    }
    if (!isAllowedCreateAdmin && type == OsAccountType::ADMIN) {
        return ERR_OSACCOUNT_SERVICE_MANAGER_CREATE_OSACCOUNT_TYPE_ERROR;
    }
    return innerManager_->CreateOsAccountForDomain(type, domainInfo, osAccountInfo);
}

ErrCode OsAccountManagerService::RemoveOsAccount(const int id)
{
    // permission check
    if (!PermissionCheck(AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, CONSTANT_REMOVE)) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    // parameters check
    if (id <= Constants::START_USER_ID) {
        ACCOUNT_LOGE("cannot remove system preinstalled user!");
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }

    return innerManager_->RemoveOsAccount(id);
}

ErrCode OsAccountManagerService::IsOsAccountExists(const int id, bool &isOsAccountExists)
{
    return innerManager_->IsOsAccountExists(id, isOsAccountExists);
}

ErrCode OsAccountManagerService::IsOsAccountActived(const int id, bool &isOsAccountActived)
{
    // check current account state
    int callerUserId = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    if (callerUserId == id) {
        return innerManager_->IsOsAccountActived(id, isOsAccountActived);
    }

    // check other account state, check permission first
    if (!PermissionCheck(AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, "") &&
        !PermissionCheck(AccountPermissionManager::INTERACT_ACROSS_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    return innerManager_->IsOsAccountActived(id, isOsAccountActived);
}

ErrCode OsAccountManagerService::IsOsAccountConstraintEnable(
    const int id, const std::string &constraint, bool &isConstraintEnable)
{
    // permission check
    if (!PermissionCheck(AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    return innerManager_->IsOsAccountConstraintEnable(id, constraint, isConstraintEnable);
}

ErrCode OsAccountManagerService::IsOsAccountVerified(const int id, bool &isVerified)
{
    // check current account state
    int callerUserId = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    if (callerUserId == id) {
        return innerManager_->IsOsAccountVerified(id, isVerified);
    }

    // check other account state, check permission first
    if (!PermissionCheck(AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, "") &&
        !PermissionCheck(AccountPermissionManager::INTERACT_ACROSS_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    return innerManager_->IsOsAccountVerified(id, isVerified);
}

ErrCode OsAccountManagerService::GetCreatedOsAccountsCount(unsigned int &osAccountsCount)
{
    // permission check
    if (!PermissionCheck(AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    return innerManager_->GetCreatedOsAccountsCount(osAccountsCount);
}

ErrCode OsAccountManagerService::GetOsAccountLocalIdFromProcess(int &id)
{
    const std::int32_t uid = IPCSkeleton::GetCallingUid();
    id = uid / UID_TRANSFORM_DIVISOR;
    return ERR_OK;
}

ErrCode OsAccountManagerService::IsMainOsAccount(bool &isMainOsAccount)
{
    const std::int32_t uid = IPCSkeleton::GetCallingUid();
    isMainOsAccount = ((uid / UID_TRANSFORM_DIVISOR) == MAIN_OS_ACCOUNT_LOCAL_ID);
    return ERR_OK;
}

ErrCode OsAccountManagerService::GetOsAccountLocalIdFromDomain(const DomainAccountInfo &domainInfo, int &id)
{
    // permission check
    if (!PermissionCheck(AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    return innerManager_->GetOsAccountLocalIdFromDomain(domainInfo, id);
}

ErrCode OsAccountManagerService::QueryMaxOsAccountNumber(int &maxOsAccountNumber)
{
    return innerManager_->QueryMaxOsAccountNumber(maxOsAccountNumber);
}

ErrCode OsAccountManagerService::GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints)
{
    // permission check
    if (!PermissionCheck(AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    return innerManager_->GetOsAccountAllConstraints(id, constraints);
}

ErrCode OsAccountManagerService::QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos)
{
    // permission check
    if (!PermissionCheck(AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    return innerManager_->QueryAllCreatedOsAccounts(osAccountInfos);
}

ErrCode OsAccountManagerService::QueryCurrentOsAccount(OsAccountInfo &osAccountInfo)
{
    // permission check
    if (!PermissionCheck(AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    int id = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    return innerManager_->QueryOsAccountById(id, osAccountInfo);
}

ErrCode OsAccountManagerService::QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo)
{
    // permission check
    if (!PermissionCheck(AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, "") &&
        !PermissionCheck(AccountPermissionManager::INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    return innerManager_->QueryOsAccountById(id, osAccountInfo);
}

ErrCode OsAccountManagerService::GetOsAccountTypeFromProcess(OsAccountType &type)
{
    int id = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    return innerManager_->GetOsAccountType(id, type);
}

ErrCode OsAccountManagerService::GetOsAccountProfilePhoto(const int id, std::string &photo)
{
    // get current account photo
    int callerUserId = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    if (callerUserId == id) {
        return innerManager_->GetOsAccountProfilePhoto(id, photo);
    }

    // get other account photo, check permission first
    if (!PermissionCheck(AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    return innerManager_->GetOsAccountProfilePhoto(id, photo);
}

ErrCode OsAccountManagerService::IsMultiOsAccountEnable(bool &isMultiOsAccountEnable)
{
    return innerManager_->IsMultiOsAccountEnable(isMultiOsAccountEnable);
}

ErrCode OsAccountManagerService::SetOsAccountName(const int id, const std::string &name)
{
    // permission check
    if (!PermissionCheck(AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    // parameters check
    if (name.size() > Constants::LOCAL_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("set os account name is out of allowed size");
        return ERR_OSACCOUNT_SERVICE_MANAGER_NAME_SIZE_OVERFLOW_ERROR;
    }
    if (name.size() <= 0) {
        ACCOUNT_LOGE("os account name is empty");
        return ERR_OSACCOUNT_SERVICE_MANAGER_NAME_SIZE_EMPTY_ERROR;
    }
    if (id < Constants::START_USER_ID) {
        ACCOUNT_LOGE("invalid input id %{public}d.", id);
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    return innerManager_->SetOsAccountName(id, name);
}

ErrCode OsAccountManagerService::SetOsAccountConstraints(
    const int id, const std::vector<std::string> &constraints, const bool enable)
{
    // permission check
    if (!PermissionCheck(AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    // parameters check
    if (id < Constants::START_USER_ID) {
        ACCOUNT_LOGE("invalid input account id %{public}d.", id);
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }

    return innerManager_->SetBaseOsAccountConstraints(id, constraints, enable);
}

ErrCode OsAccountManagerService::SetOsAccountProfilePhoto(const int id, const std::string &photo)
{
    // permission check
    if (!PermissionCheck(AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, CONSTANT_SET_ICON)) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    // parameters check
    if (id < Constants::START_USER_ID) {
        ACCOUNT_LOGE("invalid input id %{public}d.", id);
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    if (photo.size() > Constants::LOCAL_PHOTO_MAX_SIZE) {
        ACCOUNT_LOGE("photo out of allowed size");
        return ERR_OSACCOUNT_SERVICE_MANAGER_PHOTO_SIZE_OVERFLOW_ERROR;
    }

    return innerManager_->SetOsAccountProfilePhoto(id, photo);
}

ErrCode OsAccountManagerService::ActivateOsAccount(const int id)
{
    // permission check
    if (!PermissionCheck(AccountPermissionManager::INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, CONSTANT_START)) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    // parameters check
    if (id < Constants::START_USER_ID) {
        ACCOUNT_LOGE("invalid input id %{public}d.", id);
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }

    return innerManager_->ActivateOsAccount(id);
}

ErrCode OsAccountManagerService::StartOsAccount(const int id)
{
    return innerManager_->StartOsAccount(id);
}

ErrCode OsAccountManagerService::StopOsAccount(const int id)
{
    return innerManager_->StopOsAccount(id);
}

ErrCode OsAccountManagerService::SubscribeOsAccount(
    const OsAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener)
{
    // permission check
    if (!PermissionCheck(AccountPermissionManager::INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    return innerManager_->SubscribeOsAccount(subscribeInfo, eventListener);
}

ErrCode OsAccountManagerService::UnsubscribeOsAccount(const sptr<IRemoteObject> &eventListener)
{
    // permission check
    if (!PermissionCheck(AccountPermissionManager::INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    return innerManager_->UnsubscribeOsAccount(eventListener);
}

ErrCode OsAccountManagerService::GetOsAccountLocalIdBySerialNumber(const int64_t serialNumber, int &id)
{
    return innerManager_->GetOsAccountLocalIdBySerialNumber(serialNumber, id);
}

ErrCode OsAccountManagerService::GetSerialNumberByOsAccountLocalId(const int &id, int64_t &serialNumber)
{
    return innerManager_->GetSerialNumberByOsAccountLocalId(id, serialNumber);
}

OS_ACCOUNT_SWITCH_MOD OsAccountManagerService::GetOsAccountSwitchMod()
{
    return innerManager_->GetOsAccountSwitchMod();
}

ErrCode OsAccountManagerService::IsCurrentOsAccountVerified(bool &isVerified)
{
    int id = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    return innerManager_->IsOsAccountVerified(id, isVerified);
}

ErrCode OsAccountManagerService::IsOsAccountCompleted(const int id, bool &isOsAccountCompleted)
{
    return innerManager_->IsOsAccountCompleted(id, isOsAccountCompleted);
}

ErrCode OsAccountManagerService::SetCurrentOsAccountIsVerified(const bool isVerified)
{
    // permission check
    if (!PermissionCheck(AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    // parameters check
    int id = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    if (id < Constants::START_USER_ID) {
        ACCOUNT_LOGE("invalid input id %{public}d.", id);
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }

    return innerManager_->SetOsAccountIsVerified(id, isVerified);
}

ErrCode OsAccountManagerService::SetOsAccountIsVerified(const int id, const bool isVerified)
{
    // permission check
    if (!PermissionCheck(AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    // parameters check
    if (id < Constants::START_USER_ID) {
        ACCOUNT_LOGE("invalid input id %{public}d.", id);
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    return innerManager_->SetOsAccountIsVerified(id, isVerified);
}

ErrCode OsAccountManagerService::DumpState(const int &id, std::vector<std::string> &state)
{
    state.clear();

    // permission check
    if (!PermissionCheck(AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    ErrCode result = ERR_OK;
    std::vector<OsAccountInfo> osAccountInfos;

    if (id == -1) {
        result = innerManager_->QueryAllCreatedOsAccounts(osAccountInfos);
        if (result != ERR_OK) {
            return result;
        }
    } else {
        OsAccountInfo osAccountInfo;
        result = innerManager_->QueryOsAccountById(id, osAccountInfo);
        if (result != ERR_OK) {
            return result;
        }

        osAccountInfos.emplace_back(osAccountInfo);
    }

    return DumpStateByAccounts(osAccountInfos, state);
}

ErrCode OsAccountManagerService::GetCreatedOsAccountNumFromDatabase(const std::string& storeID,
    int &createdOsAccountNum)
{
    // permission check
    if (!PermissionCheck(AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    return innerManager_->GetCreatedOsAccountNumFromDatabase(storeID, createdOsAccountNum);
}

void OsAccountManagerService::CreateBasicAccounts()
{
    ACCOUNT_LOGI("enter!");
    innerManager_->Init();
    ACCOUNT_LOGI("exit!");
}

ErrCode OsAccountManagerService::GetSerialNumberFromDatabase(const std::string& storeID,
    int64_t &serialNumber)
{
    return innerManager_->GetSerialNumberFromDatabase(storeID, serialNumber);
}

ErrCode OsAccountManagerService::GetMaxAllowCreateIdFromDatabase(const std::string& storeID, int &id)
{
    return innerManager_->GetMaxAllowCreateIdFromDatabase(storeID, id);
}

ErrCode OsAccountManagerService::GetOsAccountFromDatabase(const std::string& storeID,
    const int id, OsAccountInfo &osAccountInfo)
{
    // permission check
    if (!PermissionCheck(AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    return innerManager_->GetOsAccountFromDatabase(storeID, id, osAccountInfo);
}

ErrCode OsAccountManagerService::GetOsAccountListFromDatabase(const std::string& storeID,
    std::vector<OsAccountInfo> &osAccountList)
{
    // permission check
    if (!PermissionCheck(AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    return innerManager_->GetOsAccountListFromDatabase(storeID, osAccountList);
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
        for (auto constraint : constraints) {
            state.emplace_back(DUMP_TAB_CHARACTER + DUMP_TAB_CHARACTER + constraint);
        }

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
    return innerManager_->QueryActiveOsAccountIds(ids);
}

ErrCode OsAccountManagerService::QueryOsAccountConstraintSourceTypes(const int32_t id,
    const std::string &constraint, std::vector<ConstraintSourceTypeInfo> &constraintSourceTypeInfos)
{
    // permission check
    ACCOUNT_LOGE("QueryOsAccountConstraintSourceTypes Enter");
    if (!PermissionCheck(AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    // parameters check
    if (id < Constants::START_USER_ID) {
        ACCOUNT_LOGE("invalid input id %{public}d.", id);
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    return innerManager_->QueryOsAccountConstraintSourceTypes(id, constraint, constraintSourceTypeInfos);
}

ErrCode OsAccountManagerService::SetGlobalOsAccountConstraints(const std::vector<std::string> &constraints,
    const bool enable, const int32_t enforcerId, const bool isDeviceOwner)
{
    // permission check
    if (!PermissionCheck(AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    // parameters check
    if (enforcerId < Constants::START_USER_ID) {
        ACCOUNT_LOGE("invalid input account id %{public}d.", enforcerId);
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }

    return innerManager_->SetGlobalOsAccountConstraints(constraints, enable, enforcerId, isDeviceOwner);
}

ErrCode OsAccountManagerService::SetSpecificOsAccountConstraints(const std::vector<std::string> &constraints,
    const bool enable, const int32_t targetId, const int32_t enforcerId, const bool isDeviceOwner)
{
    // permission check
    if (!PermissionCheck(AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, "")) {
        ACCOUNT_LOGE("account manager service, permission denied!");
        return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    // parameters check
    if (targetId < Constants::START_USER_ID || enforcerId < Constants::START_USER_ID) {
        ACCOUNT_LOGE("invalid input account id %{public}d or %{public}d.", targetId, enforcerId);
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }

    return innerManager_->SetSpecificOsAccountConstraints(constraints, enable, targetId, enforcerId, isDeviceOwner);
}

bool OsAccountManagerService::PermissionCheck(const std::string& permissionName, const std::string& constraintName)
{
    // constraints check
    int callerUid = IPCSkeleton::GetCallingUid();
    if (!constraintName.empty()) {
        int callerUserId = callerUid / UID_TRANSFORM_DIVISOR;
        bool isEnable = true;
        innerManager_->IsOsAccountConstraintEnable(callerUserId, constraintName, isEnable);
        if (isEnable) {
            ACCOUNT_LOGE("constraint check %{public}s failed.", constraintName.c_str());
            ReportPermissionFail(callerUid, IPCSkeleton::GetCallingPid(), constraintName);
            return false;
        }
    }

    // root check
    if (callerUid == ROOT_UID) {
        return true;
    }

    // permission check
    if (permissionManagerPtr_->VerifyPermission(permissionName) == ERR_OK) {
        return true;
    }

    ACCOUNT_LOGE("failed to verify permission for %{public}s.", permissionName.c_str());
    ReportPermissionFail(callerUid, IPCSkeleton::GetCallingPid(), permissionName);
    return false;
}
}  // namespace AccountSA
}  // namespace OHOS
