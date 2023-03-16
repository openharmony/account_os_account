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
#include "iinner_os_account_manager.h"
#include "account_log_wrapper.h"
#ifdef HAS_CES_PART
#include "common_event_support.h"
#endif // HAS_CES_PART
#include "hitrace_meter.h"
#include "hisysevent_adapter.h"
#include "ohos_account_kits.h"
#include "os_account_constants.h"
#include "os_account_control_file_manager.h"
#include "os_account_subscribe_manager.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::string CONSTRAINT_CREATE_ACCOUNT_DIRECTLY = "constraint.os.account.create.directly";
}

IInnerOsAccountManager::IInnerOsAccountManager() : subscribeManagerPtr_(OsAccountSubscribeManager::GetInstance())
{
    counterForStandard_ = 0;
    counterForStandardCreate_ = 0;
    counterForAccountStart_ = 0;
    isSendToStorageCreate_ = false;
    isSendToStorageStart_ = false;
    activeAccountId_.clear();
    operatingId_.clear();
    osAccountControl_ = std::make_shared<OsAccountControlFileManager>();
    osAccountControl_->Init();
    osAccountControl_->GetDeviceOwnerId(deviceOwnerId_);
    ACCOUNT_LOGD("OsAccountAccountMgr Init end");
}

void IInnerOsAccountManager::SetOsAccountControl(std::shared_ptr<IOsAccountControl> ptr)
{
    osAccountControl_ = ptr;
}

void IInnerOsAccountManager::CreateBaseAdminAccount()
{
    bool isExistsAccount = false;
    osAccountControl_->IsOsAccountExists(Constants::ADMIN_LOCAL_ID, isExistsAccount);
    if (!isExistsAccount) {
        int64_t serialNumber =
            Constants::CARRY_NUM * Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN + Constants::ADMIN_LOCAL_ID;
        OsAccountInfo osAccountInfo(
            Constants::ADMIN_LOCAL_ID, Constants::ADMIN_LOCAL_NAME, OsAccountType::ADMIN, serialNumber);
        int64_t time =
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
                .count();
        osAccountInfo.SetCreateTime(time);
        osAccountInfo.SetIsCreateCompleted(true);
        osAccountInfo.SetIsActived(true);  // admin local account is always active
        osAccountControl_->InsertOsAccount(osAccountInfo);
        ACCOUNT_LOGI("OsAccountAccountMgr created admin account end");
    }
}

void IInnerOsAccountManager::CreateBaseStandardAccount()
{
    bool isExistsAccount = false;
    osAccountControl_->IsOsAccountExists(Constants::START_USER_ID, isExistsAccount);
    if (!isExistsAccount) {
        int64_t serialNumber = 0;
        osAccountControl_->GetSerialNumber(serialNumber);
        OsAccountInfo osAccountInfo(
            Constants::START_USER_ID, Constants::STANDARD_LOCAL_NAME, OsAccountType::ADMIN, serialNumber);
        std::vector<std::string> constants;
        ErrCode errCode = osAccountControl_->GetConstraintsByType(OsAccountType::ADMIN, constants);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("find first standard type err, errCode %{public}d.", errCode);
            return;
        }
        osAccountInfo.SetConstraints(constants);
        int64_t time =
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
                .count();
        osAccountInfo.SetCreateTime(time);
        osAccountInfo.SetIsCreateCompleted(false);
        osAccountControl_->InsertOsAccount(osAccountInfo);
        ACCOUNT_LOGI("OsAccountAccountMgr created base account end");
    }
}

void IInnerOsAccountManager::StartAccount()
{
    ResetAccountStatus();
    GetEventHandler();
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(Constants::START_USER_ID, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE(
            "OsAccountAccountMgr init start base account failed. cannot find account, errCode %{public}d.", errCode);
        return;
    }
    if (!osAccountInfo.GetIsCreateCompleted()) {
        ACCOUNT_LOGI("OsAccountAccountMgr send to storage and bm for start");
        OHOS::AppExecFwk::InnerEvent::Callback callbackStartStandard =
            std::bind(&IInnerOsAccountManager::CreateBaseStandardAccountSendToOther, this);
        handler_->PostTask(callbackStartStandard);
        return;
    }
    ACCOUNT_LOGI("OsAccountAccountMgr send to storage and am for start");
    OHOS::AppExecFwk::InnerEvent::Callback callbackStartStandard =
        std::bind(&IInnerOsAccountManager::StartBaseStandardAccount, this, osAccountInfo);
    handler_->PostTask(callbackStartStandard);
}

void IInnerOsAccountManager::RestartActiveAccount()
{
    // query active account to restart and refresh into list
    std::vector<OsAccountInfo> osAccountInfos;
    if (QueryAllCreatedOsAccounts(osAccountInfos) != ERR_OK) {
        return;
    }
    for (size_t i = 0; i < osAccountInfos.size(); ++i) {
        if (osAccountInfos[i].GetIsActived() && osAccountInfos[i].GetLocalId() != Constants::START_USER_ID) {
            // reactivate account state
            GetEventHandler();
            OHOS::AppExecFwk::InnerEvent::Callback callbackForRestart =
                std::bind(&IInnerOsAccountManager::StartActivatedAccount, this, osAccountInfos[i].GetLocalId());
            handler_->PostTask(callbackForRestart, DELAY_FOR_FOUNDATION_SERVICE);
        }
    }
}

void IInnerOsAccountManager::StartActivatedAccount(int32_t id)
{
    OsAccountInfo osAccountInfo;
    osAccountControl_->GetOsAccountInfoById(Constants::START_USER_ID, osAccountInfo);
    if (!IsOsAccountIDInActiveList(id)) {
        ErrCode errCode = ActivateOsAccount(id);
        if (errCode != ERR_OK) {
            if (++counterForAccountStart_ == MAX_TRY_TIMES) {
                ACCOUNT_LOGE("failed to reactivate account, id = %{public}d", id);
            } else {
                GetEventHandler();
                OHOS::AppExecFwk::InnerEvent::Callback callbackForRestart =
                    std::bind(&IInnerOsAccountManager::StartActivatedAccount, this, id);
                handler_->PostTask(callbackForRestart, DELAY_FOR_FOUNDATION_SERVICE);
            }
            return;
        }
        ACCOUNT_LOGI("reactive account ok");
        counterForAccountStart_ = 0;
    }
    int64_t time = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    osAccountInfo.SetLastLoginTime(time);
    osAccountControl_->UpdateOsAccount(osAccountInfo);
    PushIdIntoActiveList(id);
    subscribeManagerPtr_->PublishActivatedOsAccount(Constants::START_USER_ID);
    OsAccountInterface::SendToCESAccountSwitched(osAccountInfo);
    ACCOUNT_LOGI("restart account ok");
}

void IInnerOsAccountManager::CreateBaseStandardAccountSendToOther(void)
{
    OsAccountInfo osAccountInfo;
    if (!isSendToStorageCreate_) {
        osAccountControl_->GetOsAccountInfoById(Constants::START_USER_ID, osAccountInfo);
        ErrCode errCode = OsAccountInterface::SendToStorageAccountCreate(osAccountInfo);
        if (errCode != ERR_OK) {
            if (++counterForStandardCreate_ == MAX_TRY_TIMES) {
                ACCOUNT_LOGE("failed connect storage to create account, errCode %{public}d.", errCode);
            } else {
                GetEventHandler();
                OHOS::AppExecFwk::InnerEvent::Callback callback =
                    std::bind(&IInnerOsAccountManager::CreateBaseStandardAccountSendToOther, this);
                handler_->PostTask(callback, DELAY_FOR_TIME_INTERVAL);
            }
            return;
        } else {
            ACCOUNT_LOGI("connect storage to create account ok");
            counterForStandardCreate_ = 0;
            isSendToStorageCreate_ = true;
        }
    }
    osAccountControl_->GetOsAccountInfoById(Constants::START_USER_ID, osAccountInfo);
    ErrCode errCodeForBM = OsAccountInterface::SendToBMSAccountCreate(osAccountInfo);
    if (errCodeForBM != ERR_OK) {
        if (++counterForStandardCreate_ == MAX_TRY_TIMES) {
            ACCOUNT_LOGE("failed connect BM to create account, errCodeForBM %{public}d.", errCodeForBM);
        } else {
            GetEventHandler();
            OHOS::AppExecFwk::InnerEvent::Callback callback =
                std::bind(&IInnerOsAccountManager::CreateBaseStandardAccountSendToOther, this);
            handler_->PostTask(callback, DELAY_FOR_TIME_INTERVAL);
        }
        return;
    }
    osAccountInfo.SetIsCreateCompleted(true);
    osAccountControl_->UpdateOsAccount(osAccountInfo);
    ACCOUNT_LOGI("connect BM to create account ok");
    GetEventHandler();
    OHOS::AppExecFwk::InnerEvent::Callback callbackStartStandard =
        std::bind(&IInnerOsAccountManager::StartBaseStandardAccount, this, osAccountInfo);
    handler_->PostTask(callbackStartStandard);
}

void IInnerOsAccountManager::ResetAccountStatus(void)
{
    std::vector<OsAccountInfo> osAccountInfos;
    if (QueryAllCreatedOsAccounts(osAccountInfos) != ERR_OK) {
        return;
    }
    for (size_t i = 0; i < osAccountInfos.size(); ++i) {
        osAccountInfos[i].SetIsVerified(false);
#ifndef ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
        osAccountInfos[i].SetIsActived(false);
#endif // ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
        osAccountControl_->UpdateOsAccount(osAccountInfos[i]);
    }
}

void IInnerOsAccountManager::StartBaseStandardAccount(OsAccountInfo &osAccountInfo)
{
    if (!isSendToStorageStart_) {
        ErrCode errCode = OsAccountInterface::SendToStorageAccountStart(osAccountInfo);
        if (errCode != ERR_OK) {
            if (++counterForStandard_ == MAX_TRY_TIMES) {
                ACCOUNT_LOGE("failed connect storage to start account, errCode %{public}d.", errCode);
            } else {
                GetEventHandler();
                OHOS::AppExecFwk::InnerEvent::Callback callback =
                    std::bind(&IInnerOsAccountManager::StartBaseStandardAccount, this, osAccountInfo);
                handler_->PostTask(callback, DELAY_FOR_TIME_INTERVAL);
            }
            return;
        }
        ACCOUNT_LOGI("connect storage to start account ok");
        counterForStandard_ = 0;
        isSendToStorageStart_ = true;
    }
    ErrCode errCodeForAM = OsAccountInterface::SendToAMSAccountStart(osAccountInfo);
    if (errCodeForAM != ERR_OK) {
        if (++counterForStandard_ == MAX_TRY_TIMES) {
            ACCOUNT_LOGE("failed connect AM to start account, errCodeForAM %{public}d.", errCodeForAM);
        } else {
            GetEventHandler();
            OHOS::AppExecFwk::InnerEvent::Callback callback =
                std::bind(&IInnerOsAccountManager::StartBaseStandardAccount, this, osAccountInfo);
            handler_->PostTask(callback, DELAY_FOR_TIME_INTERVAL);
        }
        return;
    }
    osAccountInfo.SetIsActived(true);
    int64_t time = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    osAccountInfo.SetLastLoginTime(time);
    osAccountControl_->UpdateOsAccount(osAccountInfo);
    PushIdIntoActiveList(Constants::START_USER_ID);
    subscribeManagerPtr_->PublishActivatedOsAccount(Constants::START_USER_ID);
    OsAccountInterface::SendToCESAccountSwitched(osAccountInfo);
    ACCOUNT_LOGI("connect AM to start account ok");
}

ErrCode IInnerOsAccountManager::PrepareOsAccountInfo(const std::string &name, const OsAccountType &type,
    const DomainAccountInfo &domainInfo, OsAccountInfo &osAccountInfo)
{
    int64_t serialNumber;
    ErrCode errCode = osAccountControl_->GetSerialNumber(serialNumber);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("failed to GetSerialNumber, errCode %{public}d.", errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_GET_SERIAL_NUMBER_ERROR;
    }
    int id = 0;
    errCode = osAccountControl_->GetAllowCreateId(id);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("failed to GetAllowCreateId, errCode %{public}d.", errCode);
        return errCode;
    }
    std::vector<std::string> constraints;
    constraints.clear();
    errCode = osAccountControl_->GetConstraintsByType(type, constraints);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("failed to GetConstraintsByType, errCode %{public}d.", errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_GET_TYPE_CONSTRAINTS_ERROR;
    }
    osAccountInfo = OsAccountInfo(id, name, type, serialNumber);
    osAccountInfo.SetConstraints(constraints);
    int64_t time =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    osAccountInfo.SetCreateTime(time);
    if (!osAccountInfo.SetDomainInfo(domainInfo)) {
        ACCOUNT_LOGE("failed to SetDomainInfo");
        return ERR_OSACCOUNT_KIT_CREATE_OS_ACCOUNT_FOR_DOMAIN_ERROR;
    }

    errCode = osAccountControl_->InsertOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("insert os account info err, errCode %{public}d.", errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_CREATE_ACCOUNT_ERROR;
    }
    errCode = osAccountControl_->UpdateBaseOAConstraints(std::to_string(id), constraints, true);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("UpdateBaseOAConstraints err");
        return ERR_OSACCOUNT_SERVICE_INNER_CREATE_ACCOUNT_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SendMsgForAccountCreate(OsAccountInfo &osAccountInfo)
{
    ErrCode errCode = OsAccountInterface::SendToStorageAccountCreate(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("create os account SendToStorageAccountCreate failed, errCode %{public}d.", errCode);
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_CREATE_ERROR;
    }
    errCode = OsAccountInterface::SendToBMSAccountCreate(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("create os account SendToBMSAccountCreate failed, errCode %{public}d.", errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_SEND_BM_ACCOUNT_CREATE_ERROR;
    }

    osAccountInfo.SetIsCreateCompleted(true);
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("create os account when update isCreateCompleted");
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_CREATE,
            errCode, "UpdateOsAccount failed!");
        return ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }
    ReportOsAccountLifeCycle(osAccountInfo.GetLocalId(), Constants::OPERATION_CREATE);
    OsAccountInterface::SendToCESAccountCreate(osAccountInfo);

    return ERR_OK;
}

ErrCode IInnerOsAccountManager::CreateOsAccount(
    const std::string &name, const OsAccountType &type, OsAccountInfo &osAccountInfo)
{
    DomainAccountInfo domainInfo;  // default empty domain info
    ErrCode errCode = PrepareOsAccountInfo(name, type, domainInfo, osAccountInfo);
    if (errCode != ERR_OK) {
        return errCode;
    }
    return SendMsgForAccountCreate(osAccountInfo);
}

ErrCode IInnerOsAccountManager::CreateOsAccountForDomain(
    const OsAccountType &type, const DomainAccountInfo &domainInfo, OsAccountInfo &osAccountInfo)
{
    // check whether if the target domain has already been bound to an os account or not
    std::vector<OsAccountInfo> osAccountInfos;
    ErrCode errCode = QueryAllCreatedOsAccounts(osAccountInfos);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("cannot get current os account list, err %{public}d.", errCode);
        return errCode;
    }
    for (size_t i = 0; i < osAccountInfos.size(); ++i) {
        DomainAccountInfo curDomainInfo;
        osAccountInfos[i].GetDomainInfo(curDomainInfo);
        if (curDomainInfo.accountName_ == domainInfo.accountName_ &&
            curDomainInfo.domain_ == domainInfo.domain_) {
            return ERR_OSACCOUNT_SERVICE_INNER_DOMAIN_ALREADY_BIND_ERROR;
        }
    }

    std::string osAccountName = domainInfo.domain_ + "/" + domainInfo.accountName_;
    bool isEnabled = false;
    (void)IsOsAccountConstraintEnable(Constants::START_USER_ID, CONSTRAINT_CREATE_ACCOUNT_DIRECTLY, isEnabled);
    if (isEnabled && (osAccountInfos.size() == 1) && (osAccountInfos[0].GetLocalId() == Constants::START_USER_ID)) {
        DomainAccountInfo curDomainInfo;
        osAccountInfos[0].GetDomainInfo(curDomainInfo);
        if (curDomainInfo.domain_.empty()) {
            osAccountInfos[0].SetLocalName(osAccountName);
            osAccountInfos[0].SetDomainInfo(domainInfo);
            osAccountInfo = osAccountInfos[0];
            return osAccountControl_->UpdateOsAccount(osAccountInfos[0]);
        }
    }

    errCode = PrepareOsAccountInfo(osAccountName, type, domainInfo, osAccountInfo);
    if (errCode != ERR_OK) {
        return errCode;
    }
    return SendMsgForAccountCreate(osAccountInfo);
}

ErrCode IInnerOsAccountManager::RemoveOsAccount(const int id)
{
    ACCOUNT_LOGI("RemoveOsAccount delete id is %{public}d", id);
    if (IsLocalIdInOperating(id)) {
        ACCOUNT_LOGE("the %{public}d already in operating", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_OPERATING_ERROR;
    }
    AddLocalIdToOperating(id);
#ifndef ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
    if (IsOsAccountIDInActiveList(id)) {
        ACCOUNT_LOGI("RemoveOsAccount started account to inactive, account id : %{public}d.", id);
        ErrCode activeErrCode = ActivateOsAccount(Constants::START_USER_ID);
        if (activeErrCode != ERR_OK) {
            RemoveLocalIdToOperating(id);
            ACCOUNT_LOGE("RemoveOsAccount active base account failed");
            return ERR_OSACCOUNT_SERVICE_INNER_REMOVE_ACCOUNT_ACTIVED_ERROR;
        }
    }
#endif // ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        RemoveLocalIdToOperating(id);
        ACCOUNT_LOGE("RemoveOsAccount cannot find os account info, errCode %{public}d.", errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_CANNOT_FIND_OSACCOUNT_ERROR;
    }

    // set remove flag first
    osAccountInfo.SetToBeRemoved(true);
    osAccountControl_->UpdateOsAccount(osAccountInfo);

    // stop account first
    errCode = SendMsgForAccountStop(osAccountInfo);
    if (errCode != ERR_OK) {
        RemoveLocalIdToOperating(id);
        return errCode;
    }

    // then remove account
    errCode = SendMsgForAccountRemove(osAccountInfo);
    if (errCode != ERR_OK) {
        RemoveLocalIdToOperating(id);
        return errCode;
    }
    RemoveLocalIdToOperating(id);

    errCode = osAccountControl_->RemoveOAConstraintsInfo(id);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("RemoveOsAccount failed to remove os account constraints info");
        return errCode;
    }
    if (id == deviceOwnerId_) {
        osAccountControl_->UpdateDeviceOwnerId(-1);
    }
    ACCOUNT_LOGI("IInnerOsAccountManager RemoveOsAccount end");
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SendMsgForAccountStop(OsAccountInfo &osAccountInfo)
{
    ErrCode errCode = OsAccountInterface::SendToAMSAccountStop(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("SendToAMSAccountStop failed, id %{public}d, errCode %{public}d",
            osAccountInfo.GetLocalId(), errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_SEND_AM_ACCOUNT_STOP_ERROR;
    }
    errCode = OsAccountInterface::SendToStorageAccountStop(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("SendToStorageAccountStop failed, id %{public}d, errCode %{public}d",
            osAccountInfo.GetLocalId(), errCode);
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_STOP_ERROR;
    }
#ifdef ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
    errCode = DeActivateOsAccount(osAccountInfo.GetLocalId());
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("DeActivateOsAccount failed, id %{public}d, errCode %{public}d",
            osAccountInfo.GetLocalId(), errCode);
        return errCode;
    }
    ACCOUNT_LOGI("SendMsgForAccountStop ok");
#endif // ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
    return errCode;
}

ErrCode IInnerOsAccountManager::SendMsgForAccountRemove(OsAccountInfo &osAccountInfo)
{
    ErrCode errCode = OsAccountInterface::SendToBMSAccountDelete(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("SendToBMSAccountDelete failed, id %{public}d, errCode %{public}d",
            osAccountInfo.GetLocalId(), errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_SEND_BM_ACCOUNT_DELE_ERROR;
    }
    errCode = OsAccountInterface::SendToStorageAccountRemove(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("SendToStorageAccountRemove failed, id %{public}d, errCode %{public}d",
            osAccountInfo.GetLocalId(), errCode);
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_REMOVE_ERROR;
    }
#ifdef HAS_USER_IDM_PART
    errCode = OsAccountInterface::SendToIDMAccountDelete(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("SendToIDMAccountDelete failed, id %{public}d, errCode %{public}d",
            osAccountInfo.GetLocalId(), errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_SEND_IAM_ACCOUNT_DELE_ERROR;
    }
#endif // HAS_USER_IDM_PART
    errCode = osAccountControl_->DelOsAccount(osAccountInfo.GetLocalId());
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("remove osaccount info failed, id: %{public}d, errCode %{public}d",
            osAccountInfo.GetLocalId(), errCode);
        return errCode;
    }
    OsAccountInterface::SendToCESAccountDelete(osAccountInfo);
    ReportOsAccountLifeCycle(osAccountInfo.GetLocalId(), Constants::OPERATION_DELETE);
    return errCode;
}

void IInnerOsAccountManager::Init()
{
    CreateBaseAdminAccount();
    CreateBaseStandardAccount();
    StartAccount();
#ifdef ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
    RestartActiveAccount();
#endif // ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
    CleanGarbageAccounts();
}

ErrCode IInnerOsAccountManager::IsOsAccountExists(const int id, bool &isOsAccountExits)
{
    isOsAccountExits = false;
    osAccountControl_->IsOsAccountExists(id, isOsAccountExits);
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::IsOsAccountActived(const int id, bool &isOsAccountActived)
{
    isOsAccountActived = false;

    // check if os account exists
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error, errCode %{public}d.", errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    if (id == Constants::ADMIN_LOCAL_ID) {
        isOsAccountActived = true;
        return ERR_OK;
    }
    isOsAccountActived = IsOsAccountIDInActiveList(id);
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::IsOsAccountConstraintEnable(
    const int id, const std::string &constraint, bool &isOsAccountConstraintEnable)
{
    isOsAccountConstraintEnable = false;
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error, errCode %{public}d.", errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    std::vector<std::string> constraints;
    constraints = osAccountInfo.GetConstraints();
    if (std::find(constraints.begin(), constraints.end(), constraint) != constraints.end()) {
        isOsAccountConstraintEnable = true;
        return ERR_OK;
    }
    constraints.clear();
    if (osAccountControl_->GetGlobalOAConstraintsList(constraints) == ERR_OK) {
        if (std::find(constraints.begin(), constraints.end(), constraint) != constraints.end()) {
            isOsAccountConstraintEnable = true;
            return ERR_OK;
        }
    }
    constraints.clear();
    if (osAccountControl_->GetSpecificOAConstraintsList(id, constraints) == ERR_OK) {
        if (std::find(constraints.begin(), constraints.end(), constraint) != constraints.end()) {
            isOsAccountConstraintEnable = true;
            return ERR_OK;
        }
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::IsOsAccountVerified(const int id, bool &isVerified)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error, errCode %{public}d.", errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    isVerified = osAccountInfo.GetIsVerified();
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetCreatedOsAccountsCount(unsigned int &createdOsAccountCount)
{
    std::vector<OsAccountInfo> osAccountInfos;
    ErrCode errCode = osAccountControl_->GetOsAccountList(osAccountInfos);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info list error, errCode %{public}d.", errCode);
        return errCode;
    }
    createdOsAccountCount = osAccountInfos.size();
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::QueryMaxOsAccountNumber(int &maxOsAccountNumber)
{
    ErrCode errCode = osAccountControl_->GetMaxCreatedOsAccountNum(maxOsAccountNumber);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get max created osaccount num error, errCode %{public}d.", errCode);
        return errCode;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error, errCode %{public}d.", errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    constraints = osAccountInfo.GetConstraints();
    std::vector<std::string> globalConstraints;
    errCode = osAccountControl_->GetGlobalOAConstraintsList(globalConstraints);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get globalConstraints info error");
        return errCode;
    }
    for (auto it = globalConstraints.begin(); it != globalConstraints.end(); it++) {
        if (std::find(constraints.begin(), constraints.end(), *it) == constraints.end()) {
            constraints.push_back(*it);
        }
    }
    std::vector<std::string> specificConstraints;
    errCode = osAccountControl_->GetSpecificOAConstraintsList(id, specificConstraints);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get specificConstraints info error");
        return errCode;
    }
    for (auto it = specificConstraints.begin(); it != specificConstraints.end(); it++) {
        if (std::find(constraints.begin(), constraints.end(), *it) == constraints.end()) {
            constraints.push_back(*it);
        }
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::QueryOsAccountConstraintSourceTypes(const int32_t id,
    const std::string &constraint, std::vector<ConstraintSourceTypeInfo> &constraintSourceTypeInfos)
{
    ACCOUNT_LOGD("enter.");
    bool isOsAccountConstraintEnable = false;
    ErrCode errCode = IsOsAccountConstraintEnable(id, constraint, isOsAccountConstraintEnable);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get os account constraint enable info error");
        return errCode;
    }
    if (!isOsAccountConstraintEnable) {
        ACCOUNT_LOGI("constraint not exist");
        ConstraintSourceTypeInfo constraintSourceTypeInfo;
        constraintSourceTypeInfo.localId = -1;
        constraintSourceTypeInfo.typeInfo = ConstraintSourceType::CONSTRAINT_NOT_EXIST;
        constraintSourceTypeInfos.push_back(constraintSourceTypeInfo);
        return ERR_OK;
    }

    bool isExits;
    if (osAccountControl_->IsFromBaseOAConstraintsList(id, constraint, isExits) == ERR_OK) {
        if (isExits) {
            ACCOUNT_LOGI("constraint is exist in base os account constraints list");
            ConstraintSourceTypeInfo constraintSourceTypeInfo;
            constraintSourceTypeInfo.localId = -1;
            constraintSourceTypeInfo.typeInfo = ConstraintSourceType::CONSTRAINT_TYPE_BASE;
            constraintSourceTypeInfos.push_back(constraintSourceTypeInfo);
        }
    }
    std::vector<ConstraintSourceTypeInfo> globalSourceList;
    errCode = osAccountControl_->IsFromGlobalOAConstraintsList(id, deviceOwnerId_, constraint, globalSourceList);
    if (errCode == ERR_OK && globalSourceList.size() != 0) {
        ACCOUNT_LOGI("constraint is exist in global os account constraints list");
        constraintSourceTypeInfos.insert(
            constraintSourceTypeInfos.end(), globalSourceList.begin(), globalSourceList.end());
    }
    std::vector<ConstraintSourceTypeInfo> specificSourceList;
    errCode = osAccountControl_->IsFromSpecificOAConstraintsList(id, deviceOwnerId_, constraint, specificSourceList);
    if (errCode == ERR_OK && specificSourceList.size() != 0) {
        ACCOUNT_LOGI("constraint is exist in specific os account constraints list");
        constraintSourceTypeInfos.insert(
            constraintSourceTypeInfos.end(), specificSourceList.begin(), specificSourceList.end());
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SetBaseOsAccountConstraints(const int32_t id,
    const std::vector<std::string> &constraints, const bool enable)
{
    ErrCode errCode = SetOsAccountConstraints(id, constraints, enable);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("set os account %{public}d constraints failed! errCode %{public}d.", id, errCode);
        return errCode;
    }

    errCode = osAccountControl_->UpdateBaseOAConstraints(std::to_string(id), constraints, enable);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("update base os account %{public}d constraints failed! errCode %{public}d.", id, errCode);
        return errCode;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SetGlobalOsAccountConstraints(const std::vector<std::string> &constraints,
    const bool enable, const int32_t enforcerId, const bool isDeviceOwner)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(enforcerId, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error %{public}d", enforcerId);
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    if (osAccountInfo.GetToBeRemoved()) {
        ACCOUNT_LOGE("account %{public}d will be removed, cannot change constraints!", enforcerId);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR;
    }

    bool isExists = false;
    bool isOverSize = false;
    errCode = osAccountControl_->CheckConstraintsList(constraints, isExists, isOverSize);
    if (errCode != ERR_OK || !isExists || isOverSize) {
        ACCOUNT_LOGE("input constraints not in constraints list or is oversize!");
        return ERR_OSACCOUNT_SERVICE_INNER_SER_CONSTRAINTS_ERROR;
    }

    osAccountControl_->UpdateGlobalOAConstraints(std::to_string(enforcerId), constraints, enable);

    errCode = DealWithDeviceOwnerId(isDeviceOwner, enforcerId);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("deal with device owner id error");
        return errCode;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SetSpecificOsAccountConstraints(const std::vector<std::string> &constraints,
    const bool enable, const int32_t targetId, const int32_t enforcerId, const bool isDeviceOwner)
{
    OsAccountInfo enforcerOsAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(enforcerId, enforcerOsAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error");
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }

    OsAccountInfo targetOsAccountInfo;
    errCode = osAccountControl_->GetOsAccountInfoById(targetId, targetOsAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error");
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    if (targetOsAccountInfo.GetToBeRemoved() || enforcerOsAccountInfo.GetToBeRemoved()) {
        ACCOUNT_LOGE("account %{public}d or %{public}d will be removed, cannot change constraints!",
            enforcerId, targetId);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR;
    }

    bool isExists = false;
    bool isOverSize = false;
    errCode = osAccountControl_->CheckConstraintsList(constraints, isExists, isOverSize);
    if (errCode != ERR_OK || !isExists || isOverSize) {
        ACCOUNT_LOGE("input constraints not in constraints list or is oversize!");
        return ERR_OSACCOUNT_SERVICE_INNER_SER_CONSTRAINTS_ERROR;
    }

    osAccountControl_->UpdateSpecificOAConstraints(
        std::to_string(enforcerId), std::to_string(targetId), constraints, enable);

    errCode = DealWithDeviceOwnerId(isDeviceOwner, enforcerId);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("deal with device owner id error");
        return errCode;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos)
{
    ErrCode errCode = osAccountControl_->GetOsAccountList(osAccountInfos);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info list error, errCode %{public}d.", errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_GET_ACCOUNT_LIST_ERROR;
    }
#ifndef ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
    for (auto osAccountInfosPtr = osAccountInfos.begin(); osAccountInfosPtr != osAccountInfos.end();
         ++osAccountInfosPtr) {
        if (IsOsAccountIDInActiveList(osAccountInfosPtr->GetLocalId())) {
            osAccountInfosPtr->SetIsActived(true);
        } else {
            osAccountInfosPtr->SetIsActived(false);
        }
    }
#endif // ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::DealWithDeviceOwnerId(const bool isDeviceOwner, const int32_t localId)
{
    ACCOUNT_LOGD("enter.");
    if (isDeviceOwner && localId != deviceOwnerId_) {
        ACCOUNT_LOGI("this device owner os account id is changed!");
        deviceOwnerId_ = localId;
        return osAccountControl_->UpdateDeviceOwnerId(localId);
    }
    if (isDeviceOwner == false && localId == deviceOwnerId_) {
        deviceOwnerId_ = -1;
        return osAccountControl_->UpdateDeviceOwnerId(-1);
    }
    return ERR_OK;
}

void IInnerOsAccountManager::CleanGarbageAccounts()
{
    ACCOUNT_LOGD("enter.");
    std::vector<OsAccountInfo> osAccountInfos;
    if (QueryAllCreatedOsAccounts(osAccountInfos) != ERR_OK) {
        ACCOUNT_LOGI("QueryAllCreatedOsAccounts failed.");
        return;
    }

    // check status and remove garbage accounts data
    for (size_t i = 0; i < osAccountInfos.size(); ++i) {
        if (!osAccountInfos[i].GetToBeRemoved()) {
            continue;
        }

        if (osAccountInfos[i].GetLocalId() == Constants::START_USER_ID ||
            osAccountInfos[i].GetLocalId() == Constants::ADMIN_LOCAL_ID) {
            continue;
        }

        ErrCode errCode = SendMsgForAccountRemove(osAccountInfos[i]);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("remove account %{public}d failed! errCode %{public}d.",
                osAccountInfos[i].GetLocalId(), errCode);
        } else {
            ACCOUNT_LOGI("remove account %{public}d succeed!", osAccountInfos[i].GetLocalId());
        }
    }
    ACCOUNT_LOGI("finished.");
}

ErrCode IInnerOsAccountManager::GetOsAccountLocalIdFromDomain(const DomainAccountInfo &domainInfo, int &id)
{
    if (domainInfo.domain_.empty() ||
        domainInfo.domain_.size() > Constants::DOMAIN_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("invalid domain name length %{public}zu.", domainInfo.domain_.size());
        return ERR_OSACCOUNT_SERVICE_INNER_DOMAIN_NAME_LEN_ERROR;
    }

    if (domainInfo.accountName_.empty() ||
        domainInfo.accountName_.size() > Constants::DOMAIN_ACCOUNT_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("invalid domain account name length %{public}zu.", domainInfo.accountName_.size());
        return ERR_OSACCOUNT_SERVICE_INNER_DOMAIN_ACCOUNT_NAME_LEN_ERROR;
    }

    id = -1;
    std::vector<OsAccountInfo> osAccountInfos;
    ErrCode errCode = osAccountControl_->GetOsAccountList(osAccountInfos);
    if (errCode != ERR_OK) {
        return ERR_OSACCOUNT_SERVICE_INNER_GET_ACCOUNT_LIST_ERROR;
    }

    DomainAccountInfo curDomainInfo;
    for (auto osAccountInfosPtr = osAccountInfos.begin(); osAccountInfosPtr != osAccountInfos.end();
         ++osAccountInfosPtr) {
        osAccountInfosPtr->GetDomainInfo(curDomainInfo);
        if (curDomainInfo.accountName_ == domainInfo.accountName_ &&
            curDomainInfo.domain_ == domainInfo.domain_) {
            id = osAccountInfosPtr->GetLocalId();
            return ERR_OK;
        }
    }
    return ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_LOCAL_ID_FOR_DOMAIN_ERROR;
}

ErrCode IInnerOsAccountManager::QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo)
{
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error, errCode %{public}d.", errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }

    if (IsOsAccountIDInActiveList(id)) {
        osAccountInfo.SetIsActived(true);
    } else {
        osAccountInfo.SetIsActived(false);
    }

    if (osAccountInfo.GetPhoto() != "") {
        std::string photo = osAccountInfo.GetPhoto();
        errCode = osAccountControl_->GetPhotoById(osAccountInfo.GetLocalId(), photo);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("get osaccount photo error, errCode %{public}d.", errCode);
            return errCode;
        }
        osAccountInfo.SetPhoto(photo);
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetOsAccountType(const int id, OsAccountType &type)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error, errCode %{public}d.", errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    type = osAccountInfo.GetType();
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetOsAccountProfilePhoto(const int id, std::string &photo)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = QueryOsAccountById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("QueryOsAccountById return error, errCode %{public}d.", errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    photo = osAccountInfo.GetPhoto();
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::IsMultiOsAccountEnable(bool &isMultiOsAccountEnable)
{
    ErrCode errCode = osAccountControl_->GetIsMultiOsAccountEnable(isMultiOsAccountEnable);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetIsMultiOsAccountEnable error, errCode %{public}d.", errCode);
        return errCode;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SetOsAccountName(const int id, const std::string &name)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error, errCode %{public}d.", errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }

    // to be removed, cannot change any thing
    if (osAccountInfo.GetToBeRemoved()) {
        ACCOUNT_LOGE("account %{public}d will be removed, cannot change name!", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR;
    }

    std::string localName = osAccountInfo.GetLocalName();
    if (localName == name) {
        return ERR_OK;
    }

    osAccountInfo.SetLocalName(name);
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("update osaccount info error %{public}d, id: %{public}d", errCode, osAccountInfo.GetLocalId());
        return ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }
    OsAccountInterface::PublishCommonEvent(
        osAccountInfo, OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_INFO_UPDATED, Constants::OPERATION_UPDATE);
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SetOsAccountConstraints(
    const int id, const std::vector<std::string> &constraints, const bool enable)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error, errCode %{public}d.", errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }

    // to be removed, cannot change any thing
    if (osAccountInfo.GetToBeRemoved()) {
        ACCOUNT_LOGE("account %{public}d will be removed, cannot change constraints!", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR;
    }

    bool isExists = false;
    bool isOverSize = false;
    errCode = osAccountControl_->CheckConstraintsList(constraints, isExists, isOverSize);
    if (errCode != ERR_OK || !isExists || isOverSize) {
        ACCOUNT_LOGE("input constraints not in constraints list or is oversize!");
        return ERR_OSACCOUNT_SERVICE_INNER_SER_CONSTRAINTS_ERROR;
    }
    std::vector<std::string> oldConstraints = osAccountInfo.GetConstraints();
    for (auto it = constraints.begin(); it != constraints.end(); it++) {
        if (enable) {
            if (std::find(oldConstraints.begin(), oldConstraints.end(), *it) == oldConstraints.end()) {
                oldConstraints.push_back(*it);
            }
        } else {
            oldConstraints.erase(
                std::remove(oldConstraints.begin(), oldConstraints.end(), *it), oldConstraints.end());
        }
    }
    osAccountInfo.SetConstraints(oldConstraints);
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("update osaccount info error %{public}d, id: %{public}d", errCode, osAccountInfo.GetLocalId());
        return ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SetOsAccountProfilePhoto(const int id, const std::string &photo)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error, errCode %{public}d.", errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }

    // to be removed, cannot change any thing
    if (osAccountInfo.GetToBeRemoved()) {
        ACCOUNT_LOGE("account %{public}d will be removed, cannot change photo!", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR;
    }

    if (osAccountInfo.GetPhoto() == photo) {
        return ERR_OK;
    }
    errCode = osAccountControl_->SetPhotoById(id, photo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("set photo by id error, errCode %{public}d.", errCode);
        return errCode;
    }
    auto sizeType = photo.find(Constants::USER_PHOTO_BASE_JPG_HEAD);
    if (sizeType == std::string::npos) {
        osAccountInfo.SetPhoto(Constants::USER_PHOTO_FILE_PNG_NAME);
    } else {
        osAccountInfo.SetPhoto(Constants::USER_PHOTO_FILE_JPG_NAME);
    }
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("update osaccount info error %{public}d, id: %{public}d", errCode, osAccountInfo.GetLocalId());
        return ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }
    OsAccountInterface::PublishCommonEvent(
        osAccountInfo, OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_INFO_UPDATED, Constants::OPERATION_UPDATE);
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::DeActivateOsAccount(const int id)
{
    if (id == Constants::ADMIN_LOCAL_ID) {
        ACCOUNT_LOGI("this osaccount can't deactive, id: %{public}d", Constants::ADMIN_LOCAL_ID);
        return ERR_OK;
    }
#ifdef ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
    if (id == Constants::START_USER_ID) {
        ACCOUNT_LOGI("this osaccount can't deactive, id: %{public}d", Constants::START_USER_ID);
        return ERR_OK;
    }
#endif // ENABLE_MULTIPLE_ACTIVE_ACCOUNTS

    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("DeActivateOsAccount cannot get os account %{public}d info. error %{public}d.",
            id, errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_CANNOT_FIND_OSACCOUNT_ERROR;
    }
    osAccountInfo.SetIsActived(false);
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("update %{public}d account info failed, errCode %{public}d.",
            osAccountInfo.GetLocalId(), errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }
#ifdef ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
    EraseIdFromActiveList(osAccountInfo.GetLocalId());
#endif // ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::ActivateOsAccount(const int id)
{
    if (IsLocalIdInOperating(id)) {
        ACCOUNT_LOGE("the %{public}d already in operating", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_OPERATING_ERROR;
    }
    AddLocalIdToOperating(id);
    if (IsOsAccountIDInActiveList(id)) {
        RemoveLocalIdToOperating(id);
        ACCOUNT_LOGE("account is %{public}d already active", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_ALREADY_ACTIVE_ERROR;
    }

    // get information
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        RemoveLocalIdToOperating(id);
        ACCOUNT_LOGE("cannot find os account info by id:%{public}d, errCode %{public}d.", id, errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }

    // check complete
    if (!osAccountInfo.GetIsCreateCompleted()) {
        RemoveLocalIdToOperating(id);
        ACCOUNT_LOGE("account %{public}d is not completed", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_IS_UNVERIFIED_ERROR;
    }

    // check to be removed
    if (osAccountInfo.GetToBeRemoved()) {
        RemoveLocalIdToOperating(id);
        ACCOUNT_LOGE("account %{public}d will be removed, cannot be activated!", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR;
    }

    // activate
    subscribeManagerPtr_->PublishActivatingOsAccount(id);
    errCode = SendMsgForAccountActivate(osAccountInfo);
    if (errCode != ERR_OK) {
        RemoveLocalIdToOperating(id);
        ACCOUNT_LOGE("update %{public}d account info failed, errCode %{public}d.", id, errCode);
        return errCode;
    }
    RemoveLocalIdToOperating(id);
    subscribeManagerPtr_->PublishActivatedOsAccount(id);
    ACCOUNT_LOGI("IInnerOsAccountManager ActivateOsAccount end");
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SendMsgForAccountActivate(OsAccountInfo &osAccountInfo)
{
    ErrCode errCode = OsAccountInterface::SendToStorageAccountStart(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("account %{public}d call storage active failed, errCode %{public}d.",
            osAccountInfo.GetLocalId(), errCode);
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_START_ERROR;
    }
    errCode = OsAccountInterface::SendToAMSAccountStart(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("account %{public}d call ams active failed, errCode %{public}d.",
            osAccountInfo.GetLocalId(), errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_SEND_AM_ACCOUNT_SWITCH_ERROR;
    }
    // update info
    osAccountInfo.SetIsActived(true);
    int64_t time =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    osAccountInfo.SetLastLoginTime(time);
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("update %{public}d account info failed, errCode %{public}d.",
            osAccountInfo.GetLocalId(), errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }
    RefreshActiveList(osAccountInfo.GetLocalId());
    OsAccountInterface::SendToCESAccountSwitched(osAccountInfo);
    ACCOUNT_LOGI("SendMsgForAccountActivate ok");
    return errCode;
}

ErrCode IInnerOsAccountManager::StartOsAccount(const int id)
{
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::StopOsAccount(const int id)
{
#ifdef ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
    if (id == Constants::START_USER_ID) {
        ACCOUNT_LOGW("the %{public}d os account can't stop", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_STOP_ACTIVE_ERROR;
    }

    if (IsLocalIdInOperating(id)) {
        ACCOUNT_LOGW("the %{public}d already in operating", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_OPERATING_ERROR;
    }
    AddLocalIdToOperating(id);
    if (!IsOsAccountIDInActiveList(id)) {
        RemoveLocalIdToOperating(id);
        ACCOUNT_LOGW("account is %{public}d already stop", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_ALREADY_ACTIVE_ERROR;
    }
    // get information
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        RemoveLocalIdToOperating(id);
        ACCOUNT_LOGW("cannot find os account info by id:%{public}d, errCode %{public}d.", id, errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }

     // check complete
    if (!osAccountInfo.GetIsCreateCompleted()) {
        RemoveLocalIdToOperating(id);
        ACCOUNT_LOGW("account %{public}d is not completed", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_IS_UNVERIFIED_ERROR;
    }

     // check to be removed
    if (osAccountInfo.GetToBeRemoved()) {
        RemoveLocalIdToOperating(id);
        ACCOUNT_LOGW("account %{public}d will be removed, don't need to stop!", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR;
    }

    // stop
    errCode = SendMsgForAccountStop(osAccountInfo);
    if (errCode != ERR_OK) {
        RemoveLocalIdToOperating(id);
        ACCOUNT_LOGE("update %{public}d account info failed, errCode %{public}d.", id, errCode);
        return errCode;
    }
    RemoveLocalIdToOperating(id);
    ACCOUNT_LOGI("IInnerOsAccountManager ActivateOsAccount end");
#endif // ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetOsAccountLocalIdBySerialNumber(const int64_t serialNumber, int &id)
{
    if (serialNumber ==
        Constants::CARRY_NUM * Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN + Constants::ADMIN_LOCAL_ID) {
        id = Constants::ADMIN_LOCAL_ID;
        return ERR_OK;
    }
    std::vector<OsAccountInfo> osAccountInfos;
    id = -1;
    ErrCode errCode = osAccountControl_->GetOsAccountList(osAccountInfos);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info list error");
        return ERR_OSACCOUNT_SERVICE_INNER_GET_ACCOUNT_LIST_ERROR;
    }
    for (auto it = osAccountInfos.begin(); it != osAccountInfos.end(); it++) {
        if (serialNumber == it->GetSerialNumber()) {
            id = it->GetLocalId();
            break;
        }
    }
    if (id == -1) {
        ACCOUNT_LOGE("cannot find id by serialNumber");
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetSerialNumberByOsAccountLocalId(const int &id, int64_t &serialNumber)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    serialNumber = osAccountInfo.GetSerialNumber();
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SubscribeOsAccount(
    const OsAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener)
{
    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("subscribeManagerPtr_ is nullptr");
        return ERR_OSACCOUNT_SERVICE_SUBSCRIBE_MANAGER_PTR_IS_NULLPTR;
    }

    auto subscribeInfoPtr = std::make_shared<OsAccountSubscribeInfo>(subscribeInfo);
    if (subscribeInfoPtr == nullptr) {
        ACCOUNT_LOGE("subscribeInfoPtr is nullptr");
    }
    return subscribeManagerPtr_->SubscribeOsAccount(subscribeInfoPtr, eventListener);
}

ErrCode IInnerOsAccountManager::UnsubscribeOsAccount(const sptr<IRemoteObject> &eventListener)
{
    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_OSACCOUNT_SERVICE_SUBSCRIBE_MANAGER_PTR_IS_NULLPTR;
    }
    return subscribeManagerPtr_->UnsubscribeOsAccount(eventListener);
}

OS_ACCOUNT_SWITCH_MOD IInnerOsAccountManager::GetOsAccountSwitchMod()
{
    return Constants::NOW_OS_ACCOUNT_SWITCH_MOD;
}

ErrCode IInnerOsAccountManager::IsOsAccountCompleted(const int id, bool &isOsAccountCompleted)
{
    OsAccountInfo osAccountInfo;
    (void)osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    isOsAccountCompleted = osAccountInfo.GetIsCreateCompleted();
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SetOsAccountIsVerified(const int id, const bool isVerified)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error, errCode %{public}d.", errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }

    // to be removed, cannot change any thing
    if (osAccountInfo.GetToBeRemoved()) {
        ACCOUNT_LOGE("account %{public}d will be removed, cannot change verify state!", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR;
    }

    if (isVerified && !osAccountInfo.GetIsVerified()) {
        OsAccountInterface::PublishCommonEvent(osAccountInfo,
            OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED, Constants::OPERATION_UNLOCK);
    }

    osAccountInfo.SetIsVerified(isVerified);
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("update osaccount info error %{public}d, id: %{public}d",
            errCode, osAccountInfo.GetLocalId());
        return ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetEventHandler(void)
{
    if (!handler_) {
        handler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(OHOS::AppExecFwk::EventRunner::Create());
        if (handler_ == nullptr) {
            ACCOUNT_LOGE("failed to create event handler");
            return ERR_OSACCOUNT_SERVICE_CREATE_EVENT_HANDLER;
        }
    }

    return ERR_OK;
}

ErrCode IInnerOsAccountManager::IsAllowedCreateAdmin(bool &isAllowedCreateAdmin)
{
    return osAccountControl_->IsAllowedCreateAdmin(isAllowedCreateAdmin);
}

ErrCode IInnerOsAccountManager::GetCreatedOsAccountNumFromDatabase(const std::string& storeID,
    int &createdOsAccountNum)
{
    return osAccountControl_->GetCreatedOsAccountNumFromDatabase(storeID, createdOsAccountNum);
}

ErrCode IInnerOsAccountManager::GetSerialNumberFromDatabase(const std::string& storeID,
    int64_t &serialNumber)
{
    return osAccountControl_->GetSerialNumberFromDatabase(storeID, serialNumber);
}

ErrCode IInnerOsAccountManager::GetMaxAllowCreateIdFromDatabase(const std::string& storeID, int &id)
{
    return osAccountControl_->GetMaxAllowCreateIdFromDatabase(storeID, id);
}

ErrCode IInnerOsAccountManager::GetOsAccountFromDatabase(const std::string& storeID, const int id,
    OsAccountInfo &osAccountInfo)
{
    return osAccountControl_->GetOsAccountFromDatabase(storeID, id, osAccountInfo);
}

ErrCode IInnerOsAccountManager::GetOsAccountListFromDatabase(const std::string& storeID,
    std::vector<OsAccountInfo> &osAccountList)
{
    return osAccountControl_->GetOsAccountListFromDatabase(storeID, osAccountList);
}

void IInnerOsAccountManager::AddLocalIdToOperating(int32_t localId)
{
    std::lock_guard<std::mutex> lock(operatingMutex_);
    operatingId_.push_back(localId);
}

void IInnerOsAccountManager::RemoveLocalIdToOperating(int32_t localId)
{
    std::lock_guard<std::mutex> lock(operatingMutex_);
    auto it = std::find(operatingId_.begin(), operatingId_.end(), localId);
    if (it != operatingId_.end()) {
        operatingId_.erase(it);
    }
}

bool IInnerOsAccountManager::IsLocalIdInOperating(int32_t localId)
{
    std::lock_guard<std::mutex> lock(operatingMutex_);
    return std::find(operatingId_.begin(), operatingId_.end(), localId) != operatingId_.end();
}

ErrCode IInnerOsAccountManager::QueryActiveOsAccountIds(std::vector<int32_t>& ids)
{
    CopyFromActiveList(ids);
    return ERR_OK;
}

void IInnerOsAccountManager::PushIdIntoActiveList(int32_t id)
{
    std::lock_guard<std::mutex> lock(ativeMutex_);
    if (std::find(activeAccountId_.begin(), activeAccountId_.end(), id) == activeAccountId_.end()) {
        activeAccountId_.push_back(id);
        CountTrace(HITRACE_TAG_ACCOUNT_MANAGER, "activeId", (int64_t)id);
    }
    return;
}

void IInnerOsAccountManager::EraseIdFromActiveList(int32_t id)
{
    std::lock_guard<std::mutex> lock(ativeMutex_);
    if (std::find(activeAccountId_.begin(), activeAccountId_.end(), id) != activeAccountId_.end()) {
        ACCOUNT_LOGE("EraseIdFromActiveList enter0");
        activeAccountId_.erase(
            std::remove(activeAccountId_.begin(), activeAccountId_.end(), id), activeAccountId_.end());
    } else {
        ACCOUNT_LOGI("os account is not in active list, no need to erase!");
    }
    CountTrace(HITRACE_TAG_ACCOUNT_MANAGER, "deActiveId", (int64_t)id);
}

bool IInnerOsAccountManager::IsOsAccountIDInActiveList(int32_t id)
{
    std::lock_guard<std::mutex> lock(ativeMutex_);
    auto it = std::find(activeAccountId_.begin(), activeAccountId_.end(), id);
    return (it != activeAccountId_.end());
}

void IInnerOsAccountManager::CopyFromActiveList(std::vector<int32_t>& idList)
{
    idList.clear();
    std::lock_guard<std::mutex> lock(ativeMutex_);
    for (auto it = activeAccountId_.begin(); it != activeAccountId_.end(); it++) {
        idList.push_back(*it);
    }
}

void IInnerOsAccountManager::RefreshActiveList(int32_t newId)
{
#ifdef ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
    PushIdIntoActiveList(newId);
    return;
#endif // ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
    // deactivate old ids first
    for (size_t i = 0; i < activeAccountId_.size(); ++i) {
        DeActivateOsAccount(activeAccountId_[i]);
    }
    int32_t oldId = (activeAccountId_.empty() ? -1 : activeAccountId_[0]);
    ReportOsAccountSwitch(newId, oldId);
    activeAccountId_.clear();
    PushIdIntoActiveList(newId);
}
}  // namespace AccountSA
}  // namespace OHOS
