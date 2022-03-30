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
#include "iinner_os_account_manager.h"
#include "account_log_wrapper.h"
#include "ohos_account_kits.h"
#include "os_account_constants.h"
#include "os_account_control_file_manager.h"
#include "os_account_subscribe_manager.h"

namespace OHOS {
namespace AccountSA {
IInnerOsAccountManager::IInnerOsAccountManager() : subscribeManagerPtr_(OsAccountSubscribeManager::GetInstance())
{
    counterForStandard_ = 0;
    counterForStandardCreate_ = 0;
    isSendToStorageCreate_ = false;
    isSendToStorageStart_ = false;
    activeAccountId_.clear();
    operatingId_.clear();
    osAccountControl_ = std::make_shared<OsAccountControlFileManager>();
    osAccountControl_->Init();
    ACCOUNT_LOGI("OsAccountAccountMgr Init end");
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
            ACCOUNT_LOGE("find first standard type err");
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
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(Constants::START_USER_ID, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("OsAccountAccountMgr init start base account failed. cannot find account");
        return;
    }
    ResetActiveStatus();
    GetEventHandler();
    if (!osAccountInfo.GetIsCreateCompleted()) {
        ACCOUNT_LOGI("OsAccountAccountMgr send to storage and bm for start");
        OHOS::AppExecFwk::InnerEvent::Callback callbackStartStandard =
            std::bind(&IInnerOsAccountManager::CreateBaseStandardAccountSendToOther, this);
        handler_->PostTask(callbackStartStandard, DELAY_FOR_FOUNDATION_SERVICE);
    }
    ACCOUNT_LOGI("OsAccountAccountMgr send to storage and am for start");
    OHOS::AppExecFwk::InnerEvent::Callback callbackStartStandard =
        std::bind(&IInnerOsAccountManager::StartBaseStandardAccount, this);
    handler_->PostTask(callbackStartStandard, DELAY_FOR_FOUNDATION_SERVICE);
}

void IInnerOsAccountManager::CreateBaseStandardAccountSendToOther(void)
{
    OsAccountInfo osAccountInfo;
    if (!isSendToStorageCreate_) {
        osAccountControl_->GetOsAccountInfoById(Constants::START_USER_ID, osAccountInfo);
        ErrCode errCode = OsAccountStandardInterface::SendToStorageAccountCreate(osAccountInfo);
        if (errCode != ERR_OK) {
            if (++counterForStandardCreate_ == MAX_TRY_TIMES) {
                ACCOUNT_LOGE("failed connect storage to create account");
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
    ErrCode errCodeForBM = OsAccountStandardInterface::SendToBMSAccountCreate(osAccountInfo);
    if (errCodeForBM != ERR_OK) {
        if (++counterForStandardCreate_ == MAX_TRY_TIMES) {
            ACCOUNT_LOGE("failed connect BM to create account");
        } else {
            GetEventHandler();
            OHOS::AppExecFwk::InnerEvent::Callback callback =
                std::bind(&IInnerOsAccountManager::CreateBaseStandardAccountSendToOther, this);
            handler_->PostTask(callback, DELAY_FOR_TIME_INTERVAL);
        }
        return;
    } else {
        osAccountInfo.SetIsCreateCompleted(true);
        osAccountControl_->UpdateOsAccount(osAccountInfo);
        ACCOUNT_LOGI("connect BM to create account ok");
    }
}

void IInnerOsAccountManager::ResetActiveStatus(void)
{
    std::vector<OsAccountInfo> osAccountInfos;
    if (QueryAllCreatedOsAccounts(osAccountInfos) != ERR_OK) {
        return;
    }
    for (size_t i = 0; i < osAccountInfos.size(); ++i) {
        if (osAccountInfos[i].GetLocalId() == Constants::START_USER_ID) {
            continue;
        }
        osAccountInfos[i].SetIsActived(false);
        osAccountControl_->UpdateOsAccount(osAccountInfos[i]);
    }
}

void IInnerOsAccountManager::StartBaseStandardAccount(void)
{
    OsAccountInfo osAccountInfo;
    osAccountControl_->GetOsAccountInfoById(Constants::START_USER_ID, osAccountInfo);
    if (!osAccountInfo.GetIsCreateCompleted()) {
        ++counterForStandard_;
        GetEventHandler();
        OHOS::AppExecFwk::InnerEvent::Callback callback =
            std::bind(&IInnerOsAccountManager::StartBaseStandardAccount, this);
        handler_->PostTask(callback, DELAY_FOR_TIME_INTERVAL);
        return;
    }
    if (!isSendToStorageStart_) {
        ErrCode errCode = OsAccountStandardInterface::SendToStorageAccountStart(osAccountInfo);
        if (errCode != ERR_OK) {
            if (++counterForStandard_ == MAX_TRY_TIMES) {
                ACCOUNT_LOGE("failed connect storage to start account");
            } else {
                GetEventHandler();
                OHOS::AppExecFwk::InnerEvent::Callback callback =
                    std::bind(&IInnerOsAccountManager::StartBaseStandardAccount, this);
                handler_->PostTask(callback, DELAY_FOR_TIME_INTERVAL);
            }
            return;
        }
        ACCOUNT_LOGI("connect storage to start account ok");
        counterForStandard_ = 0;
        isSendToStorageStart_ = true;
    }
    ErrCode errCodeForAM = OsAccountStandardInterface::SendToAMSAccountStart(osAccountInfo);
    if (errCodeForAM != ERR_OK) {
        if (++counterForStandard_ == MAX_TRY_TIMES) {
            ACCOUNT_LOGE("failed connect AM to start account");
        } else {
            GetEventHandler();
            OHOS::AppExecFwk::InnerEvent::Callback callback =
                std::bind(&IInnerOsAccountManager::StartBaseStandardAccount, this);
            handler_->PostTask(callback, DELAY_FOR_TIME_INTERVAL);
        }
        return;
    }
    osAccountInfo.SetIsActived(true);
    int64_t time = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    osAccountInfo.SetLastLoginTime(time);
    osAccountControl_->UpdateOsAccount(osAccountInfo);
    PushIDIntoActiveList(Constants::START_USER_ID);
    subscribeManagerPtr_->PublishActivatedOsAccount(Constants::START_USER_ID);
    OsAccountStandardInterface::SendToCESAccountSwitched(osAccountInfo);
    ACCOUNT_LOGI("connect AM to start account ok");
}

ErrCode IInnerOsAccountManager::PrepareOsAccountInfo(const std::string &name, const OsAccountType &type,
    const DomainAccountInfo &domainInfo, OsAccountInfo &osAccountInfo)
{
    int64_t serialNumber;
    ErrCode errCode = osAccountControl_->GetSerialNumber(serialNumber);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("failed to GetSerialNumber");
        return ERR_OSACCOUNT_SERVICE_INNER_GET_SERIAL_NUMBER_ERROR;
    }
    int id = 0;
    errCode = osAccountControl_->GetAllowCreateId(id);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("failed to GetAllowCreateId");
        return ERR_OSACCOUNT_SERVICE_INNER_GET_OSACCOUNT_ID_ERROR;
    }
    std::vector<std::string> constraints;
    constraints.clear();
    errCode = osAccountControl_->GetConstraintsByType(type, constraints);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("failed to GetConstraintsByType");
        return ERR_OSACCOUNT_SERVICE_INNER_GET_TTPE_CONSTRAINTS_ERROR;
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
        ACCOUNT_LOGE("insert osaccountinfo err");
        return ERR_OSACCOUNT_SERVICE_INNER_CREATE_ACCOUNT_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SendMsgForAccountCreate(OsAccountInfo &osAccountInfo)
{
    ErrCode errCode = OsAccountStandardInterface::SendToStorageAccountCreate(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("create os account SendToStorageAccountCreate failed");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_CREATE_ERROR;
    }
    errCode = OsAccountStandardInterface::SendToBMSAccountCreate(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("create os account SendToBMSAccountCreate failed");
        return ERR_OSACCOUNT_SERVICE_INNER_SEND_BM_ACCOUNT_CREATE_ERROR;
    }

    osAccountInfo.SetIsCreateCompleted(true);
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("create os account when update isCreateComplated");
        return ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }

    OsAccountStandardInterface::SendToCESAccountCreate(osAccountInfo);
    ACCOUNT_LOGI("send other subsystem to create os account ok");
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
    if (IsOsAccountIDInActiveList(id)) {
        ACCOUNT_LOGI("RemoveOsAccount started account to inactive, account id : %{public}d.", id);
        ErrCode activeErrCode = ActivateOsAccount(Constants::START_USER_ID);
        if (activeErrCode != ERR_OK) {
            RemoveLocalIdToOperating(id);
            ACCOUNT_LOGE("RemoveOsAccount active base account failed");
            return ERR_OSACCOUNT_SERVICE_INNER_REMOVE_ACCOUNT_ACTIVED_ERROR;
        }
    }
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        RemoveLocalIdToOperating(id);
        ACCOUNT_LOGE("RemoveOsAccount cannot find os account info");
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
    ACCOUNT_LOGI("IInnerOsAccountManager RemoveOsAccount end");
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SendMsgForAccountStop(OsAccountInfo &osAccountInfo)
{
    ErrCode errCode = OsAccountStandardInterface::SendToAMSAccountStop(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("SendToAMSAccountStop failed, id %{public}d, errCode %{public}d",
            osAccountInfo.GetLocalId(), errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_SEND_AM_ACCOUNT_STOP_ERROR;
    }
    errCode = OsAccountStandardInterface::SendToStorageAccountStop(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("SendToStorageAccountStop failed, id %{public}d, errCode %{public}d",
            osAccountInfo.GetLocalId(), errCode);
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_STOP_ERROR;
    }
    return errCode;
}

ErrCode IInnerOsAccountManager::SendMsgForAccountRemove(OsAccountInfo &osAccountInfo)
{
    ErrCode errCode = OsAccountStandardInterface::SendToBMSAccountDelete(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("SendToBMSAccountDelete failed, id %{public}d, errCode %{public}d",
            osAccountInfo.GetLocalId(), errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_SEND_BM_ACCOUNT_DELE_ERROR;
    }
    errCode = OsAccountStandardInterface::SendToStorageAccountRemove(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("SendToStorageAccountRemove failed, id %{public}d, errCode %{public}d",
            osAccountInfo.GetLocalId(), errCode);
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_REMOVE_ERROR;
    }
#ifdef HAS_USER_IDM_PART
    errCode = OsAccountStandardInterface::SendToIDMAccountDelete(osAccountInfo);
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
        return ERR_OSACCOUNT_SERVICE_INNER_CANNOT_DELE_OSACCOUNT_ERROR;
    }
    OsAccountStandardInterface::SendToCESAccountDelete(osAccountInfo);
    return errCode;
}

void IInnerOsAccountManager::Init()
{
    CreateBaseAdminAccount();
    CreateBaseStandardAccount();
    StartAccount();
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
        ACCOUNT_LOGE("get osaccount info error");
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
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error");
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    std::vector<std::string> constraints = osAccountInfo.GetConstraints();
    if (std::find(constraints.begin(), constraints.end(), constraint) != constraints.end()) {
        isOsAccountConstraintEnable = true;
    } else {
        isOsAccountConstraintEnable = false;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::IsOsAccountVerified(const int id, bool &isVerified)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error");
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
        ACCOUNT_LOGE("get osaccount info list error");
        return errCode;
    }
    createdOsAccountCount = osAccountInfos.size();
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::QueryMaxOsAccountNumber(int &maxOsAccountNumber)
{
    ErrCode errCode = osAccountControl_->GetMaxCreatedOsAccountNum(maxOsAccountNumber);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get max created osaccount num error");
        return errCode;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error");
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    constraints = osAccountInfo.GetConstraints();
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos)
{
    ErrCode errCode = osAccountControl_->GetOsAccountList(osAccountInfos);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info list error");
        return ERR_OSACCOUNT_SERVICE_INNER_GET_ALL_OSACCOUNTINFO_ERROR;
    }
    for (auto osAccountInfosPtr = osAccountInfos.begin(); osAccountInfosPtr != osAccountInfos.end();
         ++osAccountInfosPtr) {
        if (IsOsAccountIDInActiveList(osAccountInfosPtr->GetLocalId())) {
            osAccountInfosPtr->SetIsActived(true);
        } else {
            osAccountInfosPtr->SetIsActived(false);
        }
    }
    return ERR_OK;
}

void IInnerOsAccountManager::CleanGarbageAccounts()
{
    ACCOUNT_LOGI("enter.");
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
        return ERR_OSACCOUNT_SERVICE_INNER_GET_ALL_OSACCOUNTINFO_ERROR;
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
        ACCOUNT_LOGE("get osaccount info error");
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
            ACCOUNT_LOGE("get osaccount photo error");
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
        ACCOUNT_LOGE("get osaccount info error");
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
        ACCOUNT_LOGE("QueryOsAccountById return error");
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    photo = osAccountInfo.GetPhoto();
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::IsMultiOsAccountEnable(bool &isMultiOsAccountEnable)
{
    ErrCode errCode = osAccountControl_->GetIsMultiOsAccountEnable(isMultiOsAccountEnable);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetIsMultiOsAccountEnable error");
        return errCode;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SetOsAccountName(const int id, const std::string &name)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error");
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }

    // to be removed, cannot change any thing
    if (osAccountInfo.GetToBeRemoved()) {
        ACCOUNT_LOGE("account %{public}d will be removed, cannot change name!", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR;
    }

    osAccountInfo.SetLocalName(name);
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("update osaccount info error,id: %{public}d", osAccountInfo.GetLocalId());
        return ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SetOsAccountConstraints(
    const int id, const std::vector<std::string> &constraints, const bool enable)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error");
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }

    // to be removed, cannot change any thing
    if (osAccountInfo.GetToBeRemoved()) {
        ACCOUNT_LOGE("account %{public}d will be removed, cannot change constraints!", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR;
    }

    bool isExists = false;
    errCode = osAccountControl_->IsConstrarionsInTypeList(constraints, isExists);
    if (errCode != ERR_OK || !isExists) {
        ACCOUNT_LOGE("input constraints not in constraints list");
        return ERR_OSACCOUNT_SERVICE_INNER_SER_CONSTRAINTS_ERROR;
    }
    std::vector<std::string> oldconstraints = osAccountInfo.GetConstraints();
    for (auto it = constraints.begin(); it != constraints.end(); it++) {
        if (enable) {
            if (std::find(oldconstraints.begin(), oldconstraints.end(), *it) == oldconstraints.end()) {
                oldconstraints.push_back(*it);
            }
        } else {
            oldconstraints.erase(
                std::remove(oldconstraints.begin(), oldconstraints.end(), *it), oldconstraints.end());
        }
    }
    osAccountInfo.SetConstraints(oldconstraints);
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("update osaccount info error,id: %{public}d", osAccountInfo.GetLocalId());
        return ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SetOsAccountProfilePhoto(const int id, const std::string &photo)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error");
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }

    // to be removed, cannot change any thing
    if (osAccountInfo.GetToBeRemoved()) {
        ACCOUNT_LOGE("account %{public}d will be removed, cannot change photo!", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR;
    }

    errCode = osAccountControl_->SetPhotoById(id, photo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("set photo by id error");
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
        ACCOUNT_LOGE("update osaccount info error,id: %{public}d", osAccountInfo.GetLocalId());
        return ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }
    return ERR_OK;
}

void IInnerOsAccountManager::DeActivateOsAccount(const int id)
{
    if (id == Constants::ADMIN_LOCAL_ID) {
        return;
    }

    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("DeActivateOsAccount cannot get os account %{public}d info. error %{public}d.",
            id, errCode);
        return;
    }
    osAccountInfo.SetIsActived(false);
    (void)osAccountControl_->UpdateOsAccount(osAccountInfo);
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
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_ALREAD_ACTIVE_ERROR;
    }

    // get information
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        RemoveLocalIdToOperating(id);
        ACCOUNT_LOGE("cannot find os account info by id:%{public}d", id);
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }

    // check complete
    if (!osAccountInfo.GetIsCreateCompleted()) {
        RemoveLocalIdToOperating(id);
        ACCOUNT_LOGE("account %{public}d is not Completed", id);
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
        ACCOUNT_LOGE("update %{public}d account info failed", id);
        return errCode;
    }
    RemoveLocalIdToOperating(id);
    subscribeManagerPtr_->PublishActivatedOsAccount(id);
    ACCOUNT_LOGI("IInnerOsAccountManager ActivateOsAccount end");
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SendMsgForAccountActivate(OsAccountInfo &osAccountInfo)
{
    ErrCode errCode = OsAccountStandardInterface::SendToStorageAccountStart(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("account %{public}d call storage active failed", osAccountInfo.GetLocalId());
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_START_ERROR;
    }
    errCode = OsAccountStandardInterface::SendToAMSAccountStart(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("account %{public}d call am active failed", osAccountInfo.GetLocalId());
        return ERR_OSACCOUNT_SERVICE_INNER_SEND_AM_ACCOUNT_SWITCH_ERROR;
    }
    // update info
    osAccountInfo.SetIsActived(true);
    int64_t time =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    osAccountInfo.SetLastLoginTime(time);
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("update %{public}d account info failed", osAccountInfo.GetLocalId());
        return ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }
    RefreshActiveList(osAccountInfo.GetLocalId());
    OsAccountStandardInterface::SendToCESAccountSwitched(osAccountInfo);
    ACCOUNT_LOGI("SendMsgForAccountActivate ok");
    return errCode;
}

ErrCode IInnerOsAccountManager::StartOsAccount(const int id)
{
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::StopOsAccount(const int id)
{
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
        return ERR_OSACCOUNT_SERVICE_INNER_GET_ALL_OSACCOUNTINFO_ERROR;
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
    ACCOUNT_LOGI("IInnerOsAccountManager SubscribeOsAccount start");

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("IInnerOsAccountManager SubscribeOsAccount subscribeManagerPtr_ is nullptr");
        return ERR_OSACCOUNT_SERVICE_SUBSCRIBE_MANAGER_PTR_IS_NULLPTR;
    }

    auto subscribeInfoPtr = std::make_shared<OsAccountSubscribeInfo>(subscribeInfo);
    if (subscribeInfoPtr == nullptr) {
        ACCOUNT_LOGE("IInnerOsAccountManager SubscribeOsAccount subscribeInfoPtr is nullptr");
    }
    ACCOUNT_LOGI("IInnerOsAccountManager SubscribeOsAccount end");
    return subscribeManagerPtr_->SubscribeOsAccount(subscribeInfoPtr, eventListener);
}

ErrCode IInnerOsAccountManager::UnsubscribeOsAccount(const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("IInnerOsAccountManager UnsubscribeOsAccount start");

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_OSACCOUNT_SERVICE_SUBSCRIBE_MANAGER_PTR_IS_NULLPTR;
    }
    ACCOUNT_LOGI("IInnerOsAccountManager UnsubscribeOsAccount end");
    return subscribeManagerPtr_->UnsubscribeOsAccount(eventListener);
}

OS_ACCOUNT_SWITCH_MOD IInnerOsAccountManager::GetOsAccountSwitchMod()
{
    return Constants::NOW_OS_ACCOUNT_SWITCH_MOD;
}

ErrCode IInnerOsAccountManager::IsOsAccountCompleted(const int id, bool &isOsAccountCompleted)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error");
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    isOsAccountCompleted = osAccountInfo.GetIsCreateCompleted();
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SetOsAccountIsVerified(const int id, const bool isVerified)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error");
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }

    // to be removed, cannot change any thing
    if (osAccountInfo.GetToBeRemoved()) {
        ACCOUNT_LOGE("account %{public}d will be removed, cannot change verify state!", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR;
    }

    osAccountInfo.SetIsVerified(isVerified);
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("update osaccount info error,id: %{public}d", osAccountInfo.GetLocalId());
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

void IInnerOsAccountManager::PushIDIntoActiveList(int32_t id)
{
    std::lock_guard<std::mutex> lock(ativeMutex_);
    activeAccountId_.push_back(id);
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
    std::lock_guard<std::mutex> lock(ativeMutex_);

    // deactivate old ids first
    for (size_t i = 0; i < activeAccountId_.size(); ++i) {
        DeActivateOsAccount(activeAccountId_[i]);
    }

    activeAccountId_.clear();
    activeAccountId_.push_back(newId);
}
}  // namespace AccountSA
}  // namespace OHOS
