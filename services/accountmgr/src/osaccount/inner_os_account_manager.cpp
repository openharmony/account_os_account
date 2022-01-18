/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
    activeAccountId_.clear();
    osAccountControl_ = std::make_shared<OsAccountControlFileManager>();
    osAccountControl_->Init();
    ACCOUNT_LOGE("OsAccountAccountMgr Init end");
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
        osAccountControl_->InsertOsAccount(osAccountInfo);
    }
    {
        std::lock_guard<std::mutex> lock(ativeMutex_);
        activeAccountId_.push_back(Constants::ADMIN_LOCAL_ID);
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
    }
}

void IInnerOsAccountManager::StartAccount()
{
    GetEventHandler();
    OHOS::AppExecFwk::InnerEvent::Callback callbackStartStandard =
        std::bind(&IInnerOsAccountManager::StartBaseStandardAccount, this);
    handler_->PostTask(callbackStartStandard, DELAY_FOR_FOUNDATION_SERVICE);
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
    bool isAccountExists = false;
    osAccountControl_->IsOsAccountExists(Constants::START_USER_ID, isAccountExists);
    if (!isAccountExists) {
        return;
    }
    OsAccountInfo osAccountInfo;
    osAccountControl_->GetOsAccountInfoById(Constants::START_USER_ID, osAccountInfo);
    if (!osAccountInfo.GetIsCreateCompleted()) {
        ErrCode errCode = OsAccountStandardInterface::SendToBMSAccountCreate(osAccountInfo);
        if (errCode != ERR_OK) {
            if (++counterForStandard_ == MAX_TRY_TIMES) {
                ACCOUNT_LOGE("failed connect BMS");
            } else {
                GetEventHandler();
                OHOS::AppExecFwk::InnerEvent::Callback callback =
                    std::bind(&IInnerOsAccountManager::StartBaseStandardAccount, this);
                handler_->PostTask(callback, DELAY_FOR_TIME_INTERVAL);
            }
            return;
        } else {
            counterForStandard_ = 0;
            osAccountInfo.SetIsCreateCompleted(true);
            osAccountControl_->UpdateOsAccount(osAccountInfo);
        }
    }
    osAccountControl_->GetOsAccountInfoById(Constants::START_USER_ID, osAccountInfo);
    if (osAccountInfo.GetIsCreateCompleted()) {
        ErrCode errCode = OsAccountStandardInterface::SendToAMSAccountStart(osAccountInfo);
        if (errCode != ERR_OK) {
            if (++counterForStandard_ == MAX_TRY_TIMES) {
                ACCOUNT_LOGE("failed connect BMS");
            } else {
                GetEventHandler();
                OHOS::AppExecFwk::InnerEvent::Callback callback =
                    std::bind(&IInnerOsAccountManager::StartBaseStandardAccount, this);
                handler_->PostTask(callback, DELAY_FOR_TIME_INTERVAL);
            }
        } else {
            {
                osAccountInfo.SetIsActived(true);
                int64_t time = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                osAccountInfo.SetLastLoginTime(time);
                osAccountControl_->UpdateOsAccount(osAccountInfo);
                std::lock_guard<std::mutex> lock(ativeMutex_);
                activeAccountId_.push_back(Constants::START_USER_ID);
            }
            OsAccountStandardInterface::SendToCESAccountCreate(osAccountInfo);
        }
    }
    ResetActiveStatus();
}

ErrCode IInnerOsAccountManager::PrepareOsAccountInfo(const std::string &name, const OsAccountType &type,
    const DomainAccountInfo &domainInfo, OsAccountInfo &osAccountInfo)
{
    int64_t serialNumber;
    ErrCode errCode = osAccountControl_->GetSerialNumber(serialNumber);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_GET_SERIAL_NUMBER_ERROR;
    }
    int id = 0;
    errCode = osAccountControl_->GetAllowCreateId(id);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_GET_OSACCOUNT_ID_ERROR;
    }
    std::vector<std::string> constraints;
    constraints.clear();
    errCode = osAccountControl_->GetConstraintsByType(type, constraints);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_GET_TTPE_CONSTRAINTS_ERROR;
    }
    osAccountInfo = OsAccountInfo(id, name, type, serialNumber);
    osAccountInfo.SetConstraints(constraints);
    int64_t time =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    osAccountInfo.SetCreateTime(time);
    if (!osAccountInfo.SetDomainInfo(domainInfo)) {
        return ERR_OS_ACCOUNT_KIT_CREATE_OS_ACCOUNT_FOR_DOMAIN_ERROR;
    }

    errCode = osAccountControl_->InsertOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("insert osaccountinfo err");
        return ERR_OS_ACCOUNT_SERVICE_INNER_CREATE_ACCOUNT_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SendMsgForAccountCreate(OsAccountInfo &osAccountInfo)
{
    ErrCode errCode = OsAccountStandardInterface::SendToBMSAccountCreate(osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SEND_BM_ACCOUNT_CREATE_ERROR;
    }

    osAccountInfo.SetIsCreateCompleted(true);
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }

    errCode = OsAccountStandardInterface::SendToCESAccountCreate(osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SEND_CE_ACCOUNT_CREATE_ERROR;
    }
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
            ACCOUNT_LOGE("domain account %{public}s %{public}s has already been bound to os account %{public}d.",
                domainInfo.accountName_.c_str(), domainInfo.accountName_.c_str(), osAccountInfos[i].GetLocalId());
            return ERR_OS_ACCOUNT_SERVICE_INNER_DOMAIN_ALREADY_BIND_ERROR;
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
    ACCOUNT_LOGE("IInnerOsAccountManager RemoveOsAccount delete id is %{public}d", id);
    bool isActived = false;
    {
        std::lock_guard<std::mutex> lock(ativeMutex_);
        auto it = std::find(activeAccountId_.begin(), activeAccountId_.end(), id);
        if (it != activeAccountId_.end()) {
            ACCOUNT_LOGE("RemoveOsAccount find active id in list.");
            isActived = true;
        }
    }
    if (isActived) {
        ACCOUNT_LOGE("RemoveOsAccount start to stop active account %{public}d.", id);
        ErrCode activeErrCode = ActivateOsAccount(Constants::START_USER_ID);
        if (activeErrCode != ERR_OK) {
            return ERR_OS_ACCOUNT_SERVICE_INNER_REMOVE_ACCOUNT_ACTIVED_ERROR;
        }
    }
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_CANNOT_FIND_OSACCOUNT_ERROR;
    }
    errCode = OsAccountStandardInterface::SendToAMSAccountStop(osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SEND_AM_ACCOUNT_STOP_ERROR;
    }
    errCode = OsAccountStandardInterface::SendToBMSAccountDelete(osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SEND_BM_ACCOUNT_DELE_ERROR;
    }
    errCode = osAccountControl_->DelOsAccount(id);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_CANNOT_DELE_OSACCOUNT_ERROR;
    }
    errCode = OsAccountStandardInterface::SendToCESAccountDelete(osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SEND_CE_ACCOUNT_DELE_ERROR;
    }
    ACCOUNT_LOGE("IInnerOsAccountManager RemoveOsAccount end");
    return ERR_OK;
}

void IInnerOsAccountManager::Init()
{
    CreateBaseAdminAccount();
    CreateBaseStandardAccount();
    StartAccount();
}

ErrCode IInnerOsAccountManager::IsOsAccountExists(const int id, bool &isOsAccountExits)
{
    isOsAccountExits = false;
    osAccountControl_->IsOsAccountExists(id, isOsAccountExits);
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::IsOsAccountActived(const int id, bool &isOsAccountActived)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        isOsAccountActived = false;
        return ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    std::lock_guard<std::mutex> lock(ativeMutex_);
    if (std::find(activeAccountId_.begin(), activeAccountId_.end(), id) != activeAccountId_.end()) {
        isOsAccountActived = true;
    } else {
        isOsAccountActived = false;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::IsOsAccountConstraintEnable(
    const int id, const std::string &constraint, bool &isOsAccountConstraintEnable)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
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
        return ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    isVerified = osAccountInfo.GetIsVerified();
    ACCOUNT_LOGE("IInnerOsAccountManager IsOsAccountVerified isVerified is %{public}d", isVerified);
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetCreatedOsAccountsCount(int &createdOsAccountCount)
{
    std::vector<OsAccountInfo> osAccountInfos;
    ErrCode errCode = osAccountControl_->GetOsAccountList(osAccountInfos);
    if (errCode != ERR_OK) {
        return errCode;
    }
    createdOsAccountCount = osAccountInfos.size();
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::QueryMaxOsAccountNumber(int &maxOsAccountNumber)
{
    ErrCode errCode = osAccountControl_->GetMaxCreatedOsAccountNum(maxOsAccountNumber);
    if (errCode != ERR_OK) {
        return errCode;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    constraints = osAccountInfo.GetConstraints();
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos)
{
    ErrCode errCode = osAccountControl_->GetOsAccountList(osAccountInfos);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_GET_ALL_OSACCOUNTINFO_ERROR;
    }
    std::lock_guard<std::mutex> lock(ativeMutex_);
    for (auto osAccountInfosPtr = osAccountInfos.begin(); osAccountInfosPtr != osAccountInfos.end();
         ++osAccountInfosPtr) {
        auto it = std::find(activeAccountId_.begin(), activeAccountId_.end(), osAccountInfosPtr->GetLocalId());
        if (it != activeAccountId_.end()) {
            osAccountInfosPtr->SetIsActived(true);
        }
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetOsAccountLocalIdFromDomain(const DomainAccountInfo &domainInfo, int &id)
{
    if (domainInfo.domain_.empty() ||
        domainInfo.domain_.size() > Constants::DOMAIN_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("invalid domain name length %{public}zu.", domainInfo.domain_.size());
        return ERR_OS_ACCOUNT_SERVICE_INNER_DOMAIN_NAME_LEN_ERROR;
    }

    if (domainInfo.accountName_.empty() ||
        domainInfo.accountName_.size() > Constants::DOMAIN_ACCOUNT_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("invalid domain account name length %{public}zu.", domainInfo.accountName_.size());
        return ERR_OS_ACCOUNT_SERVICE_INNER_DOMAIN_ACCOUNT_NAME_LEN_ERROR;
    }

    id = -1;
    std::vector<OsAccountInfo> osAccountInfos;
    ErrCode errCode = osAccountControl_->GetOsAccountList(osAccountInfos);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_GET_ALL_OSACCOUNTINFO_ERROR;
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
    ACCOUNT_LOGI("cannot find domain %{public}s  domain account %{public}s in local accounts.",
        domainInfo.domain_.c_str(), domainInfo.accountName_.c_str());
    return ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_LOCAL_ID_FOR_DOMAIN_ERROR;
}

ErrCode IInnerOsAccountManager::QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGE("IInnerOsAccountManager QueryOsAccountById start");
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    {
        std::lock_guard<std::mutex> lock(ativeMutex_);
        auto it = std::find(activeAccountId_.begin(), activeAccountId_.end(), id);
        if (it != activeAccountId_.end()) {
            ACCOUNT_LOGE("IInnerOsAccountManager QueryOsAccountById activeAccountId_ start loop it is %{public}d", *it);
            osAccountInfo.SetIsActived(true);
        }
    }
    if (osAccountInfo.GetPhoto() != "") {
        std::string photo = osAccountInfo.GetPhoto();
        errCode = osAccountControl_->GetPhotoById(osAccountInfo.GetLocalId(), photo);
        if (errCode != ERR_OK) {
            return errCode;
        }
        osAccountInfo.SetPhoto(photo);
    }
    ACCOUNT_LOGE("IInnerOsAccountManager QueryOsAccountById end");
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetOsAccountType(const int id, OsAccountType &type)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    type = osAccountInfo.GetType();
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetOsAccountProfilePhoto(const int id, std::string &photo)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = QueryOsAccountById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    photo = osAccountInfo.GetPhoto();
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::IsMultiOsAccountEnable(bool &isMultiOsAccountEnable)
{
    ErrCode errCode = osAccountControl_->GetIsMultiOsAccountEnable(isMultiOsAccountEnable);
    if (errCode != ERR_OK) {
        return errCode;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SetOsAccountName(const int id, const std::string &name)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    osAccountInfo.SetLocalName(name);
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SetOsAccountConstraints(
    const int id, const std::vector<std::string> &constraints, const bool enable)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    bool isExists = false;
    errCode = osAccountControl_->IsConstrarionsInTypeList(constraints, isExists);
    if (errCode != ERR_OK || !isExists) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SER_CONSTRAINTS_ERROR;
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
        return ERR_OS_ACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SetOsAccountProfilePhoto(const int id, const std::string &photo)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    errCode = osAccountControl_->SetPhotoById(id, photo);
    if (errCode != ERR_OK) {
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
        return ERR_OS_ACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
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
    {
        std::lock_guard<std::mutex> lock(ativeMutex_);
        if (std::find(activeAccountId_.begin(), activeAccountId_.end(), id) != activeAccountId_.end()) {
            ACCOUNT_LOGE("account is %{public}d already active", id);
            return ERR_OS_ACCOUNT_SERVICE_INNER_ACCOUNT_ALREAD_ACTIVE_ERROR;
        }
    }
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("cannot find os account info by id:%{public}d", id);
        return ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    if (!osAccountInfo.GetIsCreateCompleted()) {
        ACCOUNT_LOGE("account %{public}d is not Completed", id);
        return ERR_OS_ACCOUNT_SERVICE_INNER_ACCOUNT_IS_UNVERIFIED_ERROR;
    }
    subscribeManagerPtr_->PublicActivatingOsAccount(id);
    errCode = OsAccountStandardInterface::SendToAMSAccountStart(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("account %{public}d call am active failed", id);
        return ERR_OS_ACCOUNT_SERVICE_INNER_SEND_AM_ACCOUNT_SWITCH_ERROR;
    }
    errCode = OsAccountStandardInterface::SendToCESAccountSwithced(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("account %{public}d call ce active failed", id);
        return ERR_OS_ACCOUNT_SERVICE_INNER_SEND_CE_ACCOUNT_SWITCH_ERROR;
    }

    // update info
    osAccountInfo.SetIsActived(true);
    int64_t time =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    osAccountInfo.SetLastLoginTime(time);
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("update %{public}d account info failed", id);
        return ERR_OS_ACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }

    {
        std::lock_guard<std::mutex> lock(ativeMutex_);
        for (size_t i = 0; i < activeAccountId_.size(); ++i) {
            DeActivateOsAccount(activeAccountId_[i]);
        }
        activeAccountId_.clear();
        activeAccountId_.push_back(Constants::ADMIN_LOCAL_ID);
        activeAccountId_.push_back(id);
    }
    subscribeManagerPtr_->PublicActivatedOsAccount(id);
    ACCOUNT_LOGE("IInnerOsAccountManager ActivateOsAccount end");
    return ERR_OK;
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
        return ERR_OS_ACCOUNT_SERVICE_INNER_GET_ALL_OSACCOUNTINFO_ERROR;
    }
    for (auto it = osAccountInfos.begin(); it != osAccountInfos.end(); it++) {
        if (serialNumber == it->GetSerialNumber()) {
            id = it->GetLocalId();
        }
    }
    if (id == -1) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetSerialNumberByOsAccountLocalId(const int &id, int64_t &serialNumber)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    serialNumber = osAccountInfo.GetSerialNumber();
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SubscribeOsAccount(
    const OsAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGE("IInnerOsAccountManager SubscribeOsAccount start");

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("IInnerOsAccountManager SubscribeOsAccount subscribeManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_SUBSCRIBE_MANAGER_PTR_IS_NULLPTR;
    }

    auto subscribeInfoPtr = std::make_shared<OsAccountSubscribeInfo>(subscribeInfo);
    if (subscribeInfoPtr == nullptr) {
        ACCOUNT_LOGE("IInnerOsAccountManager SubscribeOsAccount subscribeInfoPtr is nullptr");
    }
    ACCOUNT_LOGE("IInnerOsAccountManager SubscribeOsAccount end");
    return subscribeManagerPtr_->SubscribeOsAccount(subscribeInfoPtr, eventListener);
}

ErrCode IInnerOsAccountManager::UnsubscribeOsAccount(const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGE("IInnerOsAccountManager UnsubscribeOsAccount start");

    if (!subscribeManagerPtr_) {
        ACCOUNT_LOGE("controlManagerPtr_ is nullptr");
        return ERR_APPACCOUNT_SERVICE_SUBSCRIBE_MANAGER_PTR_IS_NULLPTR;
    }
    ACCOUNT_LOGE("IInnerOsAccountManager UnsubscribeOsAccount end");
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
        return ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    isOsAccountCompleted = osAccountInfo.GetIsCreateCompleted();
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SetOsAccountIsVerified(const int id, const bool isVerified)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    osAccountInfo.SetIsVerified(isVerified);
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetEventHandler(void)
{
    ACCOUNT_LOGI("enter");

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
}  // namespace AccountSA
}  // namespace OHOS
