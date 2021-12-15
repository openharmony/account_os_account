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
#include "account_log_wrapper.h"
#include "ohos_account_kits.h"
#include "os_account_constants.h"
#include "os_account_control_file_manager.h"
#include "os_account_subscribe_manager.h"

#include "iinner_os_account_manager.h"
namespace OHOS {
namespace AccountSA {
IInnerOsAccountManager::IInnerOsAccountManager() : subscribeManagerPtr_(OsAccountSubscribeManager::GetInstance())
{
    counter_ = 0;
    activeAccountId_.clear();
    osAccountControl_ = std::make_shared<OsAccountControlFileManager>();
    osAccountControl_->Init();
    Init();
    ACCOUNT_LOGE("OsAccountAccountMgr Init ed");
}
IInnerOsAccountManager::~IInnerOsAccountManager()
{}
void IInnerOsAccountManager::CreateBaseAdminAccount()
{
    bool isExistsAccount = false;
    osAccountControl_->IsOsAccountExists(Constants::ADMIN_LOCAL_ID, isExistsAccount);
    if (!isExistsAccount) {
        int64_t serialNumber =
            Constants::CARRY_NUM * Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN + Constants::ADMIN_LOCAL_ID;
        OsAccountInfo osAccountInfo(
            Constants::ADMIN_LOCAL_ID, Constants::ADMIN_LOCAL_NAME, Constants::ADMIN_TYPE, serialNumber);
        int64_t time =
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
                .count();
        osAccountInfo.SetCreateTime(time);
        osAccountInfo.SetIsAccountCompleted(true);
        std::vector<OsAccountInfo> osAccountInfos;
        osAccountInfos.clear();
        osAccountInfos.push_back(osAccountInfo);
        osAccountControl_->InsertOsAccount(osAccountInfo);
    }
    activeAccountId_.push_back(Constants::ADMIN_LOCAL_ID);
}
void IInnerOsAccountManager::CreateBaseStandardAccount()
{
    bool isExistsAccount = false;
    osAccountControl_->IsOsAccountExists(Constants::START_USER_ID, isExistsAccount);
    if (!isExistsAccount) {
        int64_t serialNumber =
            Constants::CARRY_NUM * Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN + Constants::START_USER_ID;
        OsAccountInfo osAccountInfo(
            Constants::START_USER_ID, Constants::STANDARD_LOCAL_NAME, Constants::STANDARD_TYPE, serialNumber);
        std::vector<std::string> constants;
        ErrCode errCode = osAccountControl_->GetConstraintsByType(Constants::STANDARD_TYPE, constants);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("find first standard type err");
        } else {
            osAccountInfo.SetConstraints(constants);
        }
        int64_t time =
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
                .count();
        osAccountInfo.SetCreateTime(time);
        osAccountInfo.SetIsAccountCompleted(false);
        osAccountControl_->InsertOsAccount(osAccountInfo);
    }
    activeAccountId_.push_back(Constants::START_USER_ID);
    GetEventHandler();
    OHOS::AppExecFwk::InnerEvent::Callback callback = std::bind(&IInnerOsAccountManager::StartBaseAccount, this);
    handler_->PostTask(callback, DELAY_FOR_FOUNDATION_SERVICE);
}

ErrCode IInnerOsAccountManager::CreateOsAccount(
    const std::string &name, const int &type, OsAccountInfo &osAccountInfo)
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
    std::vector<std::string> constants;
    constants.clear();
    errCode = osAccountControl_->GetConstraintsByType(type, constants);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_GET_TTPE_CONSTRAINTS_ERROR;
    }
    osAccountInfo = OsAccountInfo(id, name, type, serialNumber);
    osAccountInfo.SetConstraints(constants);
    int64_t time =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    osAccountInfo.SetCreateTime(time);
    errCode = osAccountControl_->InsertOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("insert osaccountinfo err");
        return ERR_OS_ACCOUNT_SERVICE_INNER_CREATE_ACCOUNT_ERROR;
    }
    std::vector<OsAccountInfo> osAccountInfos;
    osAccountInfos.push_back(osAccountInfo);
    errCode = OsAccountStandardInterface::SendToBMSAccountCreate(osAccountInfos);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SEND_BM_ACCOUNT_CREATE_ERROR;
    }
    errCode = OsAccountStandardInterface::SendToCESAccountCreate(osAccountInfos);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SEND_CE_ACCOUNT_CREATE_ERROR;
    }
    osAccountInfo.SetIsAccountCompleted(true);
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::RemoveOsAccount(const int id)
{
    ACCOUNT_LOGE("IInnerOsAccountManager RemoveOsAccount delete id is %{public}d", id);
    auto it = std::find(activeAccountId_.begin(), activeAccountId_.end(), id);
    if (it != activeAccountId_.end()) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_REMOVE_ACCOUNT_ACTIVED_ERROR;
    }
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_CANNOT_FIND_OSACCOUNT_ERROR;
    }
    if (osAccountInfo.GetType() <= Constants::STANDARD_TYPE) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_CANNOT_REMOVE_ADMIN_ERROR;
    }
    std::vector<OsAccountInfo> osAccountInfos;
    osAccountInfos.push_back(osAccountInfo);
    errCode = OsAccountStandardInterface::SendToAMSAccountStop(osAccountInfos);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SEND_AM_ACCOUNT_STOP_ERROR;
    }
    errCode = OsAccountStandardInterface::SendToBMSAccountDelete(osAccountInfos);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SEND_BM_ACCOUNT_DELE_ERROR;
    }
    errCode = OsAccountStandardInterface::SendToCESAccountDelete(osAccountInfos);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SEND_CE_ACCOUNT_DELE_ERROR;
    }
    errCode = osAccountControl_->DelOsAccount(id);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_CANNOT_DELE_OSACCOUNT_ERROR;
    }
    ACCOUNT_LOGE("IInnerOsAccountManager RemoveOsAccount end");
    return ERR_OK;
}
void IInnerOsAccountManager::Init()
{
    CreateBaseAdminAccount();
    ACCOUNT_LOGE("OsAccountAccountMgr CreateBaseAdminAccount ed ");
    CreateBaseStandardAccount();
    ACCOUNT_LOGE("OsAccountAccountMgr CreateBaseStandardAccount ed ");
}

ErrCode IInnerOsAccountManager::IsOsAccountExists(const int id, bool &isOsAccountExits)
{
    isOsAccountExits = false;
    osAccountControl_->IsOsAccountExists(id, isOsAccountExits);
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::IsOsAccountActived(const int id, bool &isOsAccountActived)
{
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

ErrCode IInnerOsAccountManager::IsOsAccountVerified(const int id, bool &isOsAccountVerified)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    isOsAccountVerified = osAccountInfo.GetIsAccountVerified();
    ACCOUNT_LOGE("IInnerOsAccountManager IsOsAccountVerified isOsAccountVerified is %{public}d", isOsAccountVerified);
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetCreatedOsAccountsCount(int &createdOsAccountCount)
{
    ErrCode errCode = osAccountControl_->GetMaxCreatedOsAccountNum(createdOsAccountCount);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::QueryMaxOsAccountNumber(int &maxOsAccountNumber)
{
    maxOsAccountNumber = Constants::MAX_USER_ID;
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
    for (auto osAccountInfosPtr = osAccountInfos.begin(); osAccountInfosPtr != osAccountInfos.end();
         ++osAccountInfosPtr) {
        auto it = std::find(activeAccountId_.begin(), activeAccountId_.end(), osAccountInfosPtr->GetId());
        if (it != activeAccountId_.end()) {
            osAccountInfosPtr->SetIsActived(true);
        }
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGE("IInnerOsAccountManager QueryOsAccountById start");
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    auto it = std::find(activeAccountId_.begin(), activeAccountId_.end(), id);
    if (it != activeAccountId_.end()) {
        ACCOUNT_LOGE("IInnerOsAccountManager QueryOsAccountById activeAccountId_ start loop it is %{public}d", *it);
        osAccountInfo.SetIsActived(true);
    }
    if (osAccountInfo.GetPhoto() != "") {
        std::string photo = osAccountInfo.GetPhoto();
        errCode = osAccountControl_->GetPhotoById(osAccountInfo.GetId(), photo);
        if (errCode != ERR_OK) {
            return errCode;
        }
        osAccountInfo.SetPhoto(photo);
    }
    ACCOUNT_LOGE("IInnerOsAccountManager QueryOsAccountById end");
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetOsAccountType(const int id, int &type)
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
    if (photo == "") {
        return ERR_OS_ACCOUNT_SERVICE_INNER_DONNOT_HAVE_PHOTO_ERROR;
    }
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
    osAccountInfo.SetName(name);
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
    std::vector<std::string> oldconstraints = osAccountInfo.GetConstraints();
    if (enable) {
        for (auto it = constraints.begin(); it != constraints.end(); it++) {
            if (std::find(oldconstraints.begin(), oldconstraints.end(), *it) == oldconstraints.end()) {
                oldconstraints.push_back(*it);
            }
        }
    } else {
        std::find_if(constraints.begin(), constraints.end(), [&oldconstraints](std::string constraint) {
            oldconstraints.erase(
                std::remove(oldconstraints.begin(), oldconstraints.end(), constraint), oldconstraints.end());
            return false;
        });
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

ErrCode IInnerOsAccountManager::GetDistributedVirtualDeviceId(std::int32_t &deviceId, std::int32_t uid)
{
    deviceId = OhosAccountKits::GetInstance().GetDeviceAccountIdByUID(uid);
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::ActivateOsAccount(const int id)
{
    if (std::find(activeAccountId_.begin(), activeAccountId_.end(), id) != activeAccountId_.end()) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_ACCOUNT_ALREAD_ACTIVE_ERROR;
    }
    ACCOUNT_LOGE("IInnerOsAccountManager ActivateOsAccount had find id");
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    if (!osAccountInfo.GetIsAccountCompleted()) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_ACCOUNT_IS_UNVERIFIED_ERROR;
    }
    subscribeManagerPtr_->PublicActivatingOsAccount(id);
    ACCOUNT_LOGE("IInnerOsAccountManager ActivateOsAccount had find os account info");
    std::vector<OsAccountInfo> osAccountInfos;
    osAccountInfos.push_back(osAccountInfo);
    errCode = OsAccountStandardInterface::SendToAMSAccountStart(osAccountInfos);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SEND_AM_ACCOUNT_START_ERROR;
    }
    errCode = OsAccountStandardInterface::SendToCESAccountStart(osAccountInfos);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SEND_CE_ACCOUNT_START_ERROR;
    }
    osAccountInfos.clear();
    for (auto it = activeAccountId_.begin(); it != activeAccountId_.end(); ++it) {
        if (*it == Constants::ADMIN_LOCAL_ID) {
            continue;
        }
        OsAccountInfo osAccountInfoForStop;
        errCode = osAccountControl_->GetOsAccountInfoById(*it, osAccountInfoForStop);
        if (errCode == ERR_OK) {
            osAccountInfos.push_back(osAccountInfoForStop);
        }
    }
    activeAccountId_.clear();
    activeAccountId_.push_back(Constants::ADMIN_LOCAL_ID);
    ACCOUNT_LOGE("IInnerOsAccountManager ActivateOsAccount out of loop");
    errCode = OsAccountStandardInterface::SendToAMSAccountStop(osAccountInfos);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SEND_AM_ACCOUNT_STOP_ERROR;
    }
    errCode = OsAccountStandardInterface::SendToCESAccountStop(osAccountInfos);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SEND_CE_ACCOUNT_STOP_ERROR;
    }
    activeAccountId_.push_back(id);
    subscribeManagerPtr_->PublicActivatedOsAccount(id);
    ACCOUNT_LOGE("IInnerOsAccountManager ActivateOsAccount end");
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::StartOsAccount(const int id)
{
    if (std::find(activeAccountId_.begin(), activeAccountId_.end(), id) != activeAccountId_.end()) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_ACCOUNT_ALREAD_ACTIVE_ERROR;
    }
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    if (!osAccountInfo.GetIsAccountCompleted()) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_ACCOUNT_IS_UNVERIFIED_ERROR;
    }
    subscribeManagerPtr_->PublicActivatingOsAccount(id);
    std::vector<OsAccountInfo> osAccountInfos;
    osAccountInfos.push_back(osAccountInfo);
    errCode = OsAccountStandardInterface::SendToAMSAccountStart(osAccountInfos);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SEND_AM_ACCOUNT_START_ERROR;
    }
    errCode = OsAccountStandardInterface::SendToCESAccountStart(osAccountInfos);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SEND_CE_ACCOUNT_START_ERROR;
    }
    activeAccountId_.push_back(id);
    subscribeManagerPtr_->PublicActivatedOsAccount(id);
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::StopOsAccount(const int id)
{
    ACCOUNT_LOGE("IInnerOsAccountManager StopOsAccount active ids is %{public}d", id);
    auto stopIt = std::find(activeAccountId_.begin(), activeAccountId_.end(), id);
    if (stopIt == activeAccountId_.end()) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_ACCOUNT_STOP_ACTIVE_ERROR;
    }
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    std::vector<OsAccountInfo> osAccountInfos;
    osAccountInfos.push_back(osAccountInfo);
    errCode = OsAccountStandardInterface::SendToAMSAccountStop(osAccountInfos);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SEND_AM_ACCOUNT_STOP_ERROR;
    }
    errCode = OsAccountStandardInterface::SendToCESAccountStop(osAccountInfos);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SEND_CE_ACCOUNT_STOP_ERROR;
    }
    auto it = std::find(activeAccountId_.begin(), activeAccountId_.end(), id);
    activeAccountId_.erase(it);
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetOsAccountLocalIdBySerialNumber(const int64_t serialNumber, int &id)
{
    std::vector<OsAccountInfo> osAccountInfos;
    id = -1;
    ErrCode errCode = osAccountControl_->GetOsAccountList(osAccountInfos);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_GET_ALL_OSACCOUNTINFO_ERROR;
    }
    for (auto it = osAccountInfos.begin(); it != osAccountInfos.end(); it++) {
        if (serialNumber == it->GetSerialNumber()) {
            id = it->GetId();
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
void IInnerOsAccountManager::StartBaseAccount(void)
{
    std::vector<OsAccountInfo> osAccountInfos;
    OsAccountInfo osAccountInfo;
    osAccountControl_->GetOsAccountInfoById(Constants::START_USER_ID, osAccountInfo);
    if (!osAccountInfo.GetIsAccountCompleted()) {
        osAccountInfos.push_back(osAccountInfo);
        ErrCode errCode = OsAccountStandardInterface::SendToBMSAccountCreate(osAccountInfos);
        if (errCode != ERR_OK) {
            counter_++;
            if (counter_ == MAX_TRY_TIMES) {
                ACCOUNT_LOGE("failed connect BMS");
            } else {
                GetEventHandler();
                OHOS::AppExecFwk::InnerEvent::Callback callback =
                    std::bind(&IInnerOsAccountManager::StartBaseAccount, this);
                handler_->PostTask(callback, DELAY_FOR_TIME_INTERVAL);
            }
            return;
        } else {
            counter_ = 0;
            osAccountInfo.SetIsAccountCompleted(true);
            osAccountControl_->UpdateOsAccount(osAccountInfo);
        }
    }
    osAccountControl_->GetOsAccountInfoById(Constants::START_USER_ID, osAccountInfo);
    if (osAccountInfo.GetIsAccountCompleted()) {
        osAccountInfos.clear();
        osAccountInfos.push_back(osAccountInfo);
        ErrCode errCode = OsAccountStandardInterface::SendToAMSAccountStart(osAccountInfos);
        if (errCode != ERR_OK) {
            counter_++;
            if (counter_ == MAX_TRY_TIMES) {
                ACCOUNT_LOGE("failed connect BMS");
            } else {
                GetEventHandler();
                OHOS::AppExecFwk::InnerEvent::Callback callback =
                    std::bind(&IInnerOsAccountManager::StartBaseAccount, this);
                handler_->PostTask(callback, DELAY_FOR_TIME_INTERVAL);
            }
        }
    }
}

ErrCode IInnerOsAccountManager::IsOsAccountCompleted(const int id, bool &isOsAccountCompleted)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    isOsAccountCompleted = osAccountInfo.GetIsAccountCompleted();
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SetOsAccountIsVerified(const int id, const bool isOsAccountVerified)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR;
    }
    osAccountInfo.SetIsAccountVerified(isOsAccountVerified);
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
}  // namespace AccountSA
}  // namespace OHOS
