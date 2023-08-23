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
#include "account_event_provider.h"
#include "account_info.h"
#include "account_info_report.h"
#include "account_log_wrapper.h"
#ifdef HAS_CES_PART
#include "common_event_support.h"
#endif // HAS_CES_PART
#include "domain_account_callback_service.h"
#include "hitrace_adapter.h"
#include "hisysevent_adapter.h"
#include "ohos_account_kits.h"
#include "os_account_constants.h"
#include "os_account_control_file_manager.h"
#include "os_account_domain_account_callback.h"
#include "os_account_subscribe_manager.h"
#include "parameter.h"
#include "parcel.h"
#include <pthread.h>
#include <thread>

namespace OHOS {
namespace AccountSA {
namespace {
const std::string CONSTRAINT_CREATE_ACCOUNT_DIRECTLY = "constraint.os.account.create.directly";
const std::string ACCOUNT_READY_EVENT = "bootevent.account.ready";
const char WATCH_START_USER[] = "watch.start.user";
constexpr std::int32_t DELAY_FOR_ACCOUNT_BOOT_EVENT_READY = 5000;
}

IInnerOsAccountManager::IInnerOsAccountManager() : subscribeManager_(OsAccountSubscribeManager::GetInstance())
{
    activeAccountId_.clear();
    operatingId_.clear();
    osAccountControl_ = std::make_shared<OsAccountControlFileManager>();
    osAccountControl_->Init();
    osAccountControl_->GetDeviceOwnerId(deviceOwnerId_);
    osAccountControl_->GetDefaultActivatedOsAccount(defaultActivatedId_);
    ACCOUNT_LOGD("OsAccountAccountMgr Init end");
}

IInnerOsAccountManager &IInnerOsAccountManager::GetInstance()
{
    static IInnerOsAccountManager *instance = new (std::nothrow) IInnerOsAccountManager();
    return *instance;
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
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(defaultActivatedId_, osAccountInfo);
    if (errCode != ERR_OK) {
        if (defaultActivatedId_ == Constants::START_USER_ID) {
            ACCOUNT_LOGE("Init start base account failed. cannot find account, errCode %{public}d.", errCode);
            return;
        }
        ACCOUNT_LOGE("Init startup account %{public}d failed, errCode %{public}d. And restart base account.",
            defaultActivatedId_, errCode);
        errCode = osAccountControl_->GetOsAccountInfoById(Constants::START_USER_ID, osAccountInfo);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("Restart base account failed. cannot find account, errCode %{public}d.", errCode);
            return;
        }
        osAccountControl_->SetDefaultActivatedOsAccount(Constants::START_USER_ID);
        defaultActivatedId_ = Constants::START_USER_ID;
    }
    auto task = std::bind(&IInnerOsAccountManager::WatchStartUser, this, osAccountInfo.GetLocalId());
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), WATCH_START_USER);
    taskThread.detach();
    if (!osAccountInfo.GetIsCreateCompleted()) {
        if (SendMsgForAccountCreate(osAccountInfo) != ERR_OK) {
            return;
        }
    }
    // activate
    if (SendMsgForAccountActivate(osAccountInfo) != ERR_OK) {
        return;
    }
    subscribeManager_.PublishActivatedOsAccount(osAccountInfo.GetLocalId());
    ACCOUNT_LOGI("OsAccountAccountMgr send to storage and am for start success");
}

void IInnerOsAccountManager::RestartActiveAccount()
{
    // query active account to restart and refresh into list
    std::vector<OsAccountInfo> osAccountInfos;
    if (QueryAllCreatedOsAccounts(osAccountInfos) != ERR_OK) {
        return;
    }
    for (size_t i = 0; i < osAccountInfos.size(); ++i) {
        OsAccountInfo osAccountInfo = osAccountInfos[i];
        std::int32_t id = osAccountInfo.GetLocalId();
        if (osAccountInfo.GetIsActived() && id != Constants::START_USER_ID) {
            // reactivate account state
            if (ActivateOsAccount(id) != ERR_OK) {
                ACCOUNT_LOGE("active base account failed");
                return;
            }
        }
    }
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

ErrCode IInnerOsAccountManager::PrepareOsAccountInfo(const std::string &name, const OsAccountType &type,
    const DomainAccountInfo &domainInfo, OsAccountInfo &osAccountInfo)
{
    int64_t serialNumber;
    ErrCode errCode = osAccountControl_->GetSerialNumber(serialNumber);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("failed to GetSerialNumber, errCode %{public}d.", errCode);
        return errCode;
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
        return errCode;
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
        return errCode;
    }
    errCode = osAccountControl_->UpdateBaseOAConstraints(std::to_string(id), constraints, true);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("UpdateBaseOAConstraints err");
        return errCode;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SendMsgForAccountCreate(OsAccountInfo &osAccountInfo)
{
    ErrCode errCode = OsAccountInterface::SendToStorageAccountCreate(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("create os account SendToStorageAccountCreate failed, errCode %{public}d.", errCode);
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    errCode = OsAccountInterface::SendToBMSAccountCreate(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("create os account SendToBMSAccountCreate failed, errCode %{public}d.", errCode);
        (void)OsAccountInterface::SendToStorageAccountRemove(osAccountInfo);
        return errCode;
    }

    osAccountInfo.SetIsCreateCompleted(true);
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("create os account when update isCreateCompleted");
        ReportOsAccountOperationFail(
            osAccountInfo.GetLocalId(), Constants::OPERATION_CREATE, errCode, "UpdateOsAccount failed!");
        (void)OsAccountInterface::SendToStorageAccountRemove(osAccountInfo);
        (void)OsAccountInterface::SendToBMSAccountDelete(osAccountInfo);
        return ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }
    ReportOsAccountLifeCycle(osAccountInfo.GetLocalId(), Constants::OPERATION_CREATE);
    OsAccountInterface::SendToCESAccountCreate(osAccountInfo);
    ACCOUNT_LOGI("OsAccountAccountMgr send to storage and bm for start success");
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
    errCode = SendMsgForAccountCreate(osAccountInfo);
    if (errCode != ERR_OK) {
        (void)osAccountControl_->DelOsAccount(osAccountInfo.GetLocalId());
    }
    return errCode;
}

bool IInnerOsAccountManager::CheckDomainAccountBound(
    const std::vector<OsAccountInfo> &osAccountInfos, const DomainAccountInfo &info)
{
    for (size_t i = 0; i < osAccountInfos.size(); ++i) {
        DomainAccountInfo curInfo;
        osAccountInfos[i].GetDomainInfo(curInfo);
        if ((!info.accountId_.empty() && curInfo.accountId_ == info.accountId_) ||
            ((curInfo.accountName_ == info.accountName_) && (curInfo.domain_ == info.domain_))) {
            return true;
        }
    }
    return false;
}

ErrCode IInnerOsAccountManager::BindDomainAccount(const OsAccountType &type, const DomainAccountInfo &domainAccountInfo,
    const sptr<IDomainAccountCallback> &callback)
{
    std::vector<OsAccountInfo> osAccountInfos;
    (void)QueryAllCreatedOsAccounts(osAccountInfos);
    if (CheckDomainAccountBound(osAccountInfos, domainAccountInfo)) {
        ACCOUNT_LOGE("the domain account is already bound");
        return ERR_OSACCOUNT_SERVICE_INNER_DOMAIN_ALREADY_BIND_ERROR;
    }
    bool isEnabled = false;
    (void)IsOsAccountConstraintEnable(Constants::START_USER_ID, CONSTRAINT_CREATE_ACCOUNT_DIRECTLY, isEnabled);
    std::string osAccountName = domainAccountInfo.domain_ + "/" + domainAccountInfo.accountName_;
    OsAccountInfo osAccountInfo;
    if (isEnabled && (osAccountInfos.size() == 1) && (osAccountInfos[0].GetLocalId() == Constants::START_USER_ID)) {
        DomainAccountInfo curDomainInfo;
        osAccountInfos[0].GetDomainInfo(curDomainInfo);
        if (curDomainInfo.domain_.empty()) {
            osAccountInfos[0].SetLocalName(osAccountName);
            osAccountInfos[0].SetDomainInfo(domainAccountInfo);
            osAccountInfo = osAccountInfos[0];
        }
    }
    if (osAccountInfo.GetLocalId() != Constants::START_USER_ID) {
        ErrCode errCode = PrepareOsAccountInfo(osAccountName, type, domainAccountInfo, osAccountInfo);
        if (errCode != ERR_OK) {
            return errCode;
        }
    }
    auto callbackWrapper = std::make_shared<BindDomainAccountCallback>(domainAccountInfo, osAccountInfo, callback);
    if (callbackWrapper == nullptr) {
        ACCOUNT_LOGE("create BindDomainAccountCallback failed");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    return InnerDomainAccountManager::GetInstance().OnAccountBound(
        domainAccountInfo, osAccountInfo.GetLocalId(), callbackWrapper);
}

ErrCode IInnerOsAccountManager::CreateOsAccountForDomain(
    const OsAccountType &type, const DomainAccountInfo &domainInfo, const sptr<IDomainAccountCallback> &callback)
{
    std::vector<OsAccountInfo> osAccountInfos;
    (void)QueryAllCreatedOsAccounts(osAccountInfos);
    if (CheckDomainAccountBound(osAccountInfos, domainInfo)) {
        ACCOUNT_LOGE("the domain account is already bound");
        return ERR_OSACCOUNT_SERVICE_INNER_DOMAIN_ALREADY_BIND_ERROR;
    }
    if (!InnerDomainAccountManager::GetInstance().IsPluginAvailable()) {
        ACCOUNT_LOGE("plugin is not available");
        return ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST;
    }
    sptr<CheckAndCreateDomainAccountCallback> callbackWrapper =
        new (std::nothrow) CheckAndCreateDomainAccountCallback(type, domainInfo, callback);
    if (callbackWrapper == nullptr) {
        ACCOUNT_LOGE("new DomainCreateDomainCallback failed");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    return InnerDomainAccountManager::GetInstance().GetDomainAccountInfo(domainInfo, callbackWrapper);
}

void IInnerOsAccountManager::CheckAndRefreshLocalIdRecord(const int id)
{
    if (id == defaultActivatedId_) {
        ACCOUNT_LOGI("remove default activated id %{public}d", id);
        osAccountControl_->SetDefaultActivatedOsAccount(Constants::START_USER_ID);
        defaultActivatedId_ = Constants::START_USER_ID;
    }
    if (id == deviceOwnerId_) {
        osAccountControl_->UpdateDeviceOwnerId(-1);
    }
    return;
}

ErrCode IInnerOsAccountManager::RemoveOsAccountOperate(const int id, OsAccountInfo &osAccountInfo,
    const DomainAccountInfo &domainAccountInfo)
{
    AccountInfo ohosInfo;
    (void)OhosAccountManager::GetInstance().GetAccountInfoByUserId(id, ohosInfo);
    ErrCode errCode = SendMsgForAccountRemove(osAccountInfo);
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
    CheckAndRefreshLocalIdRecord(id);
    if (!domainAccountInfo.accountId_.empty()) {
        InnerDomainAccountManager::GetInstance().NotifyDomainAccountEvent(
            id, DomainAccountEvent::LOG_OUT, DomainAccountStatus::LOGOUT, domainAccountInfo);
    }
    if (ohosInfo.ohosAccountInfo_.name_ != DEFAULT_OHOS_ACCOUNT_NAME) {
#ifdef HAS_CES_PART
        AccountEventProvider::EventPublish(EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOUT, id, nullptr);
        AccountEventProvider::EventPublish(
            EventFwk::CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT, id, nullptr);
#else  // HAS_CES_PART
        ACCOUNT_LOGI("No common event part! Publish nothing!");
#endif // HAS_CES_PART
    }
    return errCode;
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
        if (ActivateOsAccount(Constants::START_USER_ID) != ERR_OK) {
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
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    DomainAccountInfo curDomainInfo;
    osAccountInfo.GetDomainInfo(curDomainInfo);
    if (!curDomainInfo.accountId_.empty()) {
        InnerDomainAccountManager::GetInstance().OnAccountUnBound(curDomainInfo, nullptr);
        InnerDomainAccountManager::GetInstance().RemoveTokenFromMap(id);
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
    return RemoveOsAccountOperate(id, osAccountInfo, curDomainInfo);
}

ErrCode IInnerOsAccountManager::SendMsgForAccountStop(OsAccountInfo &osAccountInfo)
{
    ErrCode errCode = OsAccountInterface::SendToAMSAccountStop(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("SendToAMSAccountStop failed, id %{public}d, errCode %{public}d",
            osAccountInfo.GetLocalId(), errCode);
        return errCode;
    }
    errCode = OsAccountInterface::SendToStorageAccountStop(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("SendToStorageAccountStop failed, id %{public}d, errCode %{public}d",
            osAccountInfo.GetLocalId(), errCode);
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
#ifdef ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
    errCode = DeActivateOsAccount(osAccountInfo.GetLocalId());
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("DeActivateOsAccount failed, id %{public}d, errCode %{public}d",
            osAccountInfo.GetLocalId(), errCode);
        return errCode;
    }
#endif // ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
    ACCOUNT_LOGI("SendMsgForAccountStop ok");
    return errCode;
}

ErrCode IInnerOsAccountManager::SendMsgForAccountRemove(OsAccountInfo &osAccountInfo)
{
    ErrCode errCode = OsAccountInterface::SendToBMSAccountDelete(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("SendToBMSAccountDelete failed, id %{public}d, errCode %{public}d",
            osAccountInfo.GetLocalId(), errCode);
        return errCode;
    }
    errCode = OsAccountInterface::SendToStorageAccountRemove(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("SendToStorageAccountRemove failed, id %{public}d, errCode %{public}d",
            osAccountInfo.GetLocalId(), errCode);
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
#ifdef HAS_USER_IDM_PART
    errCode = OsAccountInterface::SendToIDMAccountDelete(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("SendToIDMAccountDelete failed, id %{public}d, errCode %{public}d",
            osAccountInfo.GetLocalId(), errCode);
        return errCode;
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
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
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
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
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
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
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
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
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
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
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
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
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
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }

    OsAccountInfo targetOsAccountInfo;
    errCode = osAccountControl_->GetOsAccountInfoById(targetId, targetOsAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error");
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
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
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
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
        return errCode;
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
    if (domainInfo.domain_.size() > Constants::DOMAIN_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("invalid domain name length %{public}zu.", domainInfo.domain_.size());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    if (domainInfo.accountName_.size() > Constants::DOMAIN_ACCOUNT_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("invalid domain account name length %{public}zu.", domainInfo.accountName_.size());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    id = -1;
    std::vector<OsAccountInfo> osAccountInfos;
    ErrCode errCode = osAccountControl_->GetOsAccountList(osAccountInfos);
    if (errCode != ERR_OK) {
        return errCode;
    }

    DomainAccountInfo curDomainInfo;
    for (auto osAccountInfosPtr = osAccountInfos.begin(); osAccountInfosPtr != osAccountInfos.end();
         ++osAccountInfosPtr) {
        osAccountInfosPtr->GetDomainInfo(curDomainInfo);
        if (((!domainInfo.accountId_.empty()) && (domainInfo.accountId_ == curDomainInfo.accountId_)) ||
            ((!domainInfo.accountName_.empty()) && (curDomainInfo.accountName_ == domainInfo.accountName_) &&
            (!domainInfo.domain_.empty()) && (curDomainInfo.domain_ == domainInfo.domain_))) {
            id = osAccountInfosPtr->GetLocalId();
            return ERR_OK;
        }
    }
    return ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT;
}

ErrCode IInnerOsAccountManager::QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo)
{
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error, errCode %{public}d.", errCode);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
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

    DomainAccountInfo domainInfo;
    osAccountInfo.GetDomainInfo(domainInfo);
    errCode = InnerDomainAccountManager::GetInstance().GetAccountStatus(domainInfo, domainInfo.status_);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGI("GetAccountStatus errCode %{public}d.", errCode);
        domainInfo.status_ = DomainAccountStatus::LOGOUT;
    }
    (void)osAccountInfo.SetDomainInfo(domainInfo);
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetOsAccountType(const int id, OsAccountType &type)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error, errCode %{public}d.", errCode);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
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
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
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
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
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
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
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
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
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
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
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
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
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
    AccountInfoReport::ReportSecurityInfo(osAccountInfo.GetLocalName(), id, ReportEvent::EVENT_LOGOUT, 0);
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
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
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
    subscribeManager_.PublishActivatingOsAccount(id);
    errCode = SendMsgForAccountActivate(osAccountInfo);
    if (errCode != ERR_OK) {
        RemoveLocalIdToOperating(id);
        return errCode;
    }
    RemoveLocalIdToOperating(id);
    subscribeManager_.PublishActivatedOsAccount(id);

    DomainAccountInfo domainInfo;
    osAccountInfo.GetDomainInfo(domainInfo);
    if (domainInfo.accountId_.empty() && !osAccountInfo.GetIsCreateSecret()) {
        AccountInfoReport::ReportSecurityInfo(
            osAccountInfo.GetLocalName(), osAccountInfo.GetLocalId(), ReportEvent::EVENT_LOGIN, 0);
    }
    ACCOUNT_LOGI("IInnerOsAccountManager ActivateOsAccount end");
    return ERR_OK;
}

void IInnerOsAccountManager::WatchStartUser(std::int32_t id)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_ACCOUNT_BOOT_EVENT_READY));
    OsAccountInfo osAccountInfo;
    osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (!osAccountInfo.GetIsActived()) {
        ReportOsAccountOperationFail(
            id, Constants::OPERATION_ACTIVATE, ERR_ACCOUNT_COMMON_OPERATION_TIMEOUT, "account activation timed out!");
    }
    SetParameter(ACCOUNT_READY_EVENT.c_str(), "true");
}

ErrCode IInnerOsAccountManager::SendMsgForAccountActivate(OsAccountInfo &osAccountInfo)
{
    ErrCode errCode = OsAccountInterface::SendToStorageAccountStart(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("account %{public}d call storage active failed, errCode %{public}d.",
            osAccountInfo.GetLocalId(), errCode);
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    errCode = OsAccountInterface::SendToAMSAccountStart(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("account %{public}d call ams active failed, errCode %{public}d.",
            osAccountInfo.GetLocalId(), errCode);
        return errCode;
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
    SetParameter(ACCOUNT_READY_EVENT.c_str(), "true");
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
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
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
        return errCode;
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

ErrCode IInnerOsAccountManager::GetOsAccountInfoById(const int id, OsAccountInfo &osAccountInfo)
{
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error, errCode %{public}d.", errCode);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetSerialNumberByOsAccountLocalId(const int &id, int64_t &serialNumber)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    serialNumber = osAccountInfo.GetSerialNumber();
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SubscribeOsAccount(
    const OsAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener)
{
    auto subscribeInfoPtr = std::make_shared<OsAccountSubscribeInfo>(subscribeInfo);
    if (subscribeInfoPtr == nullptr) {
        ACCOUNT_LOGE("subscribeInfoPtr is nullptr");
    }
    return subscribeManager_.SubscribeOsAccount(subscribeInfoPtr, eventListener);
}

ErrCode IInnerOsAccountManager::UnsubscribeOsAccount(const sptr<IRemoteObject> &eventListener)
{
    return subscribeManager_.UnsubscribeOsAccount(eventListener);
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
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
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

ErrCode IInnerOsAccountManager::SetOsAccountIsCreateSecret(const int id, const bool isCreateSecret)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error, errCode %{public}d.", errCode);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }

    osAccountInfo.SetIsCreateSecret(isCreateSecret);
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("update osaccount info error %{public}d, id: %{public}d",
            errCode, osAccountInfo.GetLocalId());
        return ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SetDefaultActivatedOsAccount(const int32_t id)
{
    std::lock_guard<std::mutex> lock(operatingMutex_);
    if (id == defaultActivatedId_) {
        ACCOUNT_LOGW("no need to repeat set initial start id %{public}d", id);
        return ERR_OK;
    }
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get osaccount info error, errCode %{public}d.", errCode);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    // to be removed, cannot change any thing
    if (osAccountInfo.GetToBeRemoved()) {
        ACCOUNT_LOGE("account %{public}d will be removed, cannot change verify state!", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR;
    }
    if (!osAccountInfo.GetIsCreateCompleted()) {
        ACCOUNT_LOGE("account %{public}d is not completed", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_IS_UNVERIFIED_ERROR;
    }
    errCode = osAccountControl_->SetDefaultActivatedOsAccount(id);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("set default activated account id error %{public}d, id: %{public}d", errCode, id);
        return errCode;
    }
    defaultActivatedId_ = id;
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetDefaultActivatedOsAccount(int32_t &id)
{
    std::lock_guard<std::mutex> lock(operatingMutex_);
    id = defaultActivatedId_;
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
        CountTraceAdapter("activeId", (int64_t)id);
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
    CountTraceAdapter("deActiveId", (int64_t)id);
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