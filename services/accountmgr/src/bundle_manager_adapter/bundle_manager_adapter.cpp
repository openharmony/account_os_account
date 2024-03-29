/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "bundle_manager_adapter.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_hisysevent_adapter.h"
#include "hitrace_adapter.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AccountSA {
BundleManagerAdapter *BundleManagerAdapter::GetInstance()
{
    static BundleManagerAdapter *instance = new (std::nothrow) BundleManagerAdapter();
    return instance;
}

BundleManagerAdapter::BundleManagerAdapter()
{}

BundleManagerAdapter::~BundleManagerAdapter()
{}

ErrCode BundleManagerAdapter::GetNameForUid(const int uid, std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    ErrCode result = Connect();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to connect bundle manager service.");
        return false;
    }
    StartTraceAdapter("Bundle manager service, GetNameForUid");
    result = proxy_->GetNameForUid(uid, bundleName);
    FinishTraceAdapter();
    return result;
}

int BundleManagerAdapter::GetUidByBundleName(const std::string &bundleName, const int userId)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    ErrCode result = Connect();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to connect bundle manager service.");
        return result;
    }
    StartTraceAdapter("Bundle manager service, GetUidByBundleName");
    auto ret = proxy_->GetUidByBundleName(bundleName, userId);
    FinishTraceAdapter();
    return ret;
}

bool BundleManagerAdapter::GetBundleInfo(const std::string &bundleName, const AppExecFwk::BundleFlag flag,
    AppExecFwk::BundleInfo &bundleInfo, int32_t userId)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    ErrCode result = Connect();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to connect bundle manager service.");
        return false;
    }
    StartTraceAdapter("Bundle manager service, GetBundleInfo");
    auto ret = proxy_->GetBundleInfo(bundleName, flag, bundleInfo, userId);
    FinishTraceAdapter();
    return ret;
}

bool BundleManagerAdapter::QueryAbilityInfos(const AAFwk::Want &want, int32_t flags, int32_t userId,
    std::vector<AppExecFwk::AbilityInfo> &abilityInfos)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    ErrCode result = Connect();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to connect bundle manager service.");
        return false;
    }
    StartTraceAdapter("Bundle manager service, QueryAbilityInfos");
    auto ret = proxy_->QueryAbilityInfos(want, flags, userId, abilityInfos);
    FinishTraceAdapter();
    return ret;
}

bool BundleManagerAdapter::QueryExtensionAbilityInfos(const AAFwk::Want &want, const int32_t &flag,
    const int32_t &userId, std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    ErrCode result = Connect();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to connect bundle manager service.");
        return false;
    }
    StartTraceAdapter("Bundle manager service, QueryExtensionAbilityInfos");
    auto ret = proxy_->QueryExtensionAbilityInfos(want, flag, userId, extensionInfos);
    FinishTraceAdapter();
    return ret;
}

bool BundleManagerAdapter::QueryExtensionAbilityInfos(
    const AAFwk::Want &want, const AppExecFwk::ExtensionAbilityType &extensionType,
    const int32_t &flag, const int32_t &userId, std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    ErrCode result = Connect();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to connect bundle manager service.");
        return false;
    }
    StartTraceAdapter("Bundle manager service, QueryExtensionAbilityInfos");
    auto ret = proxy_->QueryExtensionAbilityInfos(want, extensionType, flag, userId, extensionInfos);
    FinishTraceAdapter();
    return ret;
}

ErrCode BundleManagerAdapter::CreateNewUser(int32_t userId, const std::vector<std::string> &disallowedHapList)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    ErrCode result = Connect();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to connect bundle manager service.");
        ReportOsAccountOperationFail(userId, "create",
            ERR_OSACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_CREATE_ERROR,
            "Connect bundle manager service failed!");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_CREATE_ERROR;
    }

    auto bundleUserMgrProxy = proxy_->GetBundleUserMgr();
    if (!bundleUserMgrProxy) {
        ACCOUNT_LOGE("failed to get bundleUserMgrProxy");
        ReportOsAccountOperationFail(userId, "create",
            ERR_OSACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_CREATE_ERROR,
            "GetBundleUserMgr from BundleManager proxy failed!");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_CREATE_ERROR;
    }
    StartTraceAdapter("BundleManageService CreateNewUser");
    result = bundleUserMgrProxy->CreateNewUser(userId, disallowedHapList);
    FinishTraceAdapter();
    return result;
}

ErrCode BundleManagerAdapter::RemoveUser(int32_t userId)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    ErrCode result = Connect();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to connect bundle manager service.");
        ReportOsAccountOperationFail(userId, "delete",
            result, "Connect bundle manager service failed!");
        return result;
    }

    auto bundleUserMgrProxy = proxy_->GetBundleUserMgr();
    if (!bundleUserMgrProxy) {
        ACCOUNT_LOGE("failed to get bundleUserMgrProxy");
        ReportOsAccountOperationFail(userId, "delete",
            ERR_OSACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_DELETE_ERROR,
            "GetBundleUserMgr from BundleManager proxy failed!");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_DELETE_ERROR;
    }
    StartTraceAdapter("BundleManageService RemoveUser");
    bundleUserMgrProxy->RemoveUser(userId);
    FinishTraceAdapter();
    return ERR_OK;
}

ErrCode BundleManagerAdapter::Connect()
{
    if (proxy_ == nullptr) {
        StartTraceAdapter("Connect Bundle Manager Service");
        sptr<ISystemAbilityManager> systemAbilityManager =
            SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (systemAbilityManager == nullptr) {
            ACCOUNT_LOGE("failed to get system ability manager");
            FinishTraceAdapter();
            return ERR_ACCOUNT_COMMON_CONNECT_BUNDLE_MANAGER_SERVICE_ERROR;
        }

        sptr<IRemoteObject> remoteObj = systemAbilityManager->CheckSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        if (remoteObj == nullptr) {
            ACCOUNT_LOGE("Fail to connect bundle manager service.");
            FinishTraceAdapter();
            return ERR_ACCOUNT_COMMON_CONNECT_BUNDLE_MANAGER_SERVICE_ERROR;
        }

        deathRecipient_ = sptr<IRemoteObject::DeathRecipient>(new (std::nothrow) BundleMgrDeathRecipient());
        if (deathRecipient_ == nullptr) {
            ACCOUNT_LOGE("Failed to create BundleMgrDeathRecipient!");
            FinishTraceAdapter();
            return ERR_ACCOUNT_COMMON_CONNECT_BUNDLE_MANAGER_SERVICE_ERROR;
        }

        if ((remoteObj->IsProxyObject()) && (!remoteObj->AddDeathRecipient(deathRecipient_))) {
            ACCOUNT_LOGE("Add death recipient to AbilityManagerService failed.");
            FinishTraceAdapter();
            return ERR_ACCOUNT_COMMON_CONNECT_BUNDLE_MANAGER_SERVICE_ERROR;
        }

        proxy_ = iface_cast<AppExecFwk::IBundleMgr>(remoteObj);
        if (proxy_ == nullptr) {
            ACCOUNT_LOGE("failed to get bundle mgr service remote object");
            FinishTraceAdapter();
            return ERR_ACCOUNT_COMMON_CONNECT_BUNDLE_MANAGER_SERVICE_ERROR;
        }
        FinishTraceAdapter();
    }

    return ERR_OK;
}

void BundleManagerAdapter::ResetProxy(const wptr<IRemoteObject>& remote)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    auto serviceRemote = proxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        proxy_ = nullptr;
    }
}

void BundleManagerAdapter::BundleMgrDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    ACCOUNT_LOGI("BundleMgrDeathRecipient handle remote died.");
    BundleManagerAdapter::GetInstance()->ResetProxy(remote);
}
}  // namespace AccountSA
}  // namespace OHOS