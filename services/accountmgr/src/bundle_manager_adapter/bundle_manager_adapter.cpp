/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "hisysevent_adapter.h"
#include "hitrace_adapter.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AccountSA {
std::shared_ptr<BundleManagerAdapter> BundleManagerAdapter::instance_ = nullptr;
std::mutex BundleManagerAdapter::instanceMutex_;

std::shared_ptr<BundleManagerAdapter> BundleManagerAdapter::GetInstance()
{
    std::lock_guard<std::mutex> lock(instanceMutex_);
    if (instance_ == nullptr) {
        instance_ = std::make_shared<BundleManagerAdapter>();
    }
    return instance_;
}

BundleManagerAdapter::BundleManagerAdapter()
{
    ACCOUNT_LOGI("create BundleManagerAdapter");
}

BundleManagerAdapter::~BundleManagerAdapter()
{
    ACCOUNT_LOGI("destroy BundleManagerAdapter");
}

bool BundleManagerAdapter::GetBundleNameForUid(const int uid, std::string &bundleName)
{
    ACCOUNT_LOGI("GetBundleNameForUid begin");
    std::lock_guard<std::mutex> lock(proxyMutex_);
    ErrCode result = Connect();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to connect bundle manager service.");
        return false;
    }
    HiTraceAdapterSyncTrace tracer("Bundle manager service, GetBundleNameForUid");
    return proxy_->GetBundleNameForUid(uid, bundleName);
}

int BundleManagerAdapter::GetUidByBundleName(const std::string &bundleName, const int userId)
{
    ACCOUNT_LOGI("GetUidByBundleName begin");
    std::lock_guard<std::mutex> lock(proxyMutex_);
    ErrCode result = Connect();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to connect bundle manager service.");
        return result;
    }
    HiTraceAdapterSyncTrace tracer("Bundle manager service, GetUidByBundleName");
    return proxy_->GetUidByBundleName(bundleName, userId);
}

bool BundleManagerAdapter::GetBundleInfo(const std::string &bundleName, const AppExecFwk::BundleFlag flag,
    AppExecFwk::BundleInfo &bundleInfo, int32_t userId)
{
    ACCOUNT_LOGI("GetBundleInfo begin");
    std::lock_guard<std::mutex> lock(proxyMutex_);
    ErrCode result = Connect();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to connect bundle manager service.");
        return false;
    }
    HiTraceAdapterSyncTrace tracer("Bundle manager service, GetBundleInfo");
    return proxy_->GetBundleInfo(bundleName, flag, bundleInfo, userId);
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

    HiTraceAdapterSyncTrace tracer("Bundle manager service, QueryAbilityInfos");
    return proxy_->QueryAbilityInfos(want, flags, userId, abilityInfos);
}

ErrCode BundleManagerAdapter::CreateNewUser(int32_t userId)
{
    ACCOUNT_LOGI("CreateNewUser begin. userId %{public}d.", userId);
    std::lock_guard<std::mutex> lock(proxyMutex_);
    ErrCode result = Connect();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to connect bundle manager service.");
        ReportAccountOperationFail(userId,
            ERR_OSACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_CREATE_ERROR,
            "create",
            "Connect bundle manager service failed!");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_CREATE_ERROR;
    }

    auto bundleUserMgrProxy = proxy_->GetBundleUserMgr();
    if (!bundleUserMgrProxy) {
        ACCOUNT_LOGE("failed to get bundleUserMgrProxy");
        ReportAccountOperationFail(userId,
            ERR_OSACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_CREATE_ERROR,
            "create",
            "GetBundleUserMgr from BundleManager proxy failed!");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_CREATE_ERROR;
    }

    HiTraceAdapterSyncTrace tracer("BundleManageService CreateNewUser");
    bundleUserMgrProxy->CreateNewUser(userId);
    ACCOUNT_LOGI("call bm to create user ok, userId %{public}d.", userId);
    return ERR_OK;
}

ErrCode BundleManagerAdapter::RemoveUser(int32_t userId)
{
    ACCOUNT_LOGI("RemoveUser begin. userId %{public}d.", userId);
    std::lock_guard<std::mutex> lock(proxyMutex_);
    ErrCode result = Connect();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to connect bundle manager service.");
        ReportAccountOperationFail(userId,
            result, "delete", "Connect bundle manager service failed!");
        return result;
    }

    auto bundleUserMgrProxy = proxy_->GetBundleUserMgr();
    if (!bundleUserMgrProxy) {
        ACCOUNT_LOGE("failed to get bundleUserMgrProxy");
        ReportAccountOperationFail(userId,
            ERR_OSACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_DELETE_ERROR,
            "delete",
            "GetBundleUserMgr from BundleManager proxy failed!");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_DELETE_ERROR;
    }

    HiTraceAdapterSyncTrace tracer("BundleManageService RemoveUser");
    bundleUserMgrProxy->RemoveUser(userId);
    ACCOUNT_LOGI("call bm to remove user ok. userId %{public}d.", userId);
    return ERR_OK;
}

ErrCode BundleManagerAdapter::Connect()
{
    ACCOUNT_LOGI("bundle manager connect begin");
    if (proxy_ == nullptr) {
        HiTraceAdapterSyncTrace tracer("Connect Bundle Manager Service");
        sptr<ISystemAbilityManager> systemAbilityManager =
            SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (systemAbilityManager == nullptr) {
            ACCOUNT_LOGE("failed to get system ability manager");
            return ERR_ACCOUNT_COMMON_CONNECT_BUNDLE_MANAGER_SERVICE_ERROR;
        }

        sptr<IRemoteObject> remoteObj = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        if (remoteObj == nullptr) {
            ACCOUNT_LOGE("Fail to connect ability manager service.");
            return ERR_ACCOUNT_COMMON_CONNECT_BUNDLE_MANAGER_SERVICE_ERROR;
        }

        deathRecipient_ = sptr<IRemoteObject::DeathRecipient>(new (std::nothrow) BundleMgrDeathRecipient());
        if (deathRecipient_ == nullptr) {
            ACCOUNT_LOGE("Failed to create BundleMgrDeathRecipient!");
            return ERR_ACCOUNT_COMMON_CONNECT_BUNDLE_MANAGER_SERVICE_ERROR;
        }

        if ((remoteObj->IsProxyObject()) && (!remoteObj->AddDeathRecipient(deathRecipient_))) {
            ACCOUNT_LOGE("Add death recipient to AbilityManagerService failed.");
            return ERR_ACCOUNT_COMMON_CONNECT_BUNDLE_MANAGER_SERVICE_ERROR;
        }

        proxy_ = iface_cast<AppExecFwk::IBundleMgr>(remoteObj);
        if (proxy_ == nullptr) {
            ACCOUNT_LOGE("failed to get bundle mgr service remote object");
            return ERR_ACCOUNT_COMMON_CONNECT_BUNDLE_MANAGER_SERVICE_ERROR;
        }
    }

    ACCOUNT_LOGI("bundle manager connect end");
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