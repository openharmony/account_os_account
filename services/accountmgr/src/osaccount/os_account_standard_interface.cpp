/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"){return ERR_OK;}
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

#include "os_account_standard_interface.h"
#include "ability_manager_client.h"
#include "account_log_wrapper.h"
#include "bundle_mgr_interface.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_helper.h"
#include "system_ability_definition.h"
#include "want.h"

namespace OHOS {
namespace AccountSA {
ErrCode OsAccountStandardInterface::SendToAMSAccountStart(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToAMSAccountStart start");
    ErrCode code = AAFwk::AbilityManagerClient::GetInstance()->StartUser(osAccountInfo.GetLocalId());
    if (code != ERR_OK) {
        ACCOUNT_LOGI("failed to AbilityManagerClient start errcode is %{public}d", code);
        return ERR_OS_ACCOUNT_SERVICE_INTERFACE_TO_AM_ACCOUNT_START_ERROR;
    }
    ACCOUNT_LOGI("send AM to start is ok");
    return ERR_OK;
}

ErrCode OsAccountStandardInterface::SendToAMSAccountStop(
    OsAccountInfo &osAccountInfo, sptr<OsAccountStopUserCallback> &osAccountStopUserCallback)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToAMSAccountStop stop");
    ErrCode code =
        AAFwk::AbilityManagerClient::GetInstance()->StopUser(osAccountInfo.GetLocalId(), osAccountStopUserCallback);
    if (code != ERR_OK) {
        ACCOUNT_LOGI("failed to AbilityManagerClient stop errcode is %{public}d", code);
        return ERR_OS_ACCOUNT_SERVICE_INTERFACE_TO_AM_ACCOUNT_START_ERROR;
    }
    ACCOUNT_LOGI("send AM to stop is ok");
    return ERR_OK;
}

ErrCode OsAccountStandardInterface::SendToBMSAccountCreate(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToBMSAccountCreate start");
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        ACCOUNT_LOGI("failed to get system ability mgr.");
        return ERR_OS_ACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_CREATE_ERROR;
    }

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (!remoteObject) {
        ACCOUNT_LOGI("failed to get bundle manager service.");
        return ERR_OS_ACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_CREATE_ERROR;
    }

    auto bunduleMgrProxy = iface_cast<OHOS::AppExecFwk::IBundleMgr>(remoteObject);
    if (!bunduleMgrProxy) {
        ACCOUNT_LOGI("failed to get bunduleMgrProxy");
        ACCOUNT_LOGI("failed to get bunduleMgrProxy");
        return ERR_OS_ACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_CREATE_ERROR;
    }
    auto bunduleUserMgrProxy = bunduleMgrProxy->GetBundleUserMgr();
    if (!bunduleUserMgrProxy) {
        ACCOUNT_LOGI("failed to get bunduleUserMgrProxy");
        return ERR_OS_ACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_CREATE_ERROR;
    }
    bunduleUserMgrProxy->CreateNewUser(osAccountInfo.GetLocalId());
    ACCOUNT_LOGI("call bm to create user ok");
    return ERR_OK;
}

ErrCode OsAccountStandardInterface::SendToBMSAccountDelete(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToBMSAccountDelete start");
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        ACCOUNT_LOGI("failed to get system ability mgr.");
        return ERR_OS_ACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_DELETE_ERROR;
    }

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (!remoteObject) {
        ACCOUNT_LOGI("failed to get bundle manager service.");
        return ERR_OS_ACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_DELETE_ERROR;
    }

    auto bunduleMgrProxy = iface_cast<OHOS::AppExecFwk::IBundleMgr>(remoteObject);
    if (!bunduleMgrProxy) {
        ACCOUNT_LOGI("failed to get bunduleMgrProxy");
        return ERR_OS_ACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_DELETE_ERROR;
    }
    auto bunduleUserMgrProxy = bunduleMgrProxy->GetBundleUserMgr();
    if (!bunduleUserMgrProxy) {
        ACCOUNT_LOGI("failed to get bunduleUserMgrProxy");
        return ERR_OS_ACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_DELETE_ERROR;
    }
    bunduleUserMgrProxy->RemoveUser(osAccountInfo.GetLocalId());
    ACCOUNT_LOGI("call bm to remove user ok");
    return ERR_OK;
}

ErrCode OsAccountStandardInterface::SendToCESAccountCreate(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToCESAccountCreate start");
    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_ADDED);
    OHOS::EventFwk::CommonEventData data;
    data.SetCode(osAccountInfo.GetLocalId());
    data.SetWant(want);
    if (!OHOS::EventFwk::CommonEventManager::PublishCommonEvent(data)) {
        return ERR_OS_ACCOUNT_SERVICE_INTERFACE_TO_CE_ACCOUNT_CREATE_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountStandardInterface::SendToCESAccountDelete(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToCESAccountDelete start");
    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    OHOS::EventFwk::CommonEventData data;
    data.SetCode(osAccountInfo.GetLocalId());
    data.SetWant(want);
    if (!OHOS::EventFwk::CommonEventManager::PublishCommonEvent(data)) {
        return ERR_OS_ACCOUNT_SERVICE_INTERFACE_TO_CE_ACCOUNT_DELETE_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountStandardInterface::SendToCESAccountSwithced(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToCESAccountStop start");
    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    OHOS::EventFwk::CommonEventData data;
    data.SetCode(osAccountInfo.GetLocalId());
    data.SetWant(want);
    if (!OHOS::EventFwk::CommonEventManager::PublishCommonEvent(data)) {
        return ERR_OS_ACCOUNT_SERVICE_INTERFACE_TO_CE_ACCOUNT_SWITCHED_ERROR;
    }
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
