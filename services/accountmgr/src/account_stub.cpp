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

#include "account_stub.h"
#include <dlfcn.h>
#include <ipc_types.h>
#include "account_error_no.h"
#include "account_helper_data.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "account_mgr_service.h"
#include "bundlemgr/bundle_mgr_interface.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "ohos_account_kits.h"
#include "permission/permission_kit.h"
#include "string_ex.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::string OHOS_ACCOUNT_QUIT_TIPS_TITLE = "";
const std::string OHOS_ACCOUNT_QUIT_TIPS_CONTENT = "";
const std::string PERMISSION_MANAGE_USERS = "ohos.permission.MANAGE_LOCAL_ACCOUNTS";
const std::string PERMISSION_INTERACT_ACROSS_USERS = "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS";
const std::string PERMISSION_INTERACT_ACROSS_USERS_FULL =
    "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION";
const std::string PERMISSION_DISTRIBUTED_DATASYNC = "ohos.permission.DISTRIBUTED_DATASYNC";
const std::string DEFAULT_ACCOUNT_NAME = "no_name";
constexpr std::int32_t SYSTEM_UID = 1000;
constexpr std::int32_t ROOT_UID = 0;

std::int32_t GetBundleNamesForUid(std::int32_t uid, std::string &bundleName)
{
    sptr<ISystemAbilityManager> systemMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemMgr == nullptr) {
        ACCOUNT_LOGE("Fail to get system ability mgr");
        return ERR_ACCOUNT_ZIDL_ACCOUNT_STUB_ERROR;
    }

    sptr<IRemoteObject> remoteObject = systemMgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObject == nullptr) {
        ACCOUNT_LOGE("Fail to get bundle manager proxy");
        return ERR_ACCOUNT_ZIDL_ACCOUNT_STUB_ERROR;
    }

    sptr<OHOS::AppExecFwk::IBundleMgr> bundleMgrProxy = iface_cast<OHOS::AppExecFwk::IBundleMgr>(remoteObject);
    if (bundleMgrProxy == nullptr) {
        ACCOUNT_LOGE("Bundle mgr proxy is nullptr");
        return ERR_ACCOUNT_ZIDL_ACCOUNT_STUB_ERROR;
    }

    if (!bundleMgrProxy->GetBundleNameForUid(uid, bundleName)) {
        ACCOUNT_LOGE("Get bundle name failed");
        return ERR_ACCOUNT_ZIDL_ACCOUNT_STUB_ERROR;
    }

    return ERR_OK;
}
}
const std::map<std::uint32_t, AccountStubFunc> AccountStub::stubFuncMap_ {
    std::make_pair(UPDATE_OHOS_ACCOUNT_INFO, &AccountStub::CmdUpdateOhosAccountInfo),
    std::make_pair(QUERY_OHOS_ACCOUNT_INFO, &AccountStub::CmdQueryOhosAccountInfo),
    std::make_pair(QUERY_OHOS_ACCOUNT_QUIT_TIPS, &AccountStub::CmdQueryOhosQuitTips),
    std::make_pair(QUERY_DEVICE_ACCOUNT_ID, &AccountStub::CmdQueryDeviceAccountId),
    std::make_pair(QUERY_DEVICE_ACCOUNT_ID_FROM_UID, &AccountStub::CmdQueryDeviceAccountIdFromUid),
};

std::int32_t AccountStub::CmdUpdateOhosAccountInfo(MessageParcel &data, MessageParcel &reply)
{
    if (!IsRootOrSystemAccount() && !HasAccountRequestPermission(PERMISSION_MANAGE_USERS)) {
        ACCOUNT_LOGE("Check permission failed");
        return ERR_ACCOUNT_ZIDL_CHECK_PERMISSION_ERROR;
    }

    // ignore the real account name
    Str16ToStr8(data.ReadString16());
    const std::string accountName = DEFAULT_ACCOUNT_NAME;
    const std::string uid = Str16ToStr8(data.ReadString16());
    if (uid.empty()) {
        ACCOUNT_LOGE("invalid user id");
        return ERR_ACCOUNT_ZIDL_ACCOUNT_STUB_ERROR;
    }
    const std::string eventStr = Str16ToStr8(data.ReadString16());
    ACCOUNT_LOGI("CmdUpdateOhosAccountInfo eventStr: %s", eventStr.c_str());

    std::int32_t ret = ERR_OK;
    bool result = UpdateOhosAccountInfo(accountName, uid, eventStr);
    if (!result) {
        ACCOUNT_LOGE("Update ohos account info failed");
        ret = ERR_ACCOUNT_ZIDL_ACCOUNT_STUB_ERROR;
    }
    if (!reply.WriteInt32(ret)) {
        ACCOUNT_LOGE("Write result data failed");
        ret = ERR_ACCOUNT_ZIDL_WRITE_RESULT_ERROR;
    }
    return ret;
}

std::int32_t AccountStub::CmdQueryOhosAccountInfo(MessageParcel &data, MessageParcel &reply)
{
    if (!IsRootOrSystemAccount() && !HasAccountRequestPermission(PERMISSION_MANAGE_USERS)) {
        ACCOUNT_LOGE("Check permission failed");
        return ERR_ACCOUNT_ZIDL_CHECK_PERMISSION_ERROR;
    }

    std::pair<bool, OhosAccountInfo> info = QueryOhosAccountInfo();
    if (!info.first) {
        ACCOUNT_LOGE("Query ohos account info failed");
        return ERR_ACCOUNT_ZIDL_ACCOUNT_STUB_ERROR;
    }

    std::string name = info.second.name_;
    std::string id = info.second.uid_;
    if (!reply.WriteString16(Str8ToStr16(name))) {
        ACCOUNT_LOGE("Write name data failed");
        return ERR_ACCOUNT_ZIDL_WRITE_NAME_ERROR;
    }
    if (!reply.WriteString16(Str8ToStr16(id))) {
        ACCOUNT_LOGE("Write id data failed");
        return ERR_ACCOUNT_ZIDL_WRITE_UID_ERROR;
    }
    if (!reply.WriteInt32(info.second.status_)) {
        ACCOUNT_LOGE("Write status data failed");
        return ERR_ACCOUNT_ZIDL_WRITE_ACCOUNT_STATUS_ERROR;
    }
    return ERR_OK;
}

std::int32_t AccountStub::CmdQueryOhosQuitTips(MessageParcel &data, MessageParcel &reply)
{
    if (!IsRootOrSystemAccount() && !HasAccountRequestPermission(PERMISSION_MANAGE_USERS)) {
        ACCOUNT_LOGE("Check permission failed");
        return ERR_ACCOUNT_ZIDL_CHECK_PERMISSION_ERROR;
    }

    if (!reply.WriteString16(Str8ToStr16(OHOS_ACCOUNT_QUIT_TIPS_TITLE))) {
        ACCOUNT_LOGE("Write quit tips title failed");
        return ERR_ACCOUNT_ZIDL_WRITE_RESULT_ERROR;
    }
    if (!reply.WriteString16(Str8ToStr16(OHOS_ACCOUNT_QUIT_TIPS_CONTENT))) {
        ACCOUNT_LOGE("Write quit tips content failed");
        return ERR_ACCOUNT_ZIDL_WRITE_RESULT_ERROR;
    }
    ACCOUNT_LOGI("CmdQueryOhosQuitTips exit");
    return ERR_OK;
}

std::int32_t AccountStub::CmdQueryDeviceAccountId(MessageParcel &data, MessageParcel &reply)
{
    if (!IsRootOrSystemAccount()) {
        ACCOUNT_LOGE("Check permission failed");
        return ERR_ACCOUNT_ZIDL_CHECK_PERMISSION_ERROR;
    }

    std::int32_t id;
    auto ret = QueryDeviceAccountId(id);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("QueryDevice AccountId failed: %d", ret);
        return ret;
    }

    if (!reply.WriteInt32(id)) {
        ACCOUNT_LOGE("Write result data failed");
        return ERR_ACCOUNT_ZIDL_WRITE_RESULT_ERROR;
    }
    return ERR_OK;
}

std::int32_t AccountStub::CmdQueryDeviceAccountIdFromUid(MessageParcel &data, MessageParcel &reply)
{
    std::int32_t uid = data.ReadInt32();
    auto ret = QueryDeviceAccountIdFromUid(uid);
    if (ret < 0) {
        ACCOUNT_LOGE("QueryDevice accountid from uid failed: %d", ret);
        return ret;
    }

    if (!reply.WriteInt32(ret)) {
        ACCOUNT_LOGE("Write result data failed");
        return ERR_ACCOUNT_ZIDL_WRITE_RESULT_ERROR;
    }

    return ERR_OK;
}

std::int32_t AccountStub::OnRemoteRequest(std::uint32_t code, MessageParcel &data,
                                          MessageParcel &reply, MessageOption &option)
{
    ACCOUNT_LOGI("Received stub message: %{public}d", code);
    if (!IsServiceStarted()) {
        ACCOUNT_LOGE("account mgr not ready");
        return ERR_ACCOUNT_ZIDL_MGR_NOT_READY_ERROR;
    }

    if (!CheckCallerForTrustList()) {
        const std::u16string descriptor = AccountStub::GetDescriptor();
        const std::u16string remoteDescriptor = data.ReadInterfaceToken();
        if (descriptor != remoteDescriptor) {
            ACCOUNT_LOGE("Check remote descriptor failed");
            return ERR_ACCOUNT_ZIDL_ACCOUNT_STUB_ERROR;
        }
    }

    const auto &itFunc = stubFuncMap_.find(code);
    if (itFunc != stubFuncMap_.end()) {
        return (this->*(itFunc->second))(data, reply);
    }

    ACCOUNT_LOGW("remote request unhandled: %{public}d", code);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

bool AccountStub::HasAccountRequestPermission(const std::string &permissionName)
{
    if (permissionName.empty()) {
        return false;
    }

    if (!IsServiceStarted()) {
        ACCOUNT_LOGE("account mgr not ready");
        return false;
    }

    const std::int32_t uid = IPCSkeleton::GetCallingUid();
    if (uid == ROOT_UID || uid == SYSTEM_UID) {
        return true;
    }

    std::string bundleName;
    if (GetBundleNamesForUid(uid, bundleName) != ERR_OK) {
        return false;
    }

    ACCOUNT_LOGI("Check permission: %{public}s", permissionName.c_str());
    const std::int32_t userId = QueryDeviceAccountIdFromUid(uid);
    return (Security::Permission::PermissionKit::VerifyPermission(bundleName, permissionName, userId) ==
        Security::Permission::PermissionState::PERMISSION_GRANTED);
}

bool AccountStub::IsRootOrSystemAccount()
{
    const auto id = IPCSkeleton::GetCallingUid();
    return (id == ROOT_UID || id == SYSTEM_UID);
}

bool AccountStub::CheckCallerForTrustList()
{
    if (!IsServiceStarted()) {
        ACCOUNT_LOGE("account mgr not ready");
        return false;
    }

    const std::int32_t uid = IPCSkeleton::GetCallingUid();
    if (uid == ROOT_UID || uid == SYSTEM_UID) {
        return false;
    }

    std::string bundleName;
    if (GetBundleNamesForUid(uid, bundleName) != ERR_OK) {
        return false;
    }

    std::vector<std::string> trustList = AccountHelperData::GetBundleNameTrustList();
    if (std::find(trustList.begin(), trustList.end(), bundleName) == trustList.end()) {
        return false;
    }

    return true;
}
} // namespace AccountSA
} // namespace OHOS
