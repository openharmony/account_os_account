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
#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_user_manager_adapter_proxy.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
constexpr size_t DISALLOWED_HAP_LIST_MAX_SIZE = 1000;

BundleUserManagerAdapterProxy::BundleUserManagerAdapterProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<AppExecFwk::IBundleUserMgr>(object)
{}

BundleUserManagerAdapterProxy::~BundleUserManagerAdapterProxy()
{}

ErrCode BundleUserManagerAdapterProxy::CreateNewUser(int32_t userId, const std::vector<std::string> &disallowedHapList)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(BundleUserManagerAdapterProxy::GetDescriptor())) {
        ACCOUNT_LOGE("fail to CreateNewUser due to write MessageParcel fail");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(static_cast<int32_t>(userId))) {
        ACCOUNT_LOGE("fail to CreateNewUser due to write userId fail");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    uint32_t disallowedListMatchSize = (disallowedHapList.size() > DISALLOWED_HAP_LIST_MAX_SIZE) ?
        DISALLOWED_HAP_LIST_MAX_SIZE : disallowedHapList.size();
    if (!data.WriteInt32(disallowedListMatchSize)) {
        ACCOUNT_LOGE("Write BundleNameListVector failed");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    for (uint32_t index = 0; index < disallowedListMatchSize; ++index) {
        if (!data.WriteString(disallowedHapList.at(index))) {
            ACCOUNT_LOGE("Write BundleNameListVector failed");
            return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
        }
    }
    MessageParcel reply;
    if (!SendTransactCmd(AppExecFwk::BundleUserMgrInterfaceCode::CREATE_USER, data, reply)) {
        ACCOUNT_LOGE("fail to CreateNewUser from server");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("host reply errCode : %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode BundleUserManagerAdapterProxy::RemoveUser(int32_t userId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(BundleUserManagerAdapterProxy::GetDescriptor())) {
        ACCOUNT_LOGE("fail to RemoveUser due to write MessageParcel fail");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(static_cast<int32_t>(userId))) {
        ACCOUNT_LOGE("fail to RemoveUser due to write userId fail");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(AppExecFwk::BundleUserMgrInterfaceCode::REMOVE_USER, data, reply)) {
        ACCOUNT_LOGE("fail to RemoveUser from server");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("host reply errCode : %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

bool BundleUserManagerAdapterProxy::SendTransactCmd(
    AppExecFwk::BundleUserMgrInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCOUNT_LOGE("fail to uninstall, for Remote() is nullptr");
        return false;
    }

    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != NO_ERROR) {
        ACCOUNT_LOGE("fail to sendRequest, for transact is failed and error code is: %{public}d", result);
        return false;
    }
    return true;
}
}  // namespace AccountSA
}  // namespace OHOS
