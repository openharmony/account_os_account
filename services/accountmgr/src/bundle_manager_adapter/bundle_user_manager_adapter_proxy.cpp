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
#include "account_constants.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
constexpr size_t DISALLOWED_HAP_LIST_MAX_SIZE = 1000;
constexpr size_t ALLOWED_HAP_LIST_MAX_SIZE = 1000;

BundleUserManagerAdapterProxy::BundleUserManagerAdapterProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<AppExecFwk::IBundleUserMgr>(object)
{}

BundleUserManagerAdapterProxy::~BundleUserManagerAdapterProxy()
{}

ErrCode BundleUserManagerAdapterProxy::CreateNewUser(int32_t userId, const std::vector<std::string> &disallowedHapList,
    const std::optional<std::vector<std::string>> &allowedHapList)
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
    if (!WriteStrListToData(data, disallowedHapList, DISALLOWED_HAP_LIST_MAX_SIZE)) {
        ACCOUNT_LOGE("Write disallowedHapList failed");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!allowedHapList.has_value()) {
        data.WriteBool(false);
    } else {
        data.WriteBool(true);
        if (!WriteStrListToData(data, allowedHapList.value(), ALLOWED_HAP_LIST_MAX_SIZE)) {
            ACCOUNT_LOGE("Write allowedHapList failed");
            return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
        }
    }
    MessageParcel reply;
    ErrCode sendResult = SendTransactCmd(AppExecFwk::BundleUserMgrInterfaceCode::CREATE_USER, data, reply);
    if (sendResult != ERR_OK) {
        ACCOUNT_LOGE("fail to CreateNewUser from server");
        return sendResult;
    }
    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("host reply errCode : %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

bool BundleUserManagerAdapterProxy::WriteStrListToData(
    MessageParcel &data, const std::vector<std::string> &list, size_t maxListSize)
{
    size_t listSize = list.size();
    if (listSize > maxListSize) {
        ACCOUNT_LOGE("Abnormal list data size, size %{public}zu", listSize);
        return false;
    }
    if (!data.WriteInt32(listSize)) {
        return false;
    }
    for (size_t index = 0; index < listSize; ++index) {
        if (!data.WriteString(list.at(index))) {
            return false;
        }
    }
    return true;
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
    ErrCode sendResult = SendTransactCmd(AppExecFwk::BundleUserMgrInterfaceCode::REMOVE_USER, data, reply);
    if (sendResult != ERR_OK) {
        ACCOUNT_LOGE("fail to RemoveUser from server");
        return sendResult;
    }

    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("host reply errCode : %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode BundleUserManagerAdapterProxy::SendTransactCmd(
    AppExecFwk::BundleUserMgrInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCOUNT_LOGE("fail to uninstall, for Remote() is nullptr");
        return Constants::E_IPC_SA_DIED;
    }

    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != NO_ERROR) {
        ACCOUNT_LOGE("fail to sendRequest, for transact is failed and error code is: %{public}d", result);
        return result;
    }
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
