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

#include "bundle_user_manager_adapter_proxy.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
BundleUserManagerAdapterProxy::BundleUserManagerAdapterProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<AppExecFwk::IBundleUserMgr>(object)
{}

BundleUserManagerAdapterProxy::~BundleUserManagerAdapterProxy()
{}

void BundleUserManagerAdapterProxy::CreateNewUser(int32_t userId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!data.WriteInterfaceToken(BundleUserManagerAdapterProxy::GetDescriptor())) {
        ACCOUNT_LOGE("fail to CreateNewUser due to write MessageParcel fail");
        return;
    }

    data.WriteInt32(static_cast<int32_t>(userId));
    SendRequest(static_cast<int32_t>(AppExecFwk::IBundleUserMgr::Message::CREATE_USER), data, reply, option);
}

void BundleUserManagerAdapterProxy::RemoveUser(int32_t userId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!data.WriteInterfaceToken(BundleUserManagerAdapterProxy::GetDescriptor())) {
        ACCOUNT_LOGE("fail to RemoveUser due to write MessageParcel fail");
        return;
    }

    data.WriteInt32(static_cast<int32_t>(userId));
    SendRequest(static_cast<int32_t>(AppExecFwk::IBundleUserMgr::Message::REMOVE_USER), data, reply, option);
}

bool BundleUserManagerAdapterProxy::SendRequest(const int32_t& code, MessageParcel& data, MessageParcel& reply,
    MessageOption& option)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCOUNT_LOGE("fail to uninstall, for Remote() is nullptr");
        return false;
    }

    int32_t ret = remote->SendRequest(code, data, reply, option);
    if (ret != NO_ERROR) {
        ACCOUNT_LOGE("fail to sendRequest, for transact is failed and error code is: %{public}d", ret);
        return false;
    }
    return true;
}
}  // namespace AccountSA
}  // namespace OHOS
