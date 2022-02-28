/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "app_account_authenticator_stub.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
AppAccountAuthenticatorStub::AppAccountAuthenticatorStub()
{
    ACCOUNT_LOGI("enter");
}

AppAccountAuthenticatorStub::~AppAccountAuthenticatorStub()
{
    ACCOUNT_LOGI("enter");
}

int AppAccountAuthenticatorStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ACCOUNT_LOGI("enter");

    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("failed to check descriptor! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }

    switch (code) {
        case static_cast<uint32_t>(IAppAccountAuthenticator::Message::AUTHENTICATE): {
            std::string name = data.ReadString();
            std::string authType = data.ReadString();
            std::string callerBundleName = data.ReadString();
            AAFwk::WantParams *options = data.ReadParcelable<AAFwk::WantParams>();
            sptr<IRemoteObject> callback = data.ReadRemoteObject();
            if (callback == nullptr) {
                ACCOUNT_LOGI("callback is nullptr");
            }
            ErrCode result = Authenticate(name, authType, callerBundleName, *options, callback);
            if (!reply.WriteInt32(result)) {
                ACCOUNT_LOGE("failed to write reply");
                return IPC_STUB_WRITE_PARCEL_ERR;
            }
            break;
        }
        case static_cast<uint32_t>(IAppAccountAuthenticator::Message::ADD_ACCOUNT_IMPLICITLY): {
            std::string authType = data.ReadString();
            std::string callerBundleName = data.ReadString();
            AAFwk::WantParams *options = data.ReadParcelable<AAFwk::WantParams>();
            sptr<IRemoteObject> callback = data.ReadRemoteObject();
            if (callback == nullptr) {
                ACCOUNT_LOGI("callback is nullptr");
            }
            ErrCode result = AddAccountImplicitly(authType, callerBundleName, *options, callback);
            if (!reply.WriteInt32(result)) {
                ACCOUNT_LOGE("failed to write reply");
                return IPC_STUB_WRITE_PARCEL_ERR;
            }
            break;
        }
        default:
            ACCOUNT_LOGI("default, code = %{public}u, flags = %{public}u", code, option.GetFlags());
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return ERR_NONE;
}
}  // namespace AccountSA
}  // namespace OHOS
