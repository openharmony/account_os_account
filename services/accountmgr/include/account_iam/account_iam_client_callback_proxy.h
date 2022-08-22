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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_IAM_CLIENT_CALLBACK_PROXY_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_IAM_CLIENT_CALLBACK_PROXY_H

#include "account_error_no.h"
#include "account_iam_info.h"
#include "iaccount_iam_callback.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AccountSA {
class IDMCallbackProxy : public IRemoteProxy<IIDMCallback> {
public:
    explicit IDMCallbackProxy(const sptr<IRemoteObject> &object);
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override;
    void OnResult(int32_t result, const Attributes &extraInfo) override;

private:
    ErrCode SendRequest(IIDMCallback::Message code, MessageParcel &data, MessageParcel &reply);

private:
    static inline BrokerDelegator<IDMCallbackProxy> delegator_;
};

class GetCredInfoCallbackProxy : public IRemoteProxy<IGetCredInfoCallback> {
public:
    explicit GetCredInfoCallbackProxy(const sptr<IRemoteObject> &object);
    void OnCredentialInfo(const std::vector<CredentialInfo> &infoList) override;

private:
    ErrCode SendRequest(IGetCredInfoCallback::Message code, MessageParcel &data, MessageParcel &reply);

private:
    static inline BrokerDelegator<GetCredInfoCallbackProxy> delegator_;
};

class GetSetPropCallbackProxy : public IRemoteProxy<IGetSetPropCallback> {
public:
    explicit GetSetPropCallbackProxy(const sptr<IRemoteObject> &object);
    void OnResult(int32_t result, const Attributes &extraInfo) override;

private:
    ErrCode SendRequest(IGetSetPropCallback::Message code, MessageParcel &data, MessageParcel &reply);

private:
    static inline BrokerDelegator<GetSetPropCallbackProxy> delegator_;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_IAM_CLIENT_CALLBACK_PROXY_H
