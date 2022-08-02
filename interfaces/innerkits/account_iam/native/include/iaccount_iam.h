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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_IACCOUNT_IAM_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_IACCOUNT_IAM_H

#include "account_log_wrapper.h"
#include "iremote_broker.h"
#include "iremote_object.h"

namespace OHOS {
namespace AccountSA {
class IAccountIAM : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.accountfwk.IAccountIAM");

    virtual ErrCode ActivateUserKey(
        int32_t userId, const std::vector<uint8_t> &token, const std::vector<uint8_t> &secret) = 0;
    virtual ErrCode UpdateUserKey(int32_t userId, uint64_t credentialId,
        const std::vector<uint8_t> &token, const std::vector<uint8_t> &newSecret) = 0;
    virtual ErrCode RemoveUserKey(int32_t userId, const std::vector<uint8_t> &token) = 0;
    virtual ErrCode RestoreUserKey(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &token) = 0;

    enum class Message {
        ACTIVATE_USER_KEY,
        UPDATE_USER_KEY,
        REMOVE_USER_KEY,
        RESTORE_USER_KEY
    };
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_IACCOUNT_IAM_H
