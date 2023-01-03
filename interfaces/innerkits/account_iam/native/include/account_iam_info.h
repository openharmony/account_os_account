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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_INFO_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_INFO_H

#include "attributes.h"
#include "iam_common_defines.h"
#ifdef HAS_PIN_AUTH_PART
#include "i_inputer.h"
#endif
#include "user_auth_client_callback.h"
#include "user_auth_client_defines.h"
#include "user_idm_client.h"
#include "user_idm_client_callback.h"
#include "user_idm_client_defines.h"

namespace OHOS {
namespace AccountSA {
#ifdef HAS_PIN_AUTH_PART
typedef UserIam::PinAuth::IInputer IInputer;
typedef UserIam::PinAuth::IInputerData IInputerData;
#endif
#ifdef HAS_USER_AUTH_PART
typedef UserIam::UserAuth::ResultCode ResultCode;
typedef UserIam::UserAuth::AuthType AuthType;
typedef UserIam::UserAuth::Attributes Attributes;
typedef UserIam::UserAuth::AuthTrustLevel AuthTrustLevel;
typedef UserIam::UserAuth::AuthenticationCallback AuthenticationCallback;
typedef UserIam::UserAuth::GetPropCallback GetPropCallback;
typedef UserIam::UserAuth::SetPropCallback SetPropCallback;
typedef UserIam::UserAuth::GetPropertyRequest GetPropertyRequest;
typedef UserIam::UserAuth::SetPropertyRequest SetPropertyRequest;
typedef UserIam::UserAuth::PropertyMode PropertyMode;
typedef UserIam::UserAuth::PinSubType PinSubType;
typedef UserIam::UserAuth::UserIdmClientCallback UserIdmClientCallback;
typedef UserIam::UserAuth::CredentialParameters CredentialParameters;
typedef UserIam::UserAuth::CredentialInfo CredentialInfo;
typedef UserIam::UserAuth::GetCredentialInfoCallback GetCredentialInfoCallback;
#endif

enum IAMAuthType {
    DOMAIN = 1024
};

enum IAMAuthSubType {
    DOMAIN_MIXED = 10240001
};

enum IAMState {
    IDLE = 0,
    AFTER_OPEN_SESSION,
    DURING_AUTHENTICATE,
    DURING_ADD_CRED,
    DURING_UPDATE_CRED,
    DURING_DEL_CRED,
    AFTER_ADD_CRED,
    AFTER_UPDATE_CRED,
    AFTER_DEL_CRED,
    ROLL_BACK_ADD_CRED,
    ROLL_BACK_UPDATE_CRED,
    ROLL_BACK_DEL_CRED,
    DURING_DEL_USER,
};

struct CredentialItem {
    int32_t type = 0;
    std::vector<uint8_t> oldCredential;
    std::vector<uint8_t> credential;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_INFO_H
