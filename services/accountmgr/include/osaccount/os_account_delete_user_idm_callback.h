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
#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_DELETE_USER_IAM_CALLBACK_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_DELETE_USER_IAM_CALLBACK_H
#ifdef HAS_USER_IDM_PART
#include "user_idm_client_callback.h"
#endif // HAS_USER_IDM_PART

namespace OHOS {
namespace AccountSA {
#ifdef HAS_USER_IDM_PART
class OsAccountDeleteUserIdmCallback : public OHOS::UserIam::UserAuth::UserIdmClientCallback {
public:
    OsAccountDeleteUserIdmCallback() {}
    virtual ~OsAccountDeleteUserIdmCallback() {}
    /**
     * @brief
     * @param result .
     * @param strcut reqRet .
     * @return void.
     */
    void OnResult(int32_t result, const UserIam::UserAuth::Attributes &extraInfo) override;

    /**
     * @brief
     * @param module .
     * @param acquire .
     * @param reqRet .
     * @return void.
     */
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const UserIam::UserAuth::Attributes &extraInfo) override;

public:
    bool isIdmOnResultCallBack_ = false;
};
#endif // HAS_USER_IDM_PART
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_STOP_USER_CALLBACK_H
