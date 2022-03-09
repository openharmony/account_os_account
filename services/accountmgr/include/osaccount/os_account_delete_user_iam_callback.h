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
#include "useridm_callback.h"

namespace OHOS {
namespace AccountSA {
class OsAccountDeleteUserIamCallback : public OHOS::UserIAM::UserIDM::IDMCallback {
public:
    OsAccountDeleteUserIamCallback() {}
    virtual ~OsAccountDeleteUserIamCallback() {}
    /**
     * @brief
     * @param result .
     * @param strcut reqRet .
     * @return void.
     */
    virtual void OnResult(int32_t result, UserIAM::UserIDM::RequestResult reqRet) override;

    /**
     * @brief
     * @param module .
     * @param acquire .
     * @param reqRet .
     * @return void.
     */
    virtual void OnAcquireInfo(int32_t module, int32_t acquire, UserIAM::UserIDM::RequestResult reqRet) override;

public:
    bool isIamOnResultCallBack_ = false;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif /* OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_STOP_USER_CALLBACK_H */
