/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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


#ifndef APPACCOUNT_ERROR_H
#define APPACCOUNT_ERROR_H

namespace OHOS::AccountSA {
typedef enum {
    ERR_CJ_SUCCESS = 0,
    ERR_CJ_PARAMETER_ERROR = 401,
    ERR_CJ_INVALID_INSTANCE_CODE = -1,
    ERR_CJ_ACCOUNT_AUTHENTICATOR_SERVICE_EXCEPTION = 12300114,
    ERR_CJ_SYSTEM_SERVICE_EXCEPTION = 12300001
} CjErrorCode;
} // namespace::OHOS::AccountSA
#endif