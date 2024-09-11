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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_CCCOUNT_PLUGIN_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_CCCOUNT_PLUGIN_H
#include <functional>
#ifdef __cplusplus
extern "C" {
#endif
typedef int32_t (*VerifyActivationLockFunc)(std::function<int32_t(bool)> callback);

enum OsPluginMethodEnum {
    VERIFY_ACTIVATION_LOCK = 0,
    //this is last just for count enum
    OS_ACCOUNT_PLUGIN_COUNT,
};
#ifdef __cplusplus
}
#endif
#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_CCCOUNT_PLUGIN_H