/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_PARAMTER_MOCK_TEST_MOCK_INCLUDE_MOCK_ACCOUNT_MGR_SERVICE_H
#define OS_ACCOUNT_PARAMTER_MOCK_TEST_MOCK_INCLUDE_MOCK_ACCOUNT_MGR_SERVICE_H

namespace OHOS {
namespace AccountSA {
enum ErrTypeResult {
    ERR_INTERFACE_FAILED = -1,
    ERR_INTERFACE_OK = 0,
    ERR_INTERFACE_STORAGE_REMOVE,
    ERR_INTERFACE_IDM_DELETE,
    ERR_INTERFACE_AMS_DEACTIVATION,
    ERR_INTERFACE_STORAGE_STOP,
    ERR_INTERFACE_CHECKALLAPPDIED,
    ERR_INTERFACE_STORAGE_START,
    ERR_INTERFACE_BMS_CREATE,
};
extern int g_errType;
}  // namespace AccountSA
}  // namespace OHOS
#endif /* OS_ACCOUNT_PARAMTER_MOCK_TEST_MOCK_INCLUDE_MOCK_ACCOUNT_MGR_SERVICE_H */