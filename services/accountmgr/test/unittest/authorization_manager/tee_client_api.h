/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_MOCK_TEE_CLIENT_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_MOCK_TEE_CLIENT_H
#include <cstdint>

namespace OHOS {
namespace AccountSA {
#define TEEC_Result int32_t
#define TEEC_Context int32_t
#define TEEC_Session int32_t
#define TEEC_Operation int32_t
#define TEEC_UUID int32_t
#define TEEC_SUCCESS 0
#define TEEC_ERROR_GENERIC (-1)
} // namespace AccountSA
} // namespace OHOS
#endif // OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_MOCK_TEE_CLIENT_H
