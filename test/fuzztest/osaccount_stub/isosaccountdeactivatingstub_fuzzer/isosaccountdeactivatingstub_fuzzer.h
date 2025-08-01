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

#ifndef IS_OS_ACCOUNT_DEACTIVATING_STUB_FUZZER_H
#define IS_OS_ACCOUNT_DEACTIVATING_STUB_FUZZER_H

#include "os_account_stub.h"

namespace OHOS {
namespace AccountSA {
    bool IsOsAccountDeactivatingStubFuzzTest(const uint8_t* data, size_t size);

    class OsAccountStubFuzzer : public OsAccountStub {
    public:
        OsAccountStubFuzzer() = default;
        ~OsAccountStubFuzzer() = default;
    };
} // namespace AccountSA
} // namespace OHOS

#endif // IS_OS_ACCOUNT_DEACTIVATING_STUB_FUZZER_H
