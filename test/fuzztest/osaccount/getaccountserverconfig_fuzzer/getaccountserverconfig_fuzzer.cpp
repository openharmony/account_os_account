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

#include "getaccountserverconfig_fuzzer.h"

#include "account_log_wrapper.h"
#include "domain_account_client.h"
#include <string>

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
    bool GetAccountServerConfigFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }
        DomainAccountInfo info;
        DomainServerConfig config;
        std::string accoutId(reinterpret_cast<const char*>(data), size);
        std::string accountName(reinterpret_cast<const char*>(data), size);
        std::string domain(reinterpret_cast<const char*>(data), size);
        std::string serverConfigId(reinterpret_cast<const char*>(data), size);
        info.accountId_ = accoutId;
        info.accountName_ = accountName;
        info.domain_ = domain;
        info.serverConfigId_ = serverConfigId;
        DomainAccountClient::GetInstance().GetAccountServerConfig(info, config);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetAccountServerConfigFuzzTest(data, size);
    return 0;
}

