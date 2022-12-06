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

#include "mock_domain_plugin.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::vector<uint8_t> DEFAULT_PASSWORD = {49, 50, 51, 52, 53};
const int32_t DEFAULT_REMAINING_TIMES = 5;
const int32_t DEFAULT_FREEZING_TIME = 0;
const std::string VALID_DOMAIN = "china.example.com";
const std::string VALID_ACCOUNT_NAME = "zhangsan";
}
MockDomainPlugin::MockDomainPlugin()
{}

MockDomainPlugin::~MockDomainPlugin()
{}

void MockDomainPlugin::Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
    const std::shared_ptr<DomainAuthCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    ACCOUNT_LOGI("start, accountName: %{public}s, domain: %{public}s",
        info.accountName_.c_str(), info.domain_.c_str());
    DomainAuthResult result = {};
    if ((info.domain_ != VALID_DOMAIN) || (info.accountName_ != VALID_ACCOUNT_NAME)) {
        callback->OnResult(1, result);
        return;
    }
    if (password.size() != DEFAULT_PASSWORD.size()) {
        result.remainingTimes = DEFAULT_REMAINING_TIMES;
        result.freezingTime = DEFAULT_FREEZING_TIME;
        callback->OnResult(1, result);
        return;
    }
    for (size_t i = 0; i < password.size(); ++i) {
        if (password[i] != DEFAULT_PASSWORD[i]) {
            result.remainingTimes = DEFAULT_REMAINING_TIMES;
            result.freezingTime = DEFAULT_FREEZING_TIME;
            callback->OnResult(1, result);
            return;
        }
    }
    callback->OnResult(0, result);
}
}  // AccountSA
}  // OHOS