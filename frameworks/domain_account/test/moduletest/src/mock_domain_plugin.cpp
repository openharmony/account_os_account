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
const int32_t DEFAULT_FREEZING_TIME = 6000;
const std::string VALID_DOMAIN = "china.example.com";
const std::string VALID_ACCOUNT_NAME = "zhangsan";
}
MockDomainPlugin::MockDomainPlugin() : remainingTimes_(DEFAULT_REMAINING_TIMES), freezingTime_(0)
{}

MockDomainPlugin::~MockDomainPlugin()
{}

void MockDomainPlugin::Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
    const std::shared_ptr<DomainAuthCallback> &callback)
{
    ACCOUNT_LOGI("start, accountName: %{public}s, domain: %{public}s",
        info.accountName_.c_str(), info.domain_.c_str());
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    DomainAuthResult result = {};
    if ((info.domain_ != VALID_DOMAIN) || (info.accountName_ != VALID_ACCOUNT_NAME)) {
        callback->OnResult(1, result);
        return;
    }
    bool isCorrect = true;
    if (password.size() == DEFAULT_PASSWORD.size()) {
        for (size_t i = 0; i < password.size(); ++i) {
            if (password[i] != DEFAULT_PASSWORD[i]) {
                isCorrect = false;
                break;
            }
        }
    } else {
        isCorrect = false;
    }
    if (isCorrect) {
        remainingTimes_ = DEFAULT_REMAINING_TIMES;
        freezingTime_ = 0;
    } else {
        remainingTimes_ = remainingTimes_ > 0 ? remainingTimes_ - 1 : 0;
        freezingTime_ = remainingTimes_ > 0 ? 0 : DEFAULT_FREEZING_TIME;
    }
    result.authProperty.remainingTimes = remainingTimes_;
    result.authProperty.freezingTime = freezingTime_;
    callback->OnResult(!isCorrect, result);
}

int32_t MockDomainPlugin::GetAuthProperty(const DomainAccountInfo &info, DomainAuthProperty &property)
{
    if ((info.accountName_ == VALID_ACCOUNT_NAME) && (info.domain_ == VALID_DOMAIN)) {
        property.remainingTimes = remainingTimes_;
        property.freezingTime = freezingTime_;
    } else {
        property.remainingTimes = -1;
        property.freezingTime = -1;
    }
    return 0;
}
}  // AccountSA
}  // OHOS