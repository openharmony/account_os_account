/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef BASE_ACCOUNT_COMMON_LOG_INCLUDE_ACCOUNT_LOG_WRAPPER_H
#define BASE_ACCOUNT_COMMON_LOG_INCLUDE_ACCOUNT_LOG_WRAPPER_H

#include "hilog/log.h"
#include <string>

namespace OHOS {
namespace AccountSA {
enum class AccountLogLevel {
    DEBUG = 0,
    INFO,
    WARN,
    ERROR,
    FATAL
};

static constexpr OHOS::HiviewDFX::HiLogLabel ACCOUNT_LABEL = {LOG_CORE, LOG_DOMAIN, ACCOUNT_LOG_TAG};

class AccountLogWrapper {
public:
    static bool JudgeLevel(const AccountLogLevel& level);

    static void SetLogLevel(const AccountLogLevel& level)
    {
        level_ = level;
    }

    static const AccountLogLevel& GetLogLevel()
    {
        return level_;
    }

    static std::string GetBriefFileName(const std::string &file);

private:
    static AccountLogLevel level_;
};

#define PRINT_LOG(LEVEL, Level, fmt, ...) \
    if (AccountLogWrapper::JudgeLevel(AccountLogLevel::LEVEL)) \
        OHOS::HiviewDFX::HiLog::Level(ACCOUNT_LABEL, "[%{public}s(%{public}s)] " fmt, \
        AccountLogWrapper::GetBriefFileName(std::string(__FILE__)).c_str(), __FUNCTION__, ##__VA_ARGS__)

#define ACCOUNT_LOGD(fmt, ...) PRINT_LOG(DEBUG, Debug, fmt, ##__VA_ARGS__)
#define ACCOUNT_LOGI(fmt, ...) PRINT_LOG(INFO, Info, fmt, ##__VA_ARGS__)
#define ACCOUNT_LOGW(fmt, ...) PRINT_LOG(WARN, Warn, fmt, ##__VA_ARGS__)
#define ACCOUNT_LOGE(fmt, ...) PRINT_LOG(ERROR, Error, fmt, ##__VA_ARGS__)
#define ACCOUNT_LOGF(fmt, ...) PRINT_LOG(FATAL, Fatal, fmt, ##__VA_ARGS__)
} // namespace AccountSA
} // namespace OHOS

#endif // BASE_ACCOUNT_COMMON_LOG_INCLUDE_ACCOUNT_LOG_WRAPPER_H