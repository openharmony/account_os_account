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

#ifndef OS_ACCOUNT_FRAMEWORKS_COMMON_LOG_INCLUDE_ACCOUNT_LOG_WRAPPER_H
#define OS_ACCOUNT_FRAMEWORKS_COMMON_LOG_INCLUDE_ACCOUNT_LOG_WRAPPER_H

#include <string>
#include "hilog/log.h"

namespace OHOS {
namespace AccountSA {
#ifdef __FILE_NAME__
#define LOG_FILE_NAME __FILE_NAME__
#else
#define LOG_FILE_NAME (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

enum class AccountLogLevel { DEBUG = 0, INFO, WARN, ERROR, FATAL };
constexpr OHOS::HiviewDFX::HiLogLabel ACCOUNT_LABEL = {LOG_CORE, LOG_DOMAIN, ACCOUNT_LOG_TAG};

class AccountLogWrapper {
public:
    static bool JudgeLevel(const AccountLogLevel &level);

    static void SetLogLevel(const AccountLogLevel &level)
    {
        level_ = level;
    }

    static const AccountLogLevel &GetLogLevel()
    {
        return level_;
    }

    static std::string GetBriefFileName(const std::string &file);

private:
    static AccountLogLevel level_;
};

#define ARGS(fmt, ...) "[%{public}s@%{public}s:%{public}d] " fmt, __FUNCTION__, LOG_FILE_NAME, __LINE__, ##__VA_ARGS__
#define ACCOUNT_LOGD(fmt, ...) \
    ((void)HILOG_IMPL(ACCOUNT_LABEL.type, LOG_DEBUG, ACCOUNT_LABEL.domain, ACCOUNT_LABEL.tag, \
    "[%{public}s@%{public}s:%{public}d] " fmt, __FUNCTION__, LOG_FILE_NAME, __LINE__, ##__VA_ARGS__))
#define ACCOUNT_LOGI(fmt, ...) \
    ((void)HILOG_IMPL(ACCOUNT_LABEL.type, LOG_INFO, ACCOUNT_LABEL.domain, ACCOUNT_LABEL.tag, \
    "[%{public}s@%{public}s:%{public}d] " fmt, __FUNCTION__, LOG_FILE_NAME, __LINE__, ##__VA_ARGS__))
#define ACCOUNT_LOGW(fmt, ...) \
    ((void)HILOG_IMPL(ACCOUNT_LABEL.type, LOG_WARN, ACCOUNT_LABEL.domain, ACCOUNT_LABEL.tag, \
    "[%{public}s@%{public}s:%{public}d] " fmt, __FUNCTION__, LOG_FILE_NAME, __LINE__, ##__VA_ARGS__))
#define ACCOUNT_LOGE(fmt, ...) \
    ((void)HILOG_IMPL(ACCOUNT_LABEL.type, LOG_ERROR, ACCOUNT_LABEL.domain, ACCOUNT_LABEL.tag, \
    "[%{public}s@%{public}s:%{public}d] " fmt, __FUNCTION__, LOG_FILE_NAME, __LINE__, ##__VA_ARGS__))
#define ACCOUNT_LOGF(fmt, ...) \
    ((void)HILOG_IMPL(ACCOUNT_LABEL.type, LOG_FATAL, ACCOUNT_LABEL.domain, ACCOUNT_LABEL.tag, \
    "[%{public}s@%{public}s:%{public}d] " fmt, __FUNCTION__, LOG_FILE_NAME, __LINE__, ##__VA_ARGS__))
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_FRAMEWORKS_COMMON_LOG_INCLUDE_ACCOUNT_LOG_WRAPPER_H
