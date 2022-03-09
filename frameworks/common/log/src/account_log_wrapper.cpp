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

#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
// initial static member object
AccountLogLevel AccountLogWrapper::level_ = AccountLogLevel::INFO;

bool AccountLogWrapper::JudgeLevel(const AccountLogLevel& level)
{
    return (level >= AccountLogWrapper::GetLogLevel());
}

std::string AccountLogWrapper::GetBriefFileName(const std::string &file)
{
    auto pos = file.find_last_of("/");
    if (pos != std::string::npos) {
        return file.substr(pos + 1);
    }

    pos = file.find_last_of("\\");
    if (pos != std::string::npos) {
        return file.substr(pos + 1);
    }

    return file;
}
} // namespace AccountSA
} // namespace OHOS
