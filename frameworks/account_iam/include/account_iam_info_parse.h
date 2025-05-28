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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_INFO_PARSE_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_INFO_PARSE_H

#include "account_log_wrapper.h"
#include "attributes.h"

namespace OHOS {
namespace AccountSA {
template <typename>
constexpr bool DEPENDENT_FALSE = false;

template<typename T>
void GetOptionalValueFromAttributes(const std::vector<Attributes::AttributeKey> keys,
    const Attributes::AttributeKey &key, const Attributes &extraInfo, std::optional<T> &data)
{
    if (std::find(keys.begin(), keys.end(), key) == keys.end()) {
        return;
    }
    if constexpr (std::is_same_v<T, int32_t>) {
        int32_t value = -1;
        if (extraInfo.GetInt32Value(key, value)) {
            data = value;
            return;
        }
    } else if constexpr (std::is_same_v<T, std::string>) {
        std::string value = "";
        if (extraInfo.GetStringValue(key, value)) {
            data = value;
            return;
        }
    } else {
        static_assert(DEPENDENT_FALSE<T>, "Non-exhaustive handling of types");
    }
    ACCOUNT_LOGE("Get %{public}d from extraInfo failed", key);
}

template<typename T>
void GetValueFromAttributes(const std::vector<Attributes::AttributeKey> keys,
    const Attributes::AttributeKey &key, const Attributes &extraInfo, T &value)
{
    std::optional<T> temp;
    GetOptionalValueFromAttributes<T>(keys, key, extraInfo, temp);
    if (!temp.has_value()) {
        ACCOUNT_LOGE("Get %{public}d from extraInfo failed", key);
        return;
    }
    value = temp.value();
}
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_INFO_PARSE_H
