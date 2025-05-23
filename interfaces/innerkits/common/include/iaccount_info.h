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

#ifndef OS_ACCOUNT_FRAMEWORKS_COMMON_DATABASE_INCLUDE_IACCOUNT_INFO_H
#define OS_ACCOUNT_FRAMEWORKS_COMMON_DATABASE_INCLUDE_IACCOUNT_INFO_H

#include <string>
#include "nlohmann/json.hpp"

namespace OHOS {
namespace AccountSA {
using Json = nlohmann::json;

class IAccountInfo {
public:
    virtual Json ToJson() const = 0;
    virtual bool FromJson(const Json &jsonObject) = 0;
    virtual std::string ToString() const = 0;
    virtual std::string GetPrimeKey() const = 0;
};

enum class JsonType {
    NULLABLE,
    BOOLEAN,
    NUMBER,
    OBJECT,
    ARRAY,
    STRING,
};

template<typename T, typename dataType>
bool GetDataByType(const Json &jsonObject, const nlohmann::detail::iter_impl<const Json> &end, const std::string &key,
    dataType &data, const JsonType jsonType)
{
    if (jsonObject.is_discarded() || (!jsonObject.is_object())) {
        return false;
    }
    if (jsonObject.find(key) == end) {
        return false;
    }
    switch (jsonType) {
        case JsonType::BOOLEAN:
            if (!jsonObject.at(key).is_boolean()) {
                return false;
            }
            data = jsonObject.at(key).get<T>();
            return true;
        case JsonType::NUMBER:
            if (!jsonObject.at(key).is_number()) {
                return false;
            }
            data = static_cast<dataType>(jsonObject.at(key).get<T>());
            return true;
        case JsonType::OBJECT:
            if (!jsonObject.at(key).is_object()) {
                return false;
            }
            data = jsonObject.at(key).get<T>();
            return true;
        case JsonType::ARRAY:
            if (!jsonObject.at(key).is_array()) {
                return false;
            }
            data = jsonObject.at(key).get<T>();
            return true;
        case JsonType::STRING:
            if (!jsonObject.at(key).is_string()) {
                return false;
            }
            data = jsonObject.at(key).get<T>();
            return true;
        case JsonType::NULLABLE:
            return false;
        default:
            return false;
    }
}
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_FRAMEWORKS_COMMON_DATABASE_INCLUDE_IACCOUNT_INFO_H
