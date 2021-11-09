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
#ifndef OS_ACCOUNT_FRAMEWORKS_COMMON_DATABASE_IACCOUNT_INFO_H
#define OS_ACCOUNT_FRAMEWORKS_COMMON_DATABASE_IACCOUNT_INFO_H
#include <string>
#include "nlohmann/json.hpp"
#include "account_log_wrapper.h"
namespace OHOS {
namespace AccountSA {
using Json = nlohmann::json;

class IAccountInfo {
public:
    virtual Json ToJson() const = 0;
    virtual void FromJson(const Json &jsonObject) = 0;
    virtual std::string ToString() const = 0;
    virtual std::string GetPrimeKey() = 0;
};

enum class JsonType {
    NULLABLE,
    BOOLEAN,
    NUMBER,
    OBJECT,
    ARRAY,
    STRING,
};

template <typename T, typename dataType>
void GetDataByType(const Json &jsonObject, const nlohmann::detail::iter_impl<const Json> &end, const std::string &key,
    dataType &data, const JsonType jsonType)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("key = %{public}s, jsonType = %{public}d", key.c_str(), jsonType);

    if (jsonObject.find(key) != end) {
        switch (jsonType) {
            case JsonType::BOOLEAN:
                if (!jsonObject.at(key).is_boolean()) {
                    ACCOUNT_LOGE("type is error %{public}s is not boolean", key.c_str());
                    break;
                }
                data = jsonObject.at(key).get<T>();
                break;
            case JsonType::NUMBER:
                if (!jsonObject.at(key).is_number()) {
                    ACCOUNT_LOGE("type is error %{public}s is not number", key.c_str());
                    break;
                }
                data = jsonObject.at(key).get<T>();
                break;
            case JsonType::OBJECT:
                if (!jsonObject.at(key).is_object()) {
                    ACCOUNT_LOGE("type is error %{public}s is not object", key.c_str());
                    break;
                }
                data = jsonObject.at(key).get<T>();
                break;
            case JsonType::ARRAY:
                if (!jsonObject.at(key).is_array()) {
                    ACCOUNT_LOGE("type is error %{public}s is not array", key.c_str());
                    break;
                }
                data = jsonObject.at(key).get<T>();
                break;
            case JsonType::STRING:
                if (!jsonObject.at(key).is_string()) {
                    ACCOUNT_LOGE("type is error %{public}s is not string", key.c_str());
                    break;
                }
                data = jsonObject.at(key).get<T>();
                break;
            case JsonType::NULLABLE:
                ACCOUNT_LOGE("type is error %{public}s is nullable", key.c_str());
                break;
            default:
                ACCOUNT_LOGE("type is error %{public}s is not jsonType", key.c_str());
        }
    }
}
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_FRAMEWORKS_COMMON_DATABASE_IACCOUNT_INFO_H
