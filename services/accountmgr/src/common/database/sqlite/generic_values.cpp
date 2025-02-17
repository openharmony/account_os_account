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

#include "generic_values.h"

namespace OHOS {
namespace AccountSA {
void GenericValues::Put(const std::string& key, int32_t value)
{
    map_.insert(std::make_pair(key, VariantValue(value)));
}

void GenericValues::Put(const std::string& key, int64_t value)
{
    map_.insert(std::make_pair(key, VariantValue(value)));
}

void GenericValues::Put(const std::string& key, const std::string& value)
{
    map_.insert(std::make_pair(key, VariantValue(value)));
}

void GenericValues::Put(const std::string& key, const VariantValue& value)
{
    map_.insert(std::make_pair(key, value));
}

VariantValue GenericValues::Get(const std::string& key) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return VariantValue();
    }
    return iter->second;
}

int32_t GenericValues::GetInt(const std::string& key) const
{
    auto it = map_.find(key);
    if (it == map_.end()) {
        return VariantValue::DEFAULT_VALUE;
    }
    return it->second.GetInt();
}

int64_t GenericValues::GetInt64(const std::string& key) const
{
    auto it = map_.find(key);
    if (it == map_.end()) {
        return VariantValue::DEFAULT_VALUE;
    }
    return it->second.GetInt64();
}

std::string GenericValues::GetString(const std::string& key) const
{
    auto it = map_.find(key);
    if (it == map_.end()) {
        return std::string();
    }
    return it->second.GetString();
}

std::vector<std::string> GenericValues::GetAllKeys() const
{
    std::vector<std::string> keys;
    for (auto it = map_.begin(); it != map_.end(); ++it) {
        keys.emplace_back(it->first);
    }
    return keys;
}

void GenericValues::Remove(const std::string& key)
{
    if (map_.find(key) != map_.end()) {
        map_.erase(key);
    }
}
} // namespace AccountSA
} // namespace OHOS
