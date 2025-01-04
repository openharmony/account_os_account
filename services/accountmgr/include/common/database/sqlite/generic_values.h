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

#ifndef ACCOUNT_GENERIC_VALUES_H
#define ACCOUNT_GENERIC_VALUES_H

#include <map>
#include <vector>
#include <string>

#include "variant_value.h"

namespace OHOS {
namespace AccountSA {
class GenericValues final {
public:
    GenericValues() = default;
    virtual ~GenericValues() = default;

    void Put(const std::string& key, int32_t value);

    void Put(const std::string& key, int64_t value);

    void Put(const std::string& key, const std::string& value);

    void Put(const std::string& key, const VariantValue& value);

    std::vector<std::string> GetAllKeys() const;

    VariantValue Get(const std::string& key) const;

    int32_t GetInt(const std::string& key) const;

    int64_t GetInt64(const std::string& key) const;

    std::string GetString(const std::string& key) const;

    void Remove(const std::string& key);
private:
    std::map<std::string, VariantValue> map_;
};
} // namespace AccountSA
} // namespace OHOS
#endif // ACCOUNT_GENERIC_VALUES_H
