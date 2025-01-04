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

#ifndef ACCOUNT_VARIANT_VALUE_H
#define ACCOUNT_VARIANT_VALUE_H

#include <string>
#include <variant>

namespace OHOS {
namespace AccountSA {
enum class ValueType {
    TYPE_NULL,
    TYPE_INT,
    TYPE_INT64,
    TYPE_STRING,
};

class VariantValue final {
public:
    VariantValue();
    virtual ~VariantValue();

    explicit VariantValue(int32_t value);
    explicit VariantValue(int64_t value);
    explicit VariantValue(const std::string& value);

    ValueType GetType() const;
    int32_t GetInt() const;
    int64_t GetInt64() const;
    std::string GetString() const;

    static const int32_t DEFAULT_VALUE = -1;

private:
    ValueType type_;
    std::variant<int32_t, int64_t, std::string> value_;
};
} // namespace AccountSA
} // namespace OHOS
#endif // ACCOUNT_VARIANT_VALUE_H
