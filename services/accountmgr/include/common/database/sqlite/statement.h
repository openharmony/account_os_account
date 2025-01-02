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

#ifndef ACCOUNT_STATEMENT_H
#define ACCOUNT_STATEMENT_H

#include <string>

#include "variant_value.h"

#include "sqlite3sym.h"

namespace OHOS {
namespace AccountSA {
class Statement final {
public:
    enum State { BUSY, ROW, DONE, MISUSE, UNKNOWN };

    Statement(sqlite3* db, const std::string& sql);
    virtual ~Statement();

    void Bind(const int32_t index, const std::string& text);
    void Bind(const int32_t index, int32_t value);
    void Bind(const int32_t index, int64_t value);
    void Bind(const std::string& tableColumnName, const VariantValue& value);

    State Step();
    int32_t Reset();

    std::string GetColumnString(const int32_t column) const;
    int32_t GetColumnInt(const int32_t column) const;
    int64_t GetColumnInt64(const int32_t column) const;
    std::string GetColumnName(const int32_t column) const;
    int32_t GetParameterIndex(const std::string& name) const;
    int32_t GetColumnCount() const;
    VariantValue GetValue(const int32_t column, const bool flagInt64) const;

private:
    sqlite3* db_;
    sqlite3_stmt* statement_;
    const std::string sql_;
};
} // namespace AccountSA
} // namespace OHOS
#endif // ACCOUNT_STATEMENT_H
