/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef PRIVILEGES_MAP_H
#define PRIVILEGES_MAP_H

#include <string>
#include <stdint.h>

namespace OHOS {
namespace AccountSA {
struct PrivilegeBriefDef {
    char* privilegeName;
    char* description;
    uint32_t timeout;
};

bool TransferPrivilegeToCode(const std::string& privilegeName, uint32_t& code);
std::string TransferCodeToPrivilege(uint32_t code);
bool IsDefinedPrivilege(const std::string& privilege);
bool GetPrivilegeBriefDef(const std::string& privilege, PrivilegeBriefDef& privilegeBriefDef);
bool GetPrivilegeBriefDef(uint32_t code, PrivilegeBriefDef& privilegeBriefDef);
size_t GetDefPrivilegesSize();
const char* GetPrivilegeDefVersion();
} // namespace AccountSA
} // namespace OHOS
#endif // PRIVILEGES_MAP_H
