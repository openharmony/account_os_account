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

#include "privileges_map.h"
#include "privileges_map_constant.h"

#include <atomic>
#include <map>
#include <mutex>
#include <string>
#include <vector>
#include <cstring>

namespace OHOS {
namespace AccountSA {
static std::atomic<bool> g_isPrivilegeMapInited{false};
static std::mutex g_lockPrivilegeMap;

class CharArrayCompare {
public:
    CharArrayCompare() {};

    bool operator()(const char* str1, const char* str2) const
    {
        if (str1 == str2) {
            return false;
        } else {
            return (strcmp(str1, str2) < 0);
        }
    }
};
static std::map<const char*, uint32_t, CharArrayCompare> g_privilegeMap;

static void InitMap()
{
    std::lock_guard<std::mutex> lock(g_lockPrivilegeMap);
    if (g_isPrivilegeMapInited.load()) {
        return;
    }
    for (uint32_t i = 0; i < MAX_PRIVILEGE_SIZE; i++) {
        g_privilegeMap[g_privilegeList[i].privilegeName] = i;
    }
    g_isPrivilegeMapInited.store(true);
}

bool TransferPrivilegeToCode(const std::string& privilegeName, uint32_t& code)
{
    if (!g_isPrivilegeMapInited.load()) {
        InitMap();
    }
    auto it = g_privilegeMap.find(privilegeName.c_str());
    if (it == g_privilegeMap.end()) {
        return false;
    }
    code = it->second;
    return true;
}

std::string TransferCodeToPrivilege(uint32_t code)
{
    if (code >= MAX_PRIVILEGE_SIZE) {
        return "";
    }
    return std::string(g_privilegeList[code].privilegeName);
}

bool IsDefinedPrivilege(const std::string& privilege)
{
    if (!g_isPrivilegeMapInited.load()) {
        InitMap();
    }
    auto it = g_privilegeMap.find(privilege.c_str());
    if (it == g_privilegeMap.end()) {
        return false;
    }
    return true;
}

bool GetPrivilegeBriefDef(const std::string& privilege, PrivilegeBriefDef& privilegeBriefDef)
{
    uint32_t code;
    if (!TransferPrivilegeToCode(privilege, code)) {
        return false;
    }
    privilegeBriefDef = g_privilegeList[code];
    return true;
}

bool GetPrivilegeBriefDef(uint32_t code, PrivilegeBriefDef& privilegeBriefDef)
{
    if (code >= MAX_PRIVILEGE_SIZE) {
        return false;
    }
    privilegeBriefDef = g_privilegeList[code];
    return true;
}

size_t GetDefPrivilegesSize()
{
    return MAX_PRIVILEGE_SIZE;
}

const char* GetPrivilegeDefVersion()
{
    return PRIVILEGES_DEFINITION_VERSION;
}
} // namespace AccountSA
} // namespace OHOS
