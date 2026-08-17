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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_DISPLAY_USER_ZONE_CONFIG_DISPLAY_USER_ZONE_CONFIG_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_DISPLAY_USER_ZONE_CONFIG_DISPLAY_USER_ZONE_CONFIG_MANAGER_H

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>
#include "account_error_no.h"
#include "nocopyable.h"

namespace OHOS {
namespace AccountSA {

struct DisplayConfigInfo {
    uint64_t physicalId = 0;
    uint64_t logicalId = 0;
    std::string name;
    uint64_t userZone = 0;
    uint64_t userZoneId = 0;
    bool hasPhysicalId = false;
    bool hasLogicalId = false;
    bool hasUserZoneId = false;
};

class DisplayUserZoneConfigManager {
public:
    static DisplayUserZoneConfigManager &GetInstance();

    /**
     * Read and parse the display user zone config XML file.
     * @return ERR_OK on success; otherwise, the read or format error is recorded
     *         and reported by EnsureConfigReady before a user-zone query is consumed.
     */
    ErrCode Init();

    /**
     * Whether the given logical display is the primary display of its user zone.
     * A display is primary when its logicalId equals its user zone id (i.e. it is
     * a standalone display or the primary that other secondary displays point to).
     * @param logicalDisplayId Logical display id.
     * @param isPrimary Set to true if the display is primary, false if it is explicitly not primary.
     * @return ERR_OK on success; ERR_ACCOUNT_COMMON_FILE_READ_FAILED when the initial
     *         configuration read and its single retry fail; ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR
     *         when the configuration format is invalid.
     */
    ErrCode IsDisplayPrimary(uint64_t logicalDisplayId, bool &isPrimary);

    /**
     * Ensure the display user zone configuration is available before consuming
     * a query result whose fallback value would be ambiguous.
     * @return ERR_OK on success; ERR_ACCOUNT_COMMON_FILE_READ_FAILED after the
     *         one allowed read retry fails; ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR
     *         if the loaded configuration has an invalid format.
     */
    ErrCode EnsureConfigReady();

    /**
     * Check whether the logical display is present in the configuration.
     * @param logicalId Logical display id.
     * @return true if the display is configured, otherwise false.
     */
    bool HasDisplayByLogicalId(uint64_t logicalId) const;

    /**
     * Get the primary display id of the given group.
     * @param group Group id (the logicalId of the primary display).
     * @param logicalId Set to the primary logical display id when found.
     * @return true if the group has a primary display, otherwise false.
     */
    bool GetUserZonePrimaryDisplayId(uint64_t group, uint64_t &logicalId) const;

    /**
     * Get the logical display ids belonging to the given group.
     * @param group Group id (the logicalId of the primary display).
     * @return A list of logical display ids belonging to the group.
     */
    std::vector<uint64_t> GetDisplayIdsByUserZone(uint64_t group) const;

    /**
     * Get the group id of the given logical display.
     * @param logicalId Logical display id.
     * @return Group id, or the original logical id if the display is not found.
     */
    uint64_t GetUserZoneByLogicalId(uint64_t logicalId) const;

private:
    DisplayUserZoneConfigManager() = default;
    ~DisplayUserZoneConfigManager() = default;
    DISALLOW_COPY_AND_MOVE(DisplayUserZoneConfigManager);

    ErrCode ParseDisplayConfig(const std::string &content);
    ErrCode ParseDisplayNodes(void *root);
    ErrCode CollectDisplayNodes(void *root, std::vector<DisplayConfigInfo> &displays,
        std::map<uint64_t, uint64_t> &physicalToLogical);
    ErrCode ResolveDisplayUserZones(const std::vector<DisplayConfigInfo> &displays,
        const std::map<uint64_t, uint64_t> &physicalToLogical);
    ErrCode ParseDisplayNodeAttributes(void *node, DisplayConfigInfo &info);
    ErrCode FinalizeParsedConfig();
    ErrCode ValidateParsedConfig();
    ErrCode LoadConfigLocked();
    void ClearParsedData();
    bool ParseUInt64(const std::string &value, uint64_t &result);

private:
    mutable std::mutex mutex_;
    std::map<uint64_t, DisplayConfigInfo> logicalIdMap_;
    std::map<uint64_t, std::vector<uint64_t>> userZoneMap_;
    std::map<uint64_t, uint64_t> userZonePrimaryMap_;
    bool configReadFailed_ = false;
    bool configFormatError_ = false;
    bool configReadRetried_ = false;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_DISPLAY_USER_ZONE_CONFIG_DISPLAY_USER_ZONE_CONFIG_MANAGER_H
