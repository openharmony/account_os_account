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

#include "display_user_zone_config/display_user_zone_config_manager.h"

#include "account_log_wrapper.h"

#include <charconv>
#include <climits>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "account_file_operator.h"
#include "os_account_constants.h"
#ifdef HAS_CONFIG_POLICY_PART
#include "config_policy_utils.h"
#endif

namespace OHOS {
namespace AccountSA {

DisplayUserZoneConfigManager &DisplayUserZoneConfigManager::GetInstance()
{
    static DisplayUserZoneConfigManager instance;
    return instance;
}

ErrCode DisplayUserZoneConfigManager::IsDisplayPrimary(uint64_t logicalDisplayId, bool &isPrimary)
{
    ErrCode errCode = EnsureConfigReady();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = logicalIdMap_.find(logicalDisplayId);
    if (iter == logicalIdMap_.end()) {
        isPrimary = true;
        return ERR_OK;
    }
    isPrimary = iter->second.logicalId == iter->second.userZone;
    return ERR_OK;
}

bool DisplayUserZoneConfigManager::HasDisplayByLogicalId(uint64_t logicalId) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return logicalIdMap_.find(logicalId) != logicalIdMap_.end();
}

bool DisplayUserZoneConfigManager::GetUserZonePrimaryDisplayId(uint64_t group, uint64_t &logicalId) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = userZonePrimaryMap_.find(group);
    if (iter == userZonePrimaryMap_.end()) {
        return false;
    }
    auto displayIter = logicalIdMap_.find(iter->second);
    if (displayIter == logicalIdMap_.end()) {
        return false;
    }
    logicalId = displayIter->second.logicalId;
    return true;
}

std::vector<uint64_t> DisplayUserZoneConfigManager::GetDisplayIdsByUserZone(uint64_t group) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<uint64_t> result;
    auto iter = userZoneMap_.find(group);
    if (iter == userZoneMap_.end()) {
        return result;
    }
    for (uint64_t logicalId : iter->second) {
        auto displayIter = logicalIdMap_.find(logicalId);
        if (displayIter != logicalIdMap_.end()) {
            result.push_back(displayIter->second.logicalId);
        }
    }
    return result;
}

uint64_t DisplayUserZoneConfigManager::GetUserZoneByLogicalId(uint64_t logicalId) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = logicalIdMap_.find(logicalId);
    if (iter == logicalIdMap_.end()) {
        return logicalId;
    }
    return iter->second.userZone;
}

ErrCode DisplayUserZoneConfigManager::Init()
{
    std::lock_guard<std::mutex> lock(mutex_);
    configReadFailed_ = false;
    configFormatError_ = false;
    configReadRetried_ = false;
    return LoadConfigLocked();
}

ErrCode DisplayUserZoneConfigManager::LoadConfigLocked()
{
    ClearParsedData();
    configReadFailed_ = false;
    configFormatError_ = false;
    std::string configPath = "/system/" + Constants::DISPLAY_MANAGER_CONFIG_RELATIVE_PATH;
    bool usePolicyPath = false;
#ifdef HAS_CONFIG_POLICY_PART
    char buf[MAX_PATH_LEN] = {0};
    char *path = GetOneCfgFile(Constants::DISPLAY_MANAGER_CONFIG_RELATIVE_PATH.c_str(), buf, MAX_PATH_LEN);
    if (path != nullptr && *path != '\0') {
        configPath = path;
        usePolicyPath = true;
    }
#endif
    ACCOUNT_LOGI("Loading display user zone config from %{public}s path",
        usePolicyPath ? "policy" : "fallback");
    AccountFileOperator fileOperator;
    std::string content;
    ErrCode errCode = fileOperator.GetFileContentByPath(configPath, content);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to read display user zone config, err=%{public}d", errCode);
        ClearParsedData();
        configReadFailed_ = true;
        return errCode;
    }
    errCode = ParseDisplayConfig(content);
    if (errCode != ERR_OK) {
        configFormatError_ = true;
        ACCOUNT_LOGE("Failed to parse display user zone config, err=%{public}d", errCode);
        return errCode;
    }
    return ERR_OK;
}

ErrCode DisplayUserZoneConfigManager::EnsureConfigReady()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (configFormatError_) {
        return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
    }
    if (!configReadFailed_) {
        return ERR_OK;
    }
    if (configReadRetried_) {
        return ERR_ACCOUNT_COMMON_FILE_READ_FAILED;
    }
    configReadRetried_ = true;
    ErrCode errCode = LoadConfigLocked();
    if (errCode == ERR_OK) {
        return ERR_OK;
    }
    if (configFormatError_) {
        return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
    }
    return ERR_ACCOUNT_COMMON_FILE_READ_FAILED;
}

namespace {
xmlNodePtr FindDisplaysNode(xmlDocPtr doc)
{
    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (root == nullptr || xmlStrcmp(root->name, BAD_CAST "Configs") != 0) {
        return nullptr;
    }
    for (xmlNodePtr node = root->children; node != nullptr; node = node->next) {
        if (node->type != XML_ELEMENT_NODE || xmlStrcmp(node->name, BAD_CAST "displays") != 0) {
            continue;
        }
        return node;
    }
    return nullptr;
}
} // namespace

ErrCode DisplayUserZoneConfigManager::ParseDisplayConfig(const std::string &content)
{
    xmlDocPtr doc = xmlReadMemory(content.c_str(), static_cast<int>(content.size()),
        "display_manager_config.xml", nullptr, XML_PARSE_NOBLANKS);
    if (doc == nullptr) {
        ACCOUNT_LOGE("Failed to parse display user zone config XML");
        ClearParsedData();
        return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
    }
    xmlNodePtr displaysNode = FindDisplaysNode(doc);
    if (displaysNode == nullptr) {
        ACCOUNT_LOGE("Invalid XML: missing Configs or displays element");
        xmlFreeDoc(doc);
        ClearParsedData();
        return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
    }
    ErrCode errCode = ParseDisplayNodes(displaysNode);
    xmlFreeDoc(doc);
    if (errCode != ERR_OK) {
        ClearParsedData();
        return errCode;
    }
    return FinalizeParsedConfig();
}

ErrCode DisplayUserZoneConfigManager::ParseDisplayNodes(void *root)
{
    xmlNodePtr rootNode = static_cast<xmlNodePtr>(root);
    std::vector<DisplayConfigInfo> displays;
    std::map<uint64_t, uint64_t> physicalToLogical;
    ErrCode errCode = CollectDisplayNodes(rootNode, displays, physicalToLogical);
    if (errCode != ERR_OK) {
        return errCode;
    }
    return ResolveDisplayUserZones(displays, physicalToLogical);
}

ErrCode DisplayUserZoneConfigManager::CollectDisplayNodes(void *root,
    std::vector<DisplayConfigInfo> &displays, std::map<uint64_t, uint64_t> &physicalToLogical)
{
    xmlNodePtr rootNode = static_cast<xmlNodePtr>(root);
    for (xmlNodePtr node = rootNode->children; node != nullptr; node = node->next) {
        if (node->type != XML_ELEMENT_NODE || xmlStrcmp(node->name, BAD_CAST "display") != 0) {
            continue;
        }
        DisplayConfigInfo info;
        ErrCode errCode = ParseDisplayNodeAttributes(node, info);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("Failed to parse display node attributes, fallback to original validation path");
            ClearParsedData();
            return errCode;
        }
        if (physicalToLogical.find(info.physicalId) != physicalToLogical.end()) {
            ACCOUNT_LOGE("Duplicate physicalId=%{public}llu in config, fallback to original validation path",
                static_cast<unsigned long long>(info.physicalId));
            ClearParsedData();
            return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
        }
        displays.push_back(info);
        physicalToLogical[info.physicalId] = info.logicalId;
    }
    return ERR_OK;
}

ErrCode DisplayUserZoneConfigManager::ResolveDisplayUserZones(const std::vector<DisplayConfigInfo> &displays,
    const std::map<uint64_t, uint64_t> &physicalToLogical)
{
    for (const auto &info : displays) {
        if (logicalIdMap_.find(info.logicalId) != logicalIdMap_.end()) {
            ACCOUNT_LOGE("Duplicate logicalId=%{public}llu in config, fallback to original validation path",
                static_cast<unsigned long long>(info.logicalId));
            ClearParsedData();
            return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
        }
        DisplayConfigInfo resolved = info;
        if (info.hasUserZoneId) {
            auto it = physicalToLogical.find(info.userZoneId);
            if (it == physicalToLogical.end()) {
                ACCOUNT_LOGE("userZoneId=%{public}llu not found for display logicalId=%{public}llu",
                    static_cast<unsigned long long>(info.userZoneId),
                    static_cast<unsigned long long>(info.logicalId));
                ClearParsedData();
                return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
            }
            resolved.userZone = it->second;
        } else {
            resolved.userZone = info.logicalId;
        }
        logicalIdMap_[resolved.logicalId] = resolved;
        userZoneMap_[resolved.userZone].push_back(resolved.logicalId);
        if (resolved.userZone == resolved.logicalId) {
            userZonePrimaryMap_[resolved.userZone] = resolved.logicalId;
        }
        ACCOUNT_LOGI("Parsed display: logicalId=%{public}llu physicalId=%{public}llu group=%{public}llu "
            "name=%{public}s",
            static_cast<unsigned long long>(resolved.logicalId),
            static_cast<unsigned long long>(resolved.physicalId),
            static_cast<unsigned long long>(resolved.userZone), resolved.name.c_str());
    }
    ACCOUNT_LOGI("ParseDisplayNodes done, display count=%{public}zu user zone count=%{public}zu",
        logicalIdMap_.size(), userZoneMap_.size());
    return ERR_OK;
}

ErrCode DisplayUserZoneConfigManager::ParseDisplayNodeAttributes(void *node, DisplayConfigInfo &info)
{
    xmlNodePtr nodePtr = static_cast<xmlNodePtr>(node);
    for (xmlNodePtr child = nodePtr->children; child != nullptr; child = child->next) {
        if (child->type != XML_ELEMENT_NODE) {
            continue;
        }
        std::string name = reinterpret_cast<const char *>(child->name);
        xmlChar *nodeContent = xmlNodeGetContent(child);
        std::string value = (nodeContent != nullptr) ? reinterpret_cast<const char *>(nodeContent) : "";
        xmlFree(nodeContent);
        if (name == "physicalId") {
            if (info.hasPhysicalId || !ParseUInt64(value, info.physicalId)) {
                ACCOUNT_LOGE("Failed to parse physicalId, value=%{public}s", value.c_str());
                return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
            }
            info.hasPhysicalId = true;
        } else if (name == "logicalId") {
            if (info.hasLogicalId || !ParseUInt64(value, info.logicalId)) {
                ACCOUNT_LOGE("Failed to parse logicalId, value=%{public}s", value.c_str());
                return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
            }
            info.hasLogicalId = true;
        } else if (name == "name") {
            info.name = value;
        } else if (name == "userZoneId") {
            if (info.hasUserZoneId || !ParseUInt64(value, info.userZoneId)) {
                ACCOUNT_LOGE("Failed to parse userZoneId, value=%{public}s", value.c_str());
                return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
            }
            info.hasUserZoneId = true;
        }
    }
    if (!info.hasPhysicalId || !info.hasLogicalId) {
        ACCOUNT_LOGE("Display config is missing physicalId or logicalId");
        return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
    }
    return ERR_OK;
}

ErrCode DisplayUserZoneConfigManager::FinalizeParsedConfig()
{
    ErrCode errCode = ValidateParsedConfig();
    if (errCode != ERR_OK) {
        ClearParsedData();
        return errCode;
    }
    ACCOUNT_LOGI("Display user zone config loaded, display count: %{public}zu", logicalIdMap_.size());
    return ERR_OK;
}

void DisplayUserZoneConfigManager::ClearParsedData()
{
    logicalIdMap_.clear();
    userZoneMap_.clear();
    userZonePrimaryMap_.clear();
}

bool DisplayUserZoneConfigManager::ParseUInt64(const std::string &value, uint64_t &result)
{
    if (value.empty()) {
        return false;
    }
    auto res = std::from_chars(value.data(), value.data() + value.size(), result);
    return res.ec == std::errc{} && res.ptr == value.data() + value.size();
}

ErrCode DisplayUserZoneConfigManager::ValidateParsedConfig()
{
    if (userZonePrimaryMap_.empty()) {
        ACCOUNT_LOGE("No primary display found in config, fallback to original validation path");
        return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
    }
    for (const auto &pair : logicalIdMap_) {
        const DisplayConfigInfo &info = pair.second;
        if (info.userZone == info.logicalId) {
            continue;
        }
        auto primaryIt = logicalIdMap_.find(info.userZone);
        if (primaryIt == logicalIdMap_.end()) {
            ACCOUNT_LOGE("Secondary display logicalId=%{public}llu references non-existent primary "
                "group=%{public}llu, fallback to original validation path",
                static_cast<unsigned long long>(info.logicalId),
                static_cast<unsigned long long>(info.userZone));
            return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
        }
        if (primaryIt->second.userZone != primaryIt->second.logicalId) {
            ACCOUNT_LOGE("Secondary display logicalId=%{public}llu references display %{public}llu "
                "which is itself a secondary (group=%{public}llu), possible cycle",
                static_cast<unsigned long long>(info.logicalId),
                static_cast<unsigned long long>(primaryIt->second.logicalId),
                static_cast<unsigned long long>(primaryIt->second.userZone));
            return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
        }
    }
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
