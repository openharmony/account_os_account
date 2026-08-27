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

#include <gtest/gtest.h>
#define private public
#include "display_user_zone_config/display_user_zone_config_manager.h"
#undef private
#include "os_account_constants.h"

namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
using namespace OHOS;
using namespace AccountSA;

namespace {
constexpr uint64_t UNKNOWN_DISPLAY_ID = 88888888ULL;
constexpr uint64_t UNKNOWN_USER_ZONE_ID = 777;
constexpr uint64_t SOME_DISPLAY_ID = 100;
constexpr uint64_t SOME_USER_ZONE_ID = 200;
constexpr uint64_t DEFAULT_USER_ZONE_ID = 0;

// Display user zone config test fixtures
constexpr uint64_t DISPLAY_A_LOGICAL_ID = 100;
constexpr uint64_t DISPLAY_B_LOGICAL_ID = 200;
constexpr uint64_t DISPLAY_C_LOGICAL_ID = 300;
constexpr uint64_t DISPLAY_A_PHYSICAL_ID = 10;
constexpr uint64_t DISPLAY_B_PHYSICAL_ID = 20;
constexpr uint64_t DISPLAY_C_PHYSICAL_ID = 30;
constexpr uint64_t USER_ZONE_ONE = DISPLAY_A_LOGICAL_ID;
constexpr uint64_t USER_ZONE_TWO = DISPLAY_C_LOGICAL_ID;
constexpr uint64_t STALE_LOGICAL_ID = 99999;
const std::string DISPLAY_NAME_A = "display_a";
const std::string DISPLAY_NAME_B = "display_b";
const std::string DISPLAY_NAME_C = "display_c";

// Loop and display count constants
constexpr int LOOP_COUNT = 3;
constexpr size_t USER_ZONE_ONE_DISPLAY_COUNT = 2;
constexpr size_t USER_ZONE_TWO_DISPLAY_COUNT = 1;
}  // namespace

class DisplayUserZoneConfigManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);
};

namespace {
void SetupLoadedConfig(DisplayUserZoneConfigManager &mgr)
{
    DisplayConfigInfo infoA;
    infoA.physicalId = DISPLAY_A_PHYSICAL_ID;
    infoA.logicalId = DISPLAY_A_LOGICAL_ID;
    infoA.name = DISPLAY_NAME_A;
    infoA.userZone = USER_ZONE_ONE;
    DisplayConfigInfo infoB;
    infoB.physicalId = DISPLAY_B_PHYSICAL_ID;
    infoB.logicalId = DISPLAY_B_LOGICAL_ID;
    infoB.name = DISPLAY_NAME_B;
    infoB.userZone = USER_ZONE_ONE;
    DisplayConfigInfo infoC;
    infoC.physicalId = DISPLAY_C_PHYSICAL_ID;
    infoC.logicalId = DISPLAY_C_LOGICAL_ID;
    infoC.name = DISPLAY_NAME_C;
    infoC.userZone = USER_ZONE_TWO;
    mgr.logicalIdMap_[DISPLAY_A_LOGICAL_ID] = infoA;
    mgr.logicalIdMap_[DISPLAY_B_LOGICAL_ID] = infoB;
    mgr.logicalIdMap_[DISPLAY_C_LOGICAL_ID] = infoC;
    mgr.userZoneMap_[USER_ZONE_ONE] = {DISPLAY_A_LOGICAL_ID, DISPLAY_B_LOGICAL_ID};
    mgr.userZoneMap_[USER_ZONE_TWO] = {DISPLAY_C_LOGICAL_ID};
    mgr.userZonePrimaryMap_[USER_ZONE_ONE] = DISPLAY_A_LOGICAL_ID;
    mgr.userZonePrimaryMap_[USER_ZONE_TWO] = DISPLAY_C_LOGICAL_ID;
}

void TeardownConfig(DisplayUserZoneConfigManager &mgr)
{
    mgr.logicalIdMap_.clear();
    mgr.userZoneMap_.clear();
    mgr.userZonePrimaryMap_.clear();
    mgr.configReadFailed_ = false;
    mgr.configFormatError_ = false;
    mgr.configReadRetried_ = false;
}

void SetConfigLoadState(DisplayUserZoneConfigManager &mgr, bool readFailed, bool formatError, bool readRetried)
{
    mgr.configReadFailed_ = readFailed;
    mgr.configFormatError_ = formatError;
    mgr.configReadRetried_ = readRetried;
}

void SetUserZonePrimaryDisplay(DisplayUserZoneConfigManager &mgr, uint64_t userZone, uint64_t logicalId)
{
    mgr.userZonePrimaryMap_[userZone] = logicalId;
}
}  // namespace

void DisplayUserZoneConfigManagerTest::SetUpTestCase(void)
{}

void DisplayUserZoneConfigManagerTest::TearDownTestCase(void)
{}

void DisplayUserZoneConfigManagerTest::SetUp(void)
{}

void DisplayUserZoneConfigManagerTest::TearDown(void)
{}

/**
 * @tc.name: DisplayUserZoneConfigManagerFallback001
 * @tc.desc: Verify IsDisplayPrimary treats every display as primary when no display config is available.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayUserZoneConfigManagerTest, DisplayUserZoneConfigManagerFallback001, TestSize.Level1)
{
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    bool isPrimary = false;
    EXPECT_EQ(mgr.IsDisplayPrimary(Constants::DEFAULT_DISPLAY_ID, isPrimary), ERR_OK);
    EXPECT_TRUE(isPrimary);
    EXPECT_EQ(mgr.IsDisplayPrimary(SOME_DISPLAY_ID, isPrimary), ERR_OK);
    EXPECT_TRUE(isPrimary);
    EXPECT_EQ(mgr.IsDisplayPrimary(UNKNOWN_DISPLAY_ID, isPrimary), ERR_OK);
    EXPECT_TRUE(isPrimary);
}

/**
 * @tc.name: DisplayUserZoneConfigManagerReadFailure001
 * @tc.desc: Verify IsDisplayPrimary returns a file-read error after the one allowed retry has failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayUserZoneConfigManagerTest, DisplayUserZoneConfigManagerReadFailure001, TestSize.Level1)
{
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    SetConfigLoadState(mgr, true, false, true);
    bool isPrimary = false;
    EXPECT_EQ(mgr.IsDisplayPrimary(SOME_DISPLAY_ID, isPrimary), ERR_ACCOUNT_COMMON_FILE_READ_FAILED);
    TeardownConfig(mgr);
}

/**
 * @tc.name: DisplayUserZoneConfigManagerFormatError001
 * @tc.desc: Verify IsDisplayPrimary returns a format error without retrying an invalid config.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayUserZoneConfigManagerTest, DisplayUserZoneConfigManagerFormatError001, TestSize.Level1)
{
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    SetConfigLoadState(mgr, false, true, false);
    bool isPrimary = false;
    EXPECT_EQ(mgr.IsDisplayPrimary(SOME_DISPLAY_ID, isPrimary), ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR);
    TeardownConfig(mgr);
}

/**
 * @tc.name: DisplayUserZoneConfigManagerFallback002
 * @tc.desc: Verify HasDisplayByLogicalId returns false for any display id in fallback mode.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayUserZoneConfigManagerTest, DisplayUserZoneConfigManagerFallback002, TestSize.Level1)
{
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    EXPECT_FALSE(mgr.HasDisplayByLogicalId(Constants::DEFAULT_DISPLAY_ID));
    EXPECT_FALSE(mgr.HasDisplayByLogicalId(SOME_DISPLAY_ID));
    EXPECT_FALSE(mgr.HasDisplayByLogicalId(UNKNOWN_DISPLAY_ID));
}

/**
 * @tc.name: DisplayUserZoneConfigManagerFallback004
 * @tc.desc: Verify GetUserZonePrimaryDisplay returns nullptr for any group id in fallback mode.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayUserZoneConfigManagerTest, DisplayUserZoneConfigManagerFallback004, TestSize.Level1)
{
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    uint64_t primaryDisplayId = 0;
    EXPECT_FALSE(mgr.GetUserZonePrimaryDisplayId(DEFAULT_USER_ZONE_ID, primaryDisplayId));
    EXPECT_FALSE(mgr.GetUserZonePrimaryDisplayId(SOME_USER_ZONE_ID, primaryDisplayId));
    EXPECT_FALSE(mgr.GetUserZonePrimaryDisplayId(UNKNOWN_USER_ZONE_ID, primaryDisplayId));
}

/**
 * @tc.name: DisplayUserZoneConfigManagerFallback005
 * @tc.desc: Verify GetDisplayIdsByUserZone returns an empty vector for any group id in fallback mode.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayUserZoneConfigManagerTest, DisplayUserZoneConfigManagerFallback005, TestSize.Level1)
{
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    auto result = mgr.GetDisplayIdsByUserZone(DEFAULT_USER_ZONE_ID);
    EXPECT_TRUE(result.empty());
    result = mgr.GetDisplayIdsByUserZone(SOME_USER_ZONE_ID);
    EXPECT_TRUE(result.empty());
    result = mgr.GetDisplayIdsByUserZone(UNKNOWN_USER_ZONE_ID);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: DisplayUserZoneConfigManagerFallback006
 * @tc.desc: Verify GetUserZoneByLogicalId treats every display as an independent group in fallback mode.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayUserZoneConfigManagerTest, DisplayUserZoneConfigManagerFallback006, TestSize.Level1)
{
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    EXPECT_EQ(mgr.GetUserZoneByLogicalId(Constants::DEFAULT_DISPLAY_ID), Constants::DEFAULT_DISPLAY_ID);
    EXPECT_EQ(mgr.GetUserZoneByLogicalId(SOME_DISPLAY_ID), SOME_DISPLAY_ID);
    EXPECT_EQ(mgr.GetUserZoneByLogicalId(UNKNOWN_DISPLAY_ID), UNKNOWN_DISPLAY_ID);
}

/**
 * @tc.name: DisplayUserZoneConfigManagerFallbackConsistency001
 * @tc.desc: Verify repeated queries return consistent fallback results (no state mutation between calls).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayUserZoneConfigManagerTest, DisplayUserZoneConfigManagerFallbackConsistency001, TestSize.Level1)
{
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    bool primaryFirst = false;
    EXPECT_EQ(mgr.IsDisplayPrimary(SOME_DISPLAY_ID, primaryFirst), ERR_OK);
    uint64_t userZoneFirst = mgr.GetUserZoneByLogicalId(SOME_DISPLAY_ID);

    for (int i = 0; i < LOOP_COUNT; ++i) {
        bool isPrimary = false;
        EXPECT_EQ(mgr.IsDisplayPrimary(SOME_DISPLAY_ID, isPrimary), ERR_OK);
        EXPECT_EQ(isPrimary, primaryFirst);
        EXPECT_EQ(mgr.GetUserZoneByLogicalId(SOME_DISPLAY_ID), userZoneFirst);
        EXPECT_FALSE(mgr.HasDisplayByLogicalId(SOME_DISPLAY_ID));
        EXPECT_TRUE(mgr.GetDisplayIdsByUserZone(SOME_USER_ZONE_ID).empty());
    }
}

/**
 * @tc.name: DisplayUserZoneConfigManagerLoaded001
 * @tc.desc: Verify IsDisplayPrimary returns true for primary display, false for non-primary display,
 *           and true for unknown display (fallback) when config is loaded.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayUserZoneConfigManagerTest, DisplayUserZoneConfigManagerLoaded001, TestSize.Level1)
{
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    SetupLoadedConfig(mgr);
    bool isPrimary = false;
    EXPECT_EQ(mgr.IsDisplayPrimary(DISPLAY_A_LOGICAL_ID, isPrimary), ERR_OK);
    EXPECT_TRUE(isPrimary);
    EXPECT_EQ(mgr.IsDisplayPrimary(DISPLAY_B_LOGICAL_ID, isPrimary), ERR_OK);
    EXPECT_FALSE(isPrimary);
    EXPECT_EQ(mgr.IsDisplayPrimary(UNKNOWN_DISPLAY_ID, isPrimary), ERR_OK);
    EXPECT_TRUE(isPrimary);
    TeardownConfig(mgr);
}

/**
 * @tc.name: DisplayUserZoneConfigManagerLoaded002
 * @tc.desc: Verify HasDisplayByLogicalId returns true for known displays and false for unknown displays.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayUserZoneConfigManagerTest, DisplayUserZoneConfigManagerLoaded002, TestSize.Level1)
{
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    SetupLoadedConfig(mgr);
    EXPECT_TRUE(mgr.HasDisplayByLogicalId(DISPLAY_A_LOGICAL_ID));
    EXPECT_FALSE(mgr.HasDisplayByLogicalId(UNKNOWN_DISPLAY_ID));
    TeardownConfig(mgr);
}

/**
 * @tc.name: DisplayUserZoneConfigManagerLoaded004
 * @tc.desc: Verify GetUserZonePrimaryDisplayId returns the primary for known groups and false when unavailable.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayUserZoneConfigManagerTest, DisplayUserZoneConfigManagerLoaded004, TestSize.Level1)
{
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    SetupLoadedConfig(mgr);
    uint64_t primaryDisplayId = 0;
    EXPECT_TRUE(mgr.GetUserZonePrimaryDisplayId(USER_ZONE_ONE, primaryDisplayId));
    EXPECT_EQ(primaryDisplayId, DISPLAY_A_LOGICAL_ID);
    EXPECT_FALSE(mgr.GetUserZonePrimaryDisplayId(UNKNOWN_USER_ZONE_ID, primaryDisplayId));
    // Simulate stale userZonePrimaryMap_ entry pointing to a logicalId not in logicalIdMap_.
    SetUserZonePrimaryDisplay(mgr, USER_ZONE_ONE, STALE_LOGICAL_ID);
    EXPECT_FALSE(mgr.GetUserZonePrimaryDisplayId(USER_ZONE_ONE, primaryDisplayId));
    TeardownConfig(mgr);
}

/**
 * @tc.name: DisplayUserZoneConfigManagerLoaded005
 * @tc.desc: Verify GetDisplayIdsByUserZone returns all display ids for known groups and empty for unknown groups.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayUserZoneConfigManagerTest, DisplayUserZoneConfigManagerLoaded005, TestSize.Level1)
{
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    SetupLoadedConfig(mgr);
    auto result = mgr.GetDisplayIdsByUserZone(USER_ZONE_ONE);
    EXPECT_EQ(result.size(), USER_ZONE_ONE_DISPLAY_COUNT);
    result = mgr.GetDisplayIdsByUserZone(USER_ZONE_TWO);
    EXPECT_EQ(result.size(), USER_ZONE_TWO_DISPLAY_COUNT);
    result = mgr.GetDisplayIdsByUserZone(UNKNOWN_USER_ZONE_ID);
    EXPECT_TRUE(result.empty());
    TeardownConfig(mgr);
}

/**
 * @tc.name: DisplayUserZoneConfigManagerLoaded006
 * @tc.desc: Verify GetUserZoneByLogicalId returns the configured group for known displays and an independent group
 *           for an unknown display.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayUserZoneConfigManagerTest, DisplayUserZoneConfigManagerLoaded006, TestSize.Level1)
{
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    SetupLoadedConfig(mgr);
    EXPECT_EQ(mgr.GetUserZoneByLogicalId(DISPLAY_A_LOGICAL_ID), USER_ZONE_ONE);
    EXPECT_EQ(mgr.GetUserZoneByLogicalId(DISPLAY_C_LOGICAL_ID), USER_ZONE_TWO);
    EXPECT_EQ(mgr.GetUserZoneByLogicalId(UNKNOWN_DISPLAY_ID), UNKNOWN_DISPLAY_ID);
    TeardownConfig(mgr);
}

#ifdef ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
/**
 * @tc.name: DisplayUserZoneConfigManagerParseConfig001
 * @tc.desc: Verify ParseDisplayConfig successfully parses a valid XML where the primary display
 *           has no <userZoneId> tag (standalone) and the secondary display references
 *           the primary via <userZoneId>.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayUserZoneConfigManagerTest, DisplayUserZoneConfigManagerParseConfig001, TestSize.Level1)
{
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    std::string validXml =
        "<Configs>"
        "  <displays>"
        "    <display>"
        "      <physicalId>10</physicalId>"
        "      <logicalId>100</logicalId>"
        "      <name>display_a</name>"
        "    </display>"
        "    <display>"
        "      <physicalId>20</physicalId>"
        "      <logicalId>200</logicalId>"
        "      <name>display_b</name>"
        "      <userZoneId>10</userZoneId>"
        "    </display>"
        "  </displays>"
        "</Configs>";
    ErrCode ret = mgr.ParseDisplayConfig(validXml);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(mgr.GetUserZoneByLogicalId(DISPLAY_A_LOGICAL_ID), USER_ZONE_ONE);
    EXPECT_EQ(mgr.GetUserZoneByLogicalId(DISPLAY_B_LOGICAL_ID), USER_ZONE_ONE);
    bool isPrimary = false;
    EXPECT_EQ(mgr.IsDisplayPrimary(DISPLAY_A_LOGICAL_ID, isPrimary), ERR_OK);
    EXPECT_TRUE(isPrimary);
    EXPECT_EQ(mgr.IsDisplayPrimary(DISPLAY_B_LOGICAL_ID, isPrimary), ERR_OK);
    EXPECT_FALSE(isPrimary);
    TeardownConfig(mgr);
}

/**
 * @tc.name: DisplayUserZoneConfigManagerParseConfig002
 * @tc.desc: Verify ParseDisplayConfig returns BAD_JSON_FORMAT for invalid XML and wrong root element.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayUserZoneConfigManagerTest, DisplayUserZoneConfigManagerParseConfig002, TestSize.Level1)
{
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    // Non-XML content
    ErrCode ret = mgr.ParseDisplayConfig("this is not xml");
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR);
    // Wrong root element
    std::string wrongRoot = "<wrong_root></wrong_root>";
    ret = mgr.ParseDisplayConfig(wrongRoot);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR);
    TeardownConfig(mgr);
}

/**
 * @tc.name: DisplayUserZoneConfigManagerParseConfig003
 * @tc.desc: Verify ParseDisplayConfig fails when a secondary display references a non-existent
 *           primary via userZoneId (no display with that physicalId exists).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayUserZoneConfigManagerTest, DisplayUserZoneConfigManagerParseConfig003, TestSize.Level1)
{
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    std::string noPrimaryXml =
        "<Configs>"
        "  <displays>"
        "    <display>"
        "      <physicalId>10</physicalId>"
        "      <logicalId>100</logicalId>"
        "      <name>display_a</name>"
        "      <userZoneId>999</userZoneId>"
        "    </display>"
        "  </displays>"
        "</Configs>";
    ErrCode ret = mgr.ParseDisplayConfig(noPrimaryXml);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR);
    TeardownConfig(mgr);
}

/**
 * @tc.name: DisplayUserZoneConfigManagerParseConfig004
 * @tc.desc: Verify ParseDisplayNodes fails when a display node has invalid numeric attributes.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayUserZoneConfigManagerTest, DisplayUserZoneConfigManagerParseConfig004, TestSize.Level1)
{
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    std::string badAttrXml =
        "<Configs>"
        "  <displays>"
        "    <display>"
        "      <physicalId>abc</physicalId>"
        "      <logicalId>100</logicalId>"
        "      <name>display_a</name>"
        "    </display>"
        "  </displays>"
        "</Configs>";
    ErrCode ret = mgr.ParseDisplayConfig(badAttrXml);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR);
    TeardownConfig(mgr);
}

/**
 * @tc.name: DisplayUserZoneConfigManagerParseConfig005
 * @tc.desc: Verify ParseDisplayConfig fails on duplicate logicalId in the config.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayUserZoneConfigManagerTest, DisplayUserZoneConfigManagerParseConfig005, TestSize.Level1)
{
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    std::string dupXml =
        "<Configs>"
        "  <displays>"
        "    <display>"
        "      <physicalId>10</physicalId>"
        "      <logicalId>100</logicalId>"
        "      <name>display_a</name>"
        "    </display>"
        "    <display>"
        "      <physicalId>20</physicalId>"
        "      <logicalId>100</logicalId>"
        "      <name>display_dup</name>"
        "    </display>"
        "  </displays>"
        "</Configs>";
    ErrCode ret = mgr.ParseDisplayConfig(dupXml);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR);
    TeardownConfig(mgr);
}

/**
 * @tc.name: DisplayUserZoneConfigManagerParseConfig006
 * @tc.desc: Verify ParseDisplayConfig fails when two secondary displays form a cycle
 *           (each points to the other's physicalId via userZoneId, but neither is standalone).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayUserZoneConfigManagerTest, DisplayUserZoneConfigManagerParseConfig006, TestSize.Level1)
{
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    std::string cycleXml =
        "<Configs>"
        "  <displays>"
        "    <display>"
        "      <physicalId>10</physicalId>"
        "      <logicalId>100</logicalId>"
        "      <name>display_a</name>"
        "      <userZoneId>20</userZoneId>"
        "    </display>"
        "    <display>"
        "      <physicalId>20</physicalId>"
        "      <logicalId>200</logicalId>"
        "      <name>display_b</name>"
        "      <userZoneId>10</userZoneId>"
        "    </display>"
        "  </displays>"
        "</Configs>";
    ErrCode ret = mgr.ParseDisplayConfig(cycleXml);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR);
    TeardownConfig(mgr);
}

/**
 * @tc.name: DisplayUserZoneConfigManagerParseConfig007
 * @tc.desc: Verify ParseDisplayConfig loads a valid standalone-only configuration: every display
 *           is its own user zone and all lookup maps are populated.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayUserZoneConfigManagerTest, DisplayUserZoneConfigManagerParseConfig007, TestSize.Level1)
{
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    std::string standaloneXml =
        "<Configs>"
        "  <displays>"
        "    <display>"
        "      <physicalId>10</physicalId>"
        "      <logicalId>100</logicalId>"
        "      <name>display_a</name>"
        "    </display>"
        "    <display>"
        "      <physicalId>20</physicalId>"
        "      <logicalId>300</logicalId>"
        "      <name>display_c</name>"
        "    </display>"
        "  </displays>"
        "</Configs>";
    ErrCode ret = mgr.ParseDisplayConfig(standaloneXml);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(mgr.HasDisplayByLogicalId(DISPLAY_A_LOGICAL_ID));
    EXPECT_TRUE(mgr.HasDisplayByLogicalId(DISPLAY_C_LOGICAL_ID));
    EXPECT_EQ(mgr.GetUserZoneByLogicalId(DISPLAY_A_LOGICAL_ID), DISPLAY_A_LOGICAL_ID);
    uint64_t primaryDisplayId = 0;
    EXPECT_TRUE(mgr.GetUserZonePrimaryDisplayId(DISPLAY_A_LOGICAL_ID, primaryDisplayId));
    EXPECT_EQ(primaryDisplayId, DISPLAY_A_LOGICAL_ID);
    auto userZoneDisplays = mgr.GetDisplayIdsByUserZone(DISPLAY_C_LOGICAL_ID);
    ASSERT_EQ(userZoneDisplays.size(), 1u);
    EXPECT_EQ(userZoneDisplays[0], DISPLAY_C_LOGICAL_ID);
    TeardownConfig(mgr);
}

/**
 * @tc.name: DisplayUserZoneConfigManagerParseConfig008
 * @tc.desc: Verify ParseDisplayConfig rejects a display missing either required ID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayUserZoneConfigManagerTest, DisplayUserZoneConfigManagerParseConfig008, TestSize.Level1)
{
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    std::string missingPhysicalIdXml =
        "<Configs><displays><display><logicalId>100</logicalId></display></displays></Configs>";
    EXPECT_EQ(mgr.ParseDisplayConfig(missingPhysicalIdXml), ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR);
    EXPECT_FALSE(mgr.HasDisplayByLogicalId(DISPLAY_A_LOGICAL_ID));

    std::string missingLogicalIdXml =
        "<Configs><displays><display><physicalId>10</physicalId></display></displays></Configs>";
    EXPECT_EQ(mgr.ParseDisplayConfig(missingLogicalIdXml), ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR);
    EXPECT_FALSE(mgr.HasDisplayByLogicalId(DISPLAY_A_LOGICAL_ID));
    TeardownConfig(mgr);
}

/**
 * @tc.name: DisplayUserZoneConfigManagerParseConfig009
 * @tc.desc: Verify ParseDisplayConfig rejects repeated required IDs in one display node.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayUserZoneConfigManagerTest, DisplayUserZoneConfigManagerParseConfig009, TestSize.Level1)
{
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    std::string duplicatePhysicalIdXml =
        "<Configs><displays><display><physicalId>10</physicalId><physicalId>11</physicalId>"
        "<logicalId>100</logicalId></display></displays></Configs>";
    EXPECT_EQ(mgr.ParseDisplayConfig(duplicatePhysicalIdXml), ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR);
    EXPECT_FALSE(mgr.HasDisplayByLogicalId(DISPLAY_A_LOGICAL_ID));

    std::string duplicateLogicalIdXml =
        "<Configs><displays><display><physicalId>10</physicalId><logicalId>100</logicalId>"
        "<logicalId>101</logicalId></display></displays></Configs>";
    EXPECT_EQ(mgr.ParseDisplayConfig(duplicateLogicalIdXml), ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR);
    EXPECT_FALSE(mgr.HasDisplayByLogicalId(DISPLAY_A_LOGICAL_ID));
    TeardownConfig(mgr);
}

/**
 * @tc.name: DisplayUserZoneConfigManagerParseUInt001
 * @tc.desc: Verify ParseUInt64 handles empty, invalid, and valid inputs correctly.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DisplayUserZoneConfigManagerTest, DisplayUserZoneConfigManagerParseUInt001, TestSize.Level1)
{
    auto &mgr = DisplayUserZoneConfigManager::GetInstance();
    const std::string parseUint64Input = "12345";
    constexpr uint64_t parseUint64Expected = 12345;
    uint64_t val64 = 0;
    EXPECT_FALSE(mgr.ParseUInt64("", val64));
    EXPECT_FALSE(mgr.ParseUInt64("abc", val64));
    EXPECT_TRUE(mgr.ParseUInt64(parseUint64Input, val64));
    EXPECT_EQ(val64, parseUint64Expected);
}
#endif // ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
}  // namespace AccountSA
}  // namespace OHOS
