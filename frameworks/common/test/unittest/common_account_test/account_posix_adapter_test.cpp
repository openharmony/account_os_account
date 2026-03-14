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
#include <sys/stat.h>
#include <unistd.h>
#include "account_error_no.h"
#include "account_posix_adapter.h"
#include "account_posix_tools.h"

using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;

namespace {
const std::string TEST_POSIX_MAP_DIR = "/data/service/el1/public/account/test/";
const std::string TEST_POSIX_MAP_FILE = TEST_POSIX_MAP_DIR + "account_posix_map";
const std::string TEST_FAULT_FLAG_FILE = TEST_POSIX_MAP_DIR + ".fault_flag";
const int32_t UID_TRANSFORM_DIVISOR = 200000;
const size_t BUF_SIZE = 1024;
}

class AccountPosixAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    void SetUp();
    void TearDown();
};

void AccountPosixAdapterTest::SetUpTestCase()
{
    mkdir(TEST_POSIX_MAP_DIR.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
}

void AccountPosixAdapterTest::TearDownTestCase()
{
    std::string cmd = "rm -rf " + TEST_POSIX_MAP_DIR;
    system(cmd.c_str());
}

void AccountPosixAdapterTest::SetUp() {}

void AccountPosixAdapterTest::TearDown()
{
    std::string cmd = "rm -f " + TEST_POSIX_MAP_FILE + "*";
    system(cmd.c_str());
}

/**
 * @tc.name: PosixDataMapTest001
 * @tc.desc: Test GetAccountNameByLocalId with valid local ID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixDataMapTest001, TestSize.Level1)
{
    PosixDataMap dataMap;
    dataMap.ModifyByLocalId(100, "testAccount");
    
    std::string accountName;
    ErrCode ret = dataMap.GetAccountNameByLocalId(100, accountName);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(accountName, "testAccount");
}

/**
 * @tc.name: PosixDataMapTest002
 * @tc.desc: Test GetAccountNameByLocalId with non-existent local ID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixDataMapTest002, TestSize.Level1)
{
    PosixDataMap dataMap;
    dataMap.ModifyByLocalId(100, "testAccount");
    
    std::string accountName;
    ErrCode ret = dataMap.GetAccountNameByLocalId(999, accountName);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: PosixDataMapTest003
 * @tc.desc: Test GetLocalIdByAccountName with valid account name.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixDataMapTest003, TestSize.Level1)
{
    PosixDataMap dataMap;
    dataMap.ModifyByLocalId(100, "testAccount");
    
    int32_t localId;
    ErrCode ret = dataMap.GetLocalIdByAccountName("testAccount", localId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(localId, 100);
}

/**
 * @tc.name: PosixDataMapTest004
 * @tc.desc: Test GetLocalIdByAccountName with non-existent account name.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixDataMapTest004, TestSize.Level1)
{
    PosixDataMap dataMap;
    dataMap.ModifyByLocalId(100, "testAccount");
    
    int32_t localId;
    ErrCode ret = dataMap.GetLocalIdByAccountName("nonexistent", localId);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: PosixDataMapTest005
 * @tc.desc: Test DeleteByLocalId with existing local ID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixDataMapTest005, TestSize.Level1)
{
    PosixDataMap dataMap;
    dataMap.ModifyByLocalId(100, "testAccount");
    
    dataMap.DeleteByLocalId(100);
    
    std::string accountName;
    ErrCode ret = dataMap.GetAccountNameByLocalId(100, accountName);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: PosixDataMapTest006
 * @tc.desc: Test DeleteByLocalId with non-existent local ID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixDataMapTest006, TestSize.Level1)
{
    PosixDataMap dataMap;
    dataMap.ModifyByLocalId(100, "testAccount");
    
    dataMap.DeleteByLocalId(999);
    
    std::string accountName;
    ErrCode ret = dataMap.GetAccountNameByLocalId(100, accountName);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(accountName, "testAccount");
}

/**
 * @tc.name: PosixDataMapTest007
 * @tc.desc: Test ModifyByLocalId to update existing entry.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixDataMapTest007, TestSize.Level1)
{
    PosixDataMap dataMap;
    dataMap.ModifyByLocalId(100, "testAccount");
    dataMap.ModifyByLocalId(100, "updatedAccount");
    
    std::string accountName;
    ErrCode ret = dataMap.GetAccountNameByLocalId(100, accountName);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(accountName, "updatedAccount");
}

/**
 * @tc.name: PosixDataMapTest008
 * @tc.desc: Test ModifyByLocalId to add new entry.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixDataMapTest008, TestSize.Level1)
{
    PosixDataMap dataMap;
    dataMap.ModifyByLocalId(100, "testAccount");
    dataMap.ModifyByLocalId(200, "newAccount");
    
    std::string accountName;
    ErrCode ret = dataMap.GetAccountNameByLocalId(200, accountName);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(accountName, "newAccount");
}

/**
 * @tc.name: PosixDataMapTest009
 * @tc.desc: Test ToString with empty map.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixDataMapTest009, TestSize.Level1)
{
    PosixDataMap dataMap;
    std::string result = dataMap.ToString();
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: PosixDataMapTest010
 * @tc.desc: Test ToString with populated map.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixDataMapTest010, TestSize.Level1)
{
    PosixDataMap dataMap;
    dataMap.ModifyByLocalId(100, "account1");
    dataMap.ModifyByLocalId(200, "account2");
    
    std::string result = dataMap.ToString();
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("100:account1"), std::string::npos);
    EXPECT_NE(result.find("200:account2"), std::string::npos);
}

/**
 * @tc.name: PosixDataMapTest011
 * @tc.desc: Test FromString with empty string.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixDataMapTest011, TestSize.Level1)
{
    PosixDataMap dataMap;
    ErrCode ret = dataMap.FromString("");
    EXPECT_EQ(ret, ERR_OK);
    
    std::string accountName;
    ret = dataMap.GetAccountNameByLocalId(100, accountName);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: PosixDataMapTest012
 * @tc.desc: Test FromString with valid format.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixDataMapTest012, TestSize.Level1)
{
    PosixDataMap dataMap;
    std::string data = "100:account1\n200:account2\n";
    ErrCode ret = dataMap.FromString(data);
    EXPECT_EQ(ret, ERR_OK);
    
    std::string accountName;
    ret = dataMap.GetAccountNameByLocalId(100, accountName);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(accountName, "account1");
    
    ret = dataMap.GetAccountNameByLocalId(200, accountName);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(accountName, "account2");
}

/**
 * @tc.name: PosixDataMapTest013
 * @tc.desc: Test FromString with invalid number format.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixDataMapTest013, TestSize.Level1)
{
    PosixDataMap dataMap;
    std::string data = "invalid:account1\n";
    ErrCode ret = dataMap.FromString(data);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: PosixDataMapTest014
 * @tc.desc: Test FromString with multiple lines.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixDataMapTest014, TestSize.Level1)
{
    PosixDataMap dataMap;
    std::string data = "100:account1\n200:account2\n300:account3\n";
    ErrCode ret = dataMap.FromString(data);
    EXPECT_EQ(ret, ERR_OK);
    
    std::string accountName;
    ret = dataMap.GetAccountNameByLocalId(100, accountName);
    EXPECT_EQ(ret, ERR_OK);
    
    ret = dataMap.GetAccountNameByLocalId(200, accountName);
    EXPECT_EQ(ret, ERR_OK);
    
    ret = dataMap.GetAccountNameByLocalId(300, accountName);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: CppPasswdTypeTest001
 * @tc.desc: Test GetBufSize with default values.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, CppPasswdTypeTest001, TestSize.Level1)
{
    CppPasswdType passwd;
    size_t size = passwd.GetBufSize();
    EXPECT_GT(size, 0U);
}

/**
 * @tc.name: CppPasswdTypeTest002
 * @tc.desc: Test GetBufSize with custom values.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, CppPasswdTypeTest002, TestSize.Level1)
{
    CppPasswdType passwd;
    passwd.pw_name = "testuser";
    
    size_t size = passwd.GetBufSize();
    EXPECT_GT(size, 0U);
}

/**
 * @tc.name: CppPasswdTypeTest003
 * @tc.desc: Test CopyToOutput with sufficient buffer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, CppPasswdTypeTest003, TestSize.Level1)
{
    CppPasswdType passwd;
    passwd.pw_name = "testuser";
    passwd.pw_uid = 100;
    passwd.pw_gid = 100;
    
    struct passwd pw;
    char buf[BUF_SIZE] = {0};
    ErrCode ret = passwd.CopyToOutput(&pw, buf, sizeof(buf));
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_STREQ(pw.pw_name, "testuser");
    EXPECT_EQ(pw.pw_uid, 100);
    EXPECT_EQ(pw.pw_gid, 100);
}

/**
 * @tc.name: CppPasswdTypeTest004
 * @tc.desc: Test CopyToOutput with insufficient buffer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, CppPasswdTypeTest004, TestSize.Level1)
{
    CppPasswdType passwd;
    passwd.pw_name = "verylongusername";
    
    struct passwd pw;
    char buf[5] = {0};
    ErrCode ret = passwd.CopyToOutput(&pw, buf, sizeof(buf));
    EXPECT_EQ(ret, ERANGE);
}

/**
 * @tc.name: CppGroupTypeTest001
 * @tc.desc: Test GetBufSize with default values.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, CppGroupTypeTest001, TestSize.Level1)
{
    CppGroupType group;
    size_t size = group.GetBufSize();
    EXPECT_GT(size, 0U);
}

/**
 * @tc.name: CppGroupTypeTest002
 * @tc.desc: Test GetBufSize with custom values.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, CppGroupTypeTest002, TestSize.Level1)
{
    CppGroupType group;
    group.gr_name = "testgroup";
    
    size_t size = group.GetBufSize();
    EXPECT_GT(size, 0U);
}

/**
 * @tc.name: CppGroupTypeTest003
 * @tc.desc: Test CopyToOutput with sufficient buffer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, CppGroupTypeTest003, TestSize.Level1)
{
    CppGroupType group;
    group.gr_name = "testgroup";
    group.gr_gid = 100;
    
    struct group gr;
    char buf[BUF_SIZE] = {0};
    ErrCode ret = group.CopyToOutput(&gr, buf, sizeof(buf));
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_STREQ(gr.gr_name, "testgroup");
    EXPECT_EQ(gr.gr_gid, 100);
    EXPECT_EQ(gr.gr_mem, nullptr);
}

/**
 * @tc.name: CppGroupTypeTest004
 * @tc.desc: Test CopyToOutput with insufficient buffer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, CppGroupTypeTest004, TestSize.Level1)
{
    CppGroupType group;
    group.gr_name = "verylonggroupname";
    
    struct group gr;
    char buf[5] = {0};
    ErrCode ret = group.CopyToOutput(&gr, buf, sizeof(buf));
    EXPECT_EQ(ret, ERANGE);
}

/**
 * @tc.name: PosixToolsTest001
 * @tc.desc: Test CheckAccountNameValid with valid names.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixToolsTest001, TestSize.Level1)
{
    EXPECT_TRUE(PosixTools::CheckAccountNameValid("testAccount"));
    EXPECT_TRUE(PosixTools::CheckAccountNameValid("Test123"));
    EXPECT_TRUE(PosixTools::CheckAccountNameValid("test_account"));
    EXPECT_TRUE(PosixTools::CheckAccountNameValid("test-account"));
    EXPECT_TRUE(PosixTools::CheckAccountNameValid("test.account"));
}

/**
 * @tc.name: PosixToolsTest002
 * @tc.desc: Test CheckAccountNameValid with invalid characters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixToolsTest002, TestSize.Level1)
{
    EXPECT_FALSE(PosixTools::CheckAccountNameValid("test account"));
    EXPECT_FALSE(PosixTools::CheckAccountNameValid("test@account"));
    EXPECT_FALSE(PosixTools::CheckAccountNameValid("test#account"));
    EXPECT_FALSE(PosixTools::CheckAccountNameValid("test,account"));
    EXPECT_FALSE(PosixTools::CheckAccountNameValid("test/account"));
}

/**
 * @tc.name: PosixToolsTest003
 * @tc.desc: Test CheckAccountNameValid with empty string.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixToolsTest003, TestSize.Level1)
{
    EXPECT_FALSE(PosixTools::CheckAccountNameValid(""));
}

/**
 * @tc.name: PosixToolsTest004
 * @tc.desc: Test GetLocalIdFromUid with normal UID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixToolsTest004, TestSize.Level1)
{
    int32_t uid = 100 * UID_TRANSFORM_DIVISOR + 50;
    int32_t localId = PosixTools::GetLocalIdFromUid(uid);
    EXPECT_EQ(localId, 100);
}

/**
 * @tc.name: PosixToolsTest005
 * @tc.desc: Test GetLocalIdFromUid with boundary values.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixToolsTest005, TestSize.Level1)
{
    EXPECT_EQ(PosixTools::GetLocalIdFromUid(0), 0);
    EXPECT_EQ(PosixTools::GetLocalIdFromUid(UID_TRANSFORM_DIVISOR - 1), 0);
    EXPECT_EQ(PosixTools::GetLocalIdFromUid(UID_TRANSFORM_DIVISOR), 1);
}

/**
 * @tc.name: PosixToolsTest006
 * @tc.desc: Test GetAppIdFromUid with normal UID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixToolsTest006, TestSize.Level1)
{
    int32_t uid = 100 * UID_TRANSFORM_DIVISOR + 50;
    int32_t appId = PosixTools::GetAppIdFromUid(uid);
    EXPECT_EQ(appId, 50);
}

/**
 * @tc.name: PosixToolsTest007
 * @tc.desc: Test GetAppIdFromUid with boundary values.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixToolsTest007, TestSize.Level1)
{
    EXPECT_EQ(PosixTools::GetAppIdFromUid(0), 0);
    EXPECT_EQ(PosixTools::GetAppIdFromUid(UID_TRANSFORM_DIVISOR - 1), UID_TRANSFORM_DIVISOR - 1);
    EXPECT_EQ(PosixTools::GetAppIdFromUid(UID_TRANSFORM_DIVISOR), 0);
}

/**
 * @tc.name: PosixToolsTest008
 * @tc.desc: Test GenerateGroupName with default appIdx.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixToolsTest008, TestSize.Level1)
{
    std::string groupName = PosixTools::GenerateGroupName("testAccount");
    EXPECT_EQ(groupName, "testAccount_a0");
}

/**
 * @tc.name: PosixToolsTest009
 * @tc.desc: Test GenerateGroupName with custom appIdx.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixToolsTest009, TestSize.Level1)
{
    std::string groupName = PosixTools::GenerateGroupName("testAccount", 10);
    EXPECT_EQ(groupName, "testAccount_a10");
}

/**
 * @tc.name: PosixToolsTest010
 * @tc.desc: Test GenerateUid with normal values.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixToolsTest010, TestSize.Level1)
{
    int32_t uid = PosixTools::GenerateUid(100, 50);
    EXPECT_EQ(uid, 100 * UID_TRANSFORM_DIVISOR + 50);
}

/**
 * @tc.name: PosixToolsTest011
 * @tc.desc: Test GenerateUid with boundary values.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixToolsTest011, TestSize.Level1)
{
    EXPECT_EQ(PosixTools::GenerateUid(0, 0), 0);
    EXPECT_EQ(PosixTools::GenerateUid(1, 0), UID_TRANSFORM_DIVISOR);
    EXPECT_EQ(PosixTools::GenerateUid(0, 1), 1);
}

/**
 * @tc.name: PosixToolsTest012
 * @tc.desc: Test WritePosixMapFile success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixToolsTest012, TestSize.Level1)
{
    std::string content = "100:account1\n200:account2\n";
    ErrCode ret = PosixTools::WritePosixMapFile(content);
    EXPECT_EQ(ret, ERR_OK);
    
    bool isExist = false;
    ret = PosixTools::IsPosixMapFileExist(isExist);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(isExist);
}

/**
 * @tc.name: PosixToolsTest013
 * @tc.desc: Test IsPosixMapFileExist when file exists.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixToolsTest013, TestSize.Level1)
{
    std::string content = "100:account1\n";
    PosixTools::WritePosixMapFile(content);
    
    bool isExist = false;
    ErrCode ret = PosixTools::IsPosixMapFileExist(isExist);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(isExist);
}

/**
 * @tc.name: PosixToolsTest014
 * @tc.desc: Test IsPosixMapFileExist when file does not exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixToolsTest014, TestSize.Level1)
{
    bool isExist = false;
    ErrCode ret = PosixTools::IsPosixMapFileExist(isExist);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isExist);
}

/**
 * @tc.name: PosixToolsTest015
 * @tc.desc: Test CreateFaultFlagFile success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixToolsTest015, TestSize.Level1)
{
    ErrCode ret = PosixTools::CreateFaultFlagFile();
    EXPECT_EQ(ret, ERR_OK);
    
    bool isExist = false;
    ret = PosixTools::IsFaultFlagFileExist(isExist);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(isExist);
}

/**
 * @tc.name: PosixToolsTest016
 * @tc.desc: Test RemoveFaultFlagFile success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixToolsTest016, TestSize.Level1)
{
    PosixTools::CreateFaultFlagFile();
    
    ErrCode ret = PosixTools::RemoveFaultFlagFile();
    EXPECT_EQ(ret, ERR_OK);
    
    bool isExist = false;
    ret = PosixTools::IsFaultFlagFileExist(isExist);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isExist);
}

/**
 * @tc.name: PosixToolsTest017
 * @tc.desc: Test IsFaultFlagFileExist when file exists.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixToolsTest017, TestSize.Level1)
{
    PosixTools::CreateFaultFlagFile();
    
    bool isExist = false;
    ErrCode ret = PosixTools::IsFaultFlagFileExist(isExist);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(isExist);
}

/**
 * @tc.name: PosixToolsTest018
 * @tc.desc: Test IsFaultFlagFileExist when file does not exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, PosixToolsTest018, TestSize.Level1)
{
    PosixTools::RemoveFaultFlagFile();
    bool isExist = false;
    ErrCode ret = PosixTools::IsFaultFlagFileExist(isExist);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isExist);
}

/**
 * @tc.name: AccountPosixAdapterTest001
 * @tc.desc: Test oh_getusername with valid UID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, AccountPosixAdapterTest001, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);
    
    int32_t uid = PosixTools::GenerateUid(100);
    char *username = oh_getusername(static_cast<uid_t>(uid));
    ASSERT_NE(username, nullptr);
    EXPECT_STREQ(username, "testAccount");
}

/**
 * @tc.name: AccountPosixAdapterTest002
 * @tc.desc: Test oh_getusername with non-existent UID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, AccountPosixAdapterTest002, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);
    
    int32_t uid = PosixTools::GenerateUid(999);
    char *username = oh_getusername(static_cast<uid_t>(uid));
    EXPECT_EQ(username, nullptr);
}

/**
 * @tc.name: AccountPosixAdapterTest003
 * @tc.desc: Test oh_getgroupname with valid GID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, AccountPosixAdapterTest003, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);
    
    int32_t gid = PosixTools::GenerateUid(100);
    char *groupname = oh_getgroupname(static_cast<gid_t>(gid));
    ASSERT_NE(groupname, nullptr);
    EXPECT_STREQ(groupname, "testAccount");
}

/**
 * @tc.name: AccountPosixAdapterTest004
 * @tc.desc: Test oh_getgroupname with non-existent GID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, AccountPosixAdapterTest004, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);
    
    int32_t gid = PosixTools::GenerateUid(999);
    char *groupname = oh_getgroupname(static_cast<gid_t>(gid));
    EXPECT_EQ(groupname, nullptr);
}

/**
 * @tc.name: AccountPosixAdapterTest005
 * @tc.desc: Test oh_getpwuid with valid UID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, AccountPosixAdapterTest005, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);
    
    int32_t uid = PosixTools::GenerateUid(100);
    struct passwd *pw = oh_getpwuid(static_cast<uid_t>(uid));
    ASSERT_NE(pw, nullptr);
    EXPECT_STREQ(pw->pw_name, "testAccount");
    EXPECT_EQ(pw->pw_uid, static_cast<uid_t>(uid));
    EXPECT_EQ(pw->pw_gid, static_cast<gid_t>(uid));
}

/**
 * @tc.name: AccountPosixAdapterTest006
 * @tc.desc: Test oh_getpwuid with non-existent UID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, AccountPosixAdapterTest006, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);
    
    int32_t uid = PosixTools::GenerateUid(999);
    struct passwd *pw = oh_getpwuid(static_cast<uid_t>(uid));
    EXPECT_EQ(pw, nullptr);
}

/**
 * @tc.name: AccountPosixAdapterTest007
 * @tc.desc: Test oh_getpwuid_r with valid UID and sufficient buffer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, AccountPosixAdapterTest007, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);
    
    int32_t uid = PosixTools::GenerateUid(100);
    struct passwd pw;
    struct passwd *result = nullptr;
    char buf[BUF_SIZE] = {0};
    
    int32_t ret = oh_getpwuid_r(static_cast<uid_t>(uid), &pw, buf, sizeof(buf), &result);
    EXPECT_EQ(ret, 0);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result->pw_name, "testAccount");
    EXPECT_EQ(result->pw_uid, static_cast<uid_t>(uid));
}

/**
 * @tc.name: AccountPosixAdapterTest008
 * @tc.desc: Test oh_getpwuid_r with insufficient buffer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, AccountPosixAdapterTest008, TestSize.Level1)
{
    std::string content = "100:verylongaccountname\n";
    PosixTools::WritePosixMapFile(content);
    
    int32_t uid = PosixTools::GenerateUid(100);
    struct passwd pw;
    struct passwd *result = nullptr;
    char buf[5] = {0};
    
    int32_t ret = oh_getpwuid_r(static_cast<uid_t>(uid), &pw, buf, sizeof(buf), &result);
    EXPECT_NE(ret, 0);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: AccountPosixAdapterTest009
 * @tc.desc: Test oh_getpwnam with valid account name.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, AccountPosixAdapterTest009, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);
    
    struct passwd *pw = oh_getpwnam("testAccount");
    ASSERT_NE(pw, nullptr);
    EXPECT_STREQ(pw->pw_name, "testAccount");
    EXPECT_EQ(pw->pw_uid, static_cast<uid_t>(PosixTools::GenerateUid(100)));
}

/**
 * @tc.name: AccountPosixAdapterTest010
 * @tc.desc: Test oh_getpwnam with non-existent account name.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, AccountPosixAdapterTest010, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);
    
    struct passwd *pw = oh_getpwnam("nonexistent");
    EXPECT_EQ(pw, nullptr);
}

/**
 * @tc.name: AccountPosixAdapterTest050
 * @tc.desc: Test oh_getpwnam with invalid account name.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, AccountPosixAdapterTest050, TestSize.Level1)
{
    struct passwd *pw = oh_getpwnam("invalid@account123");
    EXPECT_EQ(pw, nullptr);
    EXPECT_EQ(errno, 0);
}

/**
 * @tc.name: AccountPosixAdapterTest011
 * @tc.desc: Test oh_getpwnam_r with valid account name and sufficient buffer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, AccountPosixAdapterTest011, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);
    
    struct passwd pw;
    struct passwd *result = nullptr;
    char buf[BUF_SIZE] = {0};
    
    int32_t ret = oh_getpwnam_r("testAccount", &pw, buf, sizeof(buf), &result);
    EXPECT_EQ(ret, 0);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result->pw_name, "testAccount");
}

/**
 * @tc.name: AccountPosixAdapterTest012
 * @tc.desc: Test oh_getpwnam_r with insufficient buffer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, AccountPosixAdapterTest012, TestSize.Level1)
{
    std::string content = "100:verylongaccountname\n";
    PosixTools::WritePosixMapFile(content);
    
    struct passwd pw;
    struct passwd *result = nullptr;
    char buf[5] = {0};
    
    int32_t ret = oh_getpwnam_r("verylongaccountname", &pw, buf, sizeof(buf), &result);
    EXPECT_NE(ret, 0);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: AccountPosixAdapterTest013
 * @tc.desc: Test oh_getgrgid with valid GID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, AccountPosixAdapterTest013, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);
    
    int32_t gid = PosixTools::GenerateUid(100);
    struct group *gr = oh_getgrgid(static_cast<gid_t>(gid));
    ASSERT_NE(gr, nullptr);
    EXPECT_STREQ(gr->gr_name, "testAccount_a0");
    EXPECT_EQ(gr->gr_gid, static_cast<gid_t>(gid));
}

/**
 * @tc.name: AccountPosixAdapterTest014
 * @tc.desc: Test oh_getgrgid with non-existent GID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, AccountPosixAdapterTest014, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);
    
    int32_t gid = PosixTools::GenerateUid(999);
    struct group *gr = oh_getgrgid(static_cast<gid_t>(gid));
    EXPECT_EQ(gr, nullptr);
}

/**
 * @tc.name: AccountPosixAdapterTest015
 * @tc.desc: Test oh_getgrgid_r with valid GID and sufficient buffer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, AccountPosixAdapterTest015, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);
    
    int32_t gid = PosixTools::GenerateUid(100);
    struct group gr;
    struct group *result = nullptr;
    char buf[BUF_SIZE] = {0};
    
    int32_t ret = oh_getgrgid_r(static_cast<gid_t>(gid), &gr, buf, sizeof(buf), &result);
    EXPECT_EQ(ret, 0);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result->gr_name, "testAccount_a0");
}

/**
 * @tc.name: AccountPosixAdapterTest016
 * @tc.desc: Test oh_getgrgid_r with insufficient buffer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, AccountPosixAdapterTest016, TestSize.Level1)
{
    std::string content = "100:verylongaccountname\n";
    PosixTools::WritePosixMapFile(content);
    
    int32_t gid = PosixTools::GenerateUid(100);
    struct group gr;
    struct group *result = nullptr;
    char buf[5] = {0};
    
    int32_t ret = oh_getgrgid_r(static_cast<gid_t>(gid), &gr, buf, sizeof(buf), &result);
    EXPECT_NE(ret, 0);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: AccountPosixAdapterTest017
 * @tc.desc: Test oh_getgrnam with valid group name format.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, AccountPosixAdapterTest017, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);

    struct group *gr = oh_getgrnam("testAccount_a0");
    ASSERT_NE(gr, nullptr);
    EXPECT_STREQ(gr->gr_name, "testAccount_a0");
    EXPECT_EQ(gr->gr_gid, static_cast<gid_t>(PosixTools::GenerateUid(100, 0)));
}

/**
 * @tc.name: AccountPosixAdapterTest018
 * @tc.desc: Test oh_getgrnam with non-existent account name.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, AccountPosixAdapterTest018, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);
    
    struct group *gr = oh_getgrnam("nonexistent");
    EXPECT_EQ(gr, nullptr);
}

/**
 * @tc.name: AccountPosixAdapterTest019
 * @tc.desc: Test oh_getgrnam_r with valid group name format.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, AccountPosixAdapterTest019, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);
    
    struct group gr;
    struct group *result = nullptr;
    char buf[BUF_SIZE] = {0};
    
    int32_t ret = oh_getgrnam_r("testAccount_a0", &gr, buf, sizeof(buf), &result);
    EXPECT_EQ(ret, 0);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result->gr_name, "testAccount_a0");
}

/**
 * @tc.name: AccountPosixAdapterTest020
 * @tc.desc: Test oh_getgrnam_r with insufficient buffer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, AccountPosixAdapterTest020, TestSize.Level1)
{
    std::string content = "100:verylongaccountname\n";
    PosixTools::WritePosixMapFile(content);
    
    struct group gr;
    struct group *result = nullptr;
    char buf[5] = {0};
    
    int32_t ret = oh_getgrnam_r("verylongaccountname", &gr, buf, sizeof(buf), &result);
    EXPECT_NE(ret, 0);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: AccountPosixAdapterTest021
 * @tc.desc: Test oh_getgrnam_r with invalid app index in group name.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, AccountPosixAdapterTest021, TestSize.Level1)
{
    // Test with invalid group name where app index is not a number
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);

    struct group gr;
    struct group *result = nullptr;
    char buf[BUF_SIZE] = {0};

    // This should fail because app index "invalid" is not a number
    int32_t ret = oh_getgrnam_r("testAccount_ainvalid", &gr, buf, sizeof(buf), &result);
    EXPECT_EQ(ret, EINVAL);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: AccountPosixAdapterTest022
 * @tc.desc: Test oh_getgrnam_r with incorrect character in account name.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, AccountPosixAdapterTest022, TestSize.Level1)
{
    std::string content = "100:very^long&account)name\n";
    PosixTools::WritePosixMapFile(content);

    int32_t gid = PosixTools::GenerateUid(100);
    struct group gr;
    struct group *result = nullptr;
    char buf[BUF_SIZE] = {0};
    
    int32_t ret = oh_getgrgid_r(static_cast<gid_t>(gid), &gr, buf, sizeof(buf), &result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: AccountPosixAdapterTest023
 * @tc.desc: Test oh_getgrgid_r with different appidx.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, AccountPosixAdapterTest023, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);
    
    int32_t gid = PosixTools::GenerateUid(100, 200);
    struct group gr;
    struct group *result = nullptr;
    char buf[BUF_SIZE] = {0};
    
    int32_t ret = oh_getgrgid_r(static_cast<gid_t>(gid), &gr, buf, sizeof(buf), &result);
    EXPECT_EQ(ret, 0);
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result->gr_name, "testAccount_a200");
}

/**
 * @tc.name: SplitGroupNameTest001
 * @tc.desc: Test SplitGroupName with valid format.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, SplitGroupNameTest001, TestSize.Level1)
{
    std::string groupName = "testAccount_a10";
    std::string accountName;
    int32_t appIdx;

    int32_t ret = PosixTools::SplitGroupName(groupName, accountName, appIdx);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(accountName, "testAccount");
    EXPECT_EQ(appIdx, 10);
}

/**
 * @tc.name: SplitGroupNameTest002
 * @tc.desc: Test SplitGroupName with default app index.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, SplitGroupNameTest002, TestSize.Level1)
{
    std::string groupName = "testAccount_a0";
    std::string accountName;
    int32_t appIdx;

    int32_t ret = PosixTools::SplitGroupName(groupName, accountName, appIdx);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(accountName, "testAccount");
    EXPECT_EQ(appIdx, 0);
}

/**
 * @tc.name: SplitGroupNameTest003
 * @tc.desc: Test SplitGroupName without app index delimiter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, SplitGroupNameTest003, TestSize.Level1)
{
    std::string groupName = "testAccount";
    std::string accountName;
    int32_t appIdx;

    int32_t ret = PosixTools::SplitGroupName(groupName, accountName, appIdx);
    EXPECT_EQ(ret, EINVAL);
    EXPECT_TRUE(accountName.empty());
}

/**
 * @tc.name: SplitGroupNameTest004
 * @tc.desc: Test SplitGroupName with invalid app index.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, SplitGroupNameTest004, TestSize.Level1)
{
    std::string groupName = "testAccount_invalid";
    std::string accountName;
    int32_t appIdx;

    int32_t ret = PosixTools::SplitGroupName(groupName, accountName, appIdx);
    EXPECT_EQ(ret, EINVAL);
    EXPECT_TRUE(accountName.empty());
}

/**
 * @tc.name: OhGetgrnamRTest001
 * @tc.desc: Test oh_getgrnam_r with null name parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, OhGetgrnamRTest001, TestSize.Level1)
{
    struct group gr;
    struct group *result = nullptr;
    char buf[BUF_SIZE] = {0};

    int32_t ret = oh_getgrnam_r(nullptr, &gr, buf, BUF_SIZE, &result);
    EXPECT_EQ(ret, EINVAL);
}

/**
 * @tc.name: OhGetgrnamRTest002
 * @tc.desc: Test oh_getgrnam_r with null gr parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, OhGetgrnamRTest002, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);

    struct group *result = nullptr;
    char buf[BUF_SIZE] = {0};

    int32_t ret = oh_getgrnam_r("testAccount_a0", nullptr, buf, BUF_SIZE, &result);
    EXPECT_EQ(ret, EINVAL);
}

/**
 * @tc.name: OhGetgrnamRTest003
 * @tc.desc: Test oh_getgrnam_r with null buf parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, OhGetgrnamRTest003, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);

    struct group gr;
    struct group *result = nullptr;

    int32_t ret = oh_getgrnam_r("testAccount_a0", &gr, nullptr, BUF_SIZE, &result);
    EXPECT_EQ(ret, EINVAL);
}

/**
 * @tc.name: OhGetgrnamRTest004
 * @tc.desc: Test oh_getgrnam_r with null res parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, OhGetgrnamRTest004, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);

    struct group gr;
    char buf[BUF_SIZE] = {0};

    int32_t ret = oh_getgrnam_r("testAccount_a0", &gr, buf, sizeof(buf), nullptr);
    EXPECT_EQ(ret, EINVAL);
}

/**
 * @tc.name: OhGetgrnamRTest005
 * @tc.desc: Test oh_getgrnam_r with invalid group name.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, OhGetgrnamRTest005, TestSize.Level1)
{
    struct group gr;
    char buf[BUF_SIZE] = {0};
    struct group *result = nullptr;

    int32_t ret = oh_getgrnam_r("invalid()account123_a0", &gr, buf, sizeof(buf), &result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: OhGetgrnamTest001
 * @tc.desc: Test oh_getgrnam with null name parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, OhGetgrnamTest001, TestSize.Level1)
{
    struct group *gr = oh_getgrnam(nullptr);
    EXPECT_EQ(gr, nullptr);
}

/**
 * @tc.name: OhGetgrnamTest002
 * @tc.desc: Test oh_getgrnam with invalid name.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, OhGetgrnamTest002, TestSize.Level1)
{
    struct group *gr = oh_getgrnam("invalid!account123_a0");
    EXPECT_EQ(gr, nullptr);
    EXPECT_EQ(errno, 0);
}

/**
 * @tc.name: OhGetgrgidRTest001
 * @tc.desc: Test oh_getgrgid_r with null gr parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, OhGetgrgidRTest001, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);

    int32_t gid = PosixTools::GenerateUid(100);
    struct group *result = nullptr;
    char buf[BUF_SIZE] = {0};

    int32_t ret = oh_getgrgid_r(static_cast<gid_t>(gid), nullptr, buf, sizeof(buf), &result);
    EXPECT_EQ(ret, EINVAL);
}

/**
 * @tc.name: OhGetgrgidRTest002
 * @tc.desc: Test oh_getgrgid_r with null buf parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, OhGetgrgidRTest002, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);

    int32_t gid = PosixTools::GenerateUid(100);
    struct group gr;
    struct group *result = nullptr;

    int32_t ret = oh_getgrgid_r(static_cast<gid_t>(gid), &gr, nullptr, BUF_SIZE, &result);
    EXPECT_EQ(ret, EINVAL);
}

/**
 * @tc.name: OhGetgrgidRTest003
 * @tc.desc: Test oh_getgrgid_r with null res parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, OhGetgrgidRTest003, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);

    int32_t gid = PosixTools::GenerateUid(100);
    struct group gr;
    char buf[BUF_SIZE] = {0};

    int32_t ret = oh_getgrgid_r(static_cast<gid_t>(gid), &gr, buf, sizeof(buf), nullptr);
    EXPECT_EQ(ret, EINVAL);
}

/**
 * @tc.name: OhGetpwuidRTest001
 * @tc.desc: Test oh_getpwuid_r with null pw parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, OhGetpwuidRTest001, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);

    int32_t uid = PosixTools::GenerateUid(100);
    struct passwd *result = nullptr;
    char buf[BUF_SIZE] = {0};

    int32_t ret = oh_getpwuid_r(static_cast<uid_t>(uid), nullptr, buf, sizeof(buf), &result);
    EXPECT_EQ(ret, EINVAL);
}

/**
 * @tc.name: OhGetpwuidRTest002
 * @tc.desc: Test oh_getpwuid_r with null buf parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, OhGetpwuidRTest002, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);

    int32_t uid = PosixTools::GenerateUid(100);
    struct passwd pw;
    struct passwd *result = nullptr;

    int32_t ret = oh_getpwuid_r(static_cast<uid_t>(uid), &pw, nullptr, BUF_SIZE, &result);
    EXPECT_EQ(ret, EINVAL);
}

/**
 * @tc.name: OhGetpwuidRTest003
 * @tc.desc: Test oh_getpwuid_r with null res parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, OhGetpwuidRTest003, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);

    int32_t uid = PosixTools::GenerateUid(100);
    struct passwd pw;
    char buf[BUF_SIZE] = {0};

    int32_t ret = oh_getpwuid_r(static_cast<uid_t>(uid), &pw, buf, sizeof(buf), nullptr);
    EXPECT_EQ(ret, EINVAL);
}

/**
 * @tc.name: OhGetpwnamRTest001
 * @tc.desc: Test oh_getpwnam_r with null pw parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, OhGetpwnamRTest001, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);

    struct passwd *result = nullptr;
    char buf[BUF_SIZE] = {0};

    int32_t ret = oh_getpwnam_r("testAccount", nullptr, buf, sizeof(buf), &result);
    EXPECT_EQ(ret, EINVAL);
}

/**
 * @tc.name: OhGetpwnamRTest002
 * @tc.desc: Test oh_getpwnam_r with null buf parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, OhGetpwnamRTest002, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);

    struct passwd pw;
    struct passwd *result = nullptr;

    int32_t ret = oh_getpwnam_r("testAccount", &pw, nullptr, BUF_SIZE, &result);
    EXPECT_EQ(ret, EINVAL);
}

/**
 * @tc.name: OhGetpwnamRTest003
 * @tc.desc: Test oh_getpwnam_r with null res parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, OhGetpwnamRTest003, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);

    struct passwd pw;
    char buf[BUF_SIZE] = {0};

    int32_t ret = oh_getpwnam_r("testAccount", &pw, buf, sizeof(buf), nullptr);
    EXPECT_EQ(ret, EINVAL);
}

/**
 * @tc.name: OhGetpwnamRTest004
 * @tc.desc: Test oh_getpwnam_r with zero size parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, OhGetpwnamRTest004, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);

    struct passwd pw;
    struct passwd *result = nullptr;
    char buf[BUF_SIZE] = {0};

    int32_t ret = oh_getpwnam_r("testAccount", &pw, buf, 0, &result);
    EXPECT_EQ(ret, ERANGE);
}

/**
 * @tc.name: OhGetpwnamRTest005
 * @tc.desc: Test oh_getpwnam_r with invalid accountName.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, OhGetpwnamRTest005, TestSize.Level1)
{
    struct passwd pw;
    struct passwd *result = nullptr;
    char buf[BUF_SIZE] = {0};

    int32_t ret = oh_getpwnam_r("invalid^account123", &pw, buf, 0, &result);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: FileOperationErrorTest001
 * @tc.desc: Test behavior when posix map file doesn't exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, FileOperationErrorTest001, TestSize.Level1)
{
    // Test with no posix map file
    // Remove any existing file first
    std::string cmd = "rm -f " + TEST_POSIX_MAP_FILE;
    system(cmd.c_str());

    struct passwd *pw = oh_getpwuid(100); // Non-existent UID
    EXPECT_EQ(pw, nullptr);
}

/**
 * @tc.name: FileOperationErrorTest002
 * @tc.desc: Test behavior with corrupted posix map file.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, FileOperationErrorTest002, TestSize.Level1)
{
    // Write corrupted file data
    std::string cmd = "echo \"invalid:data\" > " + TEST_POSIX_MAP_FILE;
    system(cmd.c_str());

    struct passwd *pw = oh_getpwuid(100);
    EXPECT_EQ(pw, nullptr);
}

/**
 * @tc.name: BufferOverflowTest001
 * @tc.desc: Test oh_getpwuid_r with zero size buffer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, BufferOverflowTest001, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);

    int32_t uid = PosixTools::GenerateUid(100);
    struct passwd pw;
    struct passwd *result = nullptr;
    char buf[BUF_SIZE] = {0};

    int32_t ret = oh_getpwuid_r(static_cast<uid_t>(uid), &pw, buf, 0, &result);
    EXPECT_EQ(ret, ERANGE);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: BufferOverflowTest002
 * @tc.desc: Test oh_getpwuid_r with insufficient buffer size.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, BufferOverflowTest002, TestSize.Level1)
{
    std::string content = "100:verylongaccountnamethatexceedsnormallimits1234567890\n";
    PosixTools::WritePosixMapFile(content);

    int32_t uid = PosixTools::GenerateUid(100);
    struct passwd pw;
    struct passwd *result = nullptr;
    char buf[5] = {0};  // Very small buffer

    int32_t ret = oh_getpwuid_r(static_cast<uid_t>(uid), &pw, buf, sizeof(buf), &result);
    EXPECT_EQ(ret, ERANGE);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: BufferOverflowTest003
 * @tc.desc: Test oh_getgrgid_r with zero size buffer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, BufferOverflowTest003, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);

    int32_t gid = PosixTools::GenerateUid(100);
    struct group gr;
    struct group *result = nullptr;
    char buf[BUF_SIZE] = {0};

    int32_t ret = oh_getgrgid_r(static_cast<gid_t>(gid), &gr, buf, 0, &result);
    EXPECT_EQ(ret, ERANGE);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: BufferOverflowTest004
 * @tc.desc: Test oh_getgrgid_r with insufficient buffer size.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, BufferOverflowTest004, TestSize.Level1)
{
    std::string content = "100:verylongaccountnamethatexceedsnormallimits1234567890\n";
    PosixTools::WritePosixMapFile(content);

    int32_t gid = PosixTools::GenerateUid(100);
    struct group gr;
    struct group *result = nullptr;
    char buf[5] = {0};  // Very small buffer

    int32_t ret = oh_getgrgid_r(static_cast<gid_t>(gid), &gr, buf, sizeof(buf), &result);
    EXPECT_EQ(ret, ERANGE);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: BufferOverflowTest005
 * @tc.desc: Test oh_getpwnam_r with zero size buffer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, BufferOverflowTest005, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);

    struct passwd pw;
    struct passwd *result = nullptr;
    char buf[BUF_SIZE] = {0};

    int32_t ret = oh_getpwnam_r("testAccount", &pw, buf, 0, &result);
    EXPECT_EQ(ret, ERANGE);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: BufferOverflowTest006
 * @tc.desc: Test oh_getpwnam_r with insufficient buffer size.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, BufferOverflowTest006, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);

    struct passwd pw;
    struct passwd *result = nullptr;
    char buf[5] = {0};  // Very small buffer

    int32_t ret = oh_getpwnam_r("testAccount", &pw, buf, sizeof(buf), &result);
    EXPECT_EQ(ret, ERANGE);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: BufferOverflowTest007
 * @tc.desc: Test oh_getgrnam_r with zero size buffer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, BufferOverflowTest007, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);

    struct group gr;
    struct group *result = nullptr;
    char buf[BUF_SIZE] = {0};

    int32_t ret = oh_getgrnam_r("testAccount_a0", &gr, buf, 0, &result);
    EXPECT_EQ(ret, ERANGE);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: BufferOverflowTest008
 * @tc.desc: Test oh_getgrnam_r with insufficient buffer size.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountPosixAdapterTest, BufferOverflowTest008, TestSize.Level1)
{
    std::string content = "100:testAccount\n";
    PosixTools::WritePosixMapFile(content);

    struct group gr;
    struct group *result = nullptr;
    char buf[5] = {0};  // Very small buffer

    int32_t ret = oh_getgrnam_r("testAccount_a0", &gr, buf, sizeof(buf), &result);
    EXPECT_EQ(ret, ERANGE);
    EXPECT_EQ(result, nullptr);
}
