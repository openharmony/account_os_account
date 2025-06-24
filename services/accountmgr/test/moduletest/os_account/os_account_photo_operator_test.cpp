/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include <thread>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "os_account_constants.h"
#define private public
#include "os_account_photo_operator.h"
#undef private

namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;

namespace {
const std::string STRING_TEST_NAME = "name";
}  // namespace

class OsAccountPhotoOperatorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);
    std::shared_ptr<OsAccountPhotoOperator>
        osAccountPhotoOperator_ = std::make_shared<OsAccountPhotoOperator>();
};

void OsAccountPhotoOperatorTest::SetUpTestCase(void)
{
}

void OsAccountPhotoOperatorTest::TearDownTestCase(void)
{}

void OsAccountPhotoOperatorTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void OsAccountPhotoOperatorTest::TearDown(void)
{}

/**
 * @tc.name: OsAccountPhotoOperator_0001
 * @tc.desc: Test empty input.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountPhotoOperatorTest, OsAccountPhotoOperator_0001, TestSize.Level3)
{
    const char* data = "";
    std::string ret = osAccountPhotoOperator_->EnCode(data, 0);
    EXPECT_EQ(ret, "");
}

/**
 * @tc.name: OsAccountPhotoOperator_0002
 * @tc.desc: Test 3-byte alignment (without line breaks).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountPhotoOperatorTest, OsAccountPhotoOperator_0002, TestSize.Level3)
{
    const char data[] = "ABC"; // length=3
    std::string ret = osAccountPhotoOperator_->EnCode(data, sizeof(data) - 1);
    EXPECT_EQ(ret, "QUJD"); // ABC Base64 is "QUJD"
}

/**
 * @tc.name: OsAccountPhotoOperator_0003
 * @tc.desc: Test the remaining 1 byte (mod=1).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountPhotoOperatorTest, OsAccountPhotoOperator_0003, TestSize.Level3)
{
    const char data[] = "A"; // length=1
    std::string ret = osAccountPhotoOperator_->EnCode(data, sizeof(data) - 1);
    EXPECT_EQ(ret, "QQ==");
}

/**
 * @tc.name: OsAccountPhotoOperator_0004
 * @tc.desc: Test the remaining 2 bytes (mod=2).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountPhotoOperatorTest, OsAccountPhotoOperator_0004, TestSize.Level3)
{
    const char data[] = "AB"; // length=2
    std::string ret = osAccountPhotoOperator_->EnCode(data, sizeof(data) - 1);
    EXPECT_EQ(ret, "QUI=");
}

/**
 * @tc.name: OsAccountPhotoOperator_0005
 * @tc.desc: Test line break insertion (76-character boundary).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountPhotoOperatorTest, OsAccountPhotoOperator_0005, TestSize.Level3)
{
    // Construct a 57-byte input (19 groups *3 bytes)
    std::string input;
    for (int i = 0; i < 19; ++i) {
        input += "ABC"; // Each group is 3 bytes
    }

    // Expected result: Insert \r\n after 76 characters
    std::string expected;
    for (int i = 0; i < 19; ++i) {
        expected += "QUJD"; // Each group consists of 4 characters
    }
    expected.insert(76, "\r\n"); // Insert a line break at the 76-character position

    std::string ret = osAccountPhotoOperator_->EnCode(input.c_str(), input.size());
    EXPECT_EQ(ret, expected);
}

/**
 * @tc.name: OsAccountPhotoOperator_0006
 * @tc.desc: Continue encoding after the test line break (more than 76 characters).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountPhotoOperatorTest, OsAccountPhotoOperator_0006, TestSize.Level3)
{
    // Construct a 60-byte input (20 groups *3 bytes)
    std::string input;
    for (int i = 0; i < 20; ++i) {
        input += "XYZ"; // Each group is 3 bytes
    }

    // Expected result: After 76 characters, insert \r\n + 4 remaining characters
    std::string expected;
    for (int i = 0; i < 20; ++i) {
        expected += "WFla"; // Base64 encoding of XYZ
    }
    expected.insert(76, "\r\n"); // Insert a line break at the 76-character position

    std::string ret = osAccountPhotoOperator_->EnCode(input.c_str(), input.size());
    EXPECT_EQ(ret, expected);
}

/**
 * @tc.name: OsAccountPhotoOperator_0007
 * @tc.desc: Test the 56-byte boundary (without triggering line breaks).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountPhotoOperatorTest, OsAccountPhotoOperator_0007, TestSize.Level3)
{
    // Construct a 56-byte input (18 groups *3 + 2 bytes)
    std::string input;
    for (int i = 0; i < 18; ++i) {
        input += "ABC";
    }
    input += "XY"; // Remaining 2 bytes

    // Expectation: 72 characters (18 groups) + "WFg=" (XY encoding) = 76 characters without line breaks
    std::string expected;
    for (int i = 0; i < 18; ++i) {
        expected += "QUJD";
    }
    expected += "WFk="; // The Base64 encoding of XY

    std::string ret = osAccountPhotoOperator_->EnCode(input.c_str(), input.size());
    EXPECT_EQ(ret, expected);
}

/**
 * @tc.name: OsAccountPhotoOperator_0008
 * @tc.desc: Test DeCode when string.size() = 0.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountPhotoOperatorTest, OsAccountPhotoOperator_0008, TestSize.Level3)
{
    std::string baseStr = "";
    std::string ret = osAccountPhotoOperator_->DeCode(baseStr);
    EXPECT_TRUE(ret.empty());
}

/**
 * @tc.name: OsAccountPhotoOperator_0009
 * @tc.desc: Test all illegal characters (an empty return should be made).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountPhotoOperatorTest, OsAccountPhotoOperator_0009, TestSize.Level3)
{
    std::string baseStr = "@#$%";
    std::string ret = osAccountPhotoOperator_->DeCode(baseStr);
    EXPECT_TRUE(ret.empty());
}

/**
 * @tc.name: OsAccountPhotoOperator_0010
 * @tc.desc: Test the illegal characters at the beginning (an empty space should be returned).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountPhotoOperatorTest, OsAccountPhotoOperator_0010, TestSize.Level3)
{
    std::string baseStr = "@ABC";
    std::string ret = osAccountPhotoOperator_->DeCode(baseStr);
    EXPECT_TRUE(ret.empty());
}

/**
 * @tc.name: OsAccountPhotoOperator_0011
 * @tc.desc: Test the illegal characters in the middle (the first half should be decoded).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountPhotoOperatorTest, OsAccountPhotoOperator_0011, TestSize.Level3)
{
    std::string baseStr = "AB@D";
    std::string ret = osAccountPhotoOperator_->DeCode(baseStr);
    // It is expected to decode the first valid character 'A' -> 0x00
    EXPECT_EQ(ret, std::string("\0", 1));
}

/**
 * @tc.name: OsAccountPhotoOperator_0012
 * @tc.desc: Test a single equal sign fill.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountPhotoOperatorTest, OsAccountPhotoOperator_0012, TestSize.Level3)
{
    std::string baseStr = "QQ=="; // After decoding, it is "A".
    std::string ret = osAccountPhotoOperator_->DeCode(baseStr);
    EXPECT_EQ(ret, "A");
}

/**
 * @tc.name: OsAccountPhotoOperator_0013
 * @tc.desc: Test double equal sign filling.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountPhotoOperatorTest, OsAccountPhotoOperator_0013, TestSize.Level3)
{
    std::string baseStr = "TWE="; // After decoding, it is "Ma"
    std::string ret = osAccountPhotoOperator_->DeCode(baseStr);
    EXPECT_EQ(ret, "Ma");
}

/**
 * @tc.name: OsAccountPhotoOperator_0014
 * @tc.desc: Test for valid decoding without padding.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountPhotoOperatorTest, OsAccountPhotoOperator_0014, TestSize.Level3)
{
    std::string baseStr = "TWFu"; // After decoding, it is "Man"
    std::string ret = osAccountPhotoOperator_->DeCode(baseStr);
    EXPECT_EQ(ret, "Man");
}

/**
 * @tc.name: OsAccountPhotoOperator_0015
 * @tc.desc: The test length is not a multiple of 4 (2 characters).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountPhotoOperatorTest, OsAccountPhotoOperator_0015, TestSize.Level3)
{
    std::string baseStr = "AA";
    std::string ret = osAccountPhotoOperator_->DeCode(baseStr);
    // It is expected to be decoded as 1 byte of \x00
    EXPECT_EQ(ret, std::string("\0", 1));
}

/**
 * @tc.name: OsAccountPhotoOperator_0016
 * @tc.desc: The test length is not a multiple of 4 (3 characters).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountPhotoOperatorTest, OsAccountPhotoOperator_0016, TestSize.Level3)
{
    std::string baseStr = "AAA";
    std::string ret = osAccountPhotoOperator_->DeCode(baseStr);
    // It is expected to be decoded into 2 bytes of \x00\x00
    EXPECT_EQ(ret, std::string("\0\0", 2));
}

/**
 * @tc.name: OsAccountPhotoOperator_0017
 * @tc.desc: Test a mixture of upper and lower case and numbers.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountPhotoOperatorTest, OsAccountPhotoOperator_0017, TestSize.Level3)
{
    std::string baseStr = "aGVsbG8="; // After decoding, it is "hello"
    std::string ret = osAccountPhotoOperator_->DeCode(baseStr);
    EXPECT_EQ(ret, "hello");
}

/**
 * @tc.name: OsAccountPhotoOperator_0018
 * @tc.desc: The test contains an equal sign but not an ending.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountPhotoOperatorTest, OsAccountPhotoOperator_0018, TestSize.Level3)
{
    std::string baseStr = "QUE=Q"; // Partial coding
    std::string ret = osAccountPhotoOperator_->DeCode(baseStr);
    // Expect to decode "AA" (QUE is the base64 of "AA")
    EXPECT_EQ(ret, "AA");
}

/**
 * @tc.name: OsAccountPhotoOperator_0019
 * @tc.desc: The test only has one valid character.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountPhotoOperatorTest, OsAccountPhotoOperator_0019, TestSize.Level3)
{
    std::string baseStr = "A";
    std::string ret = osAccountPhotoOperator_->DeCode(baseStr);
    // The expected decoding failed (i-1=0), and an empty return was made
    EXPECT_TRUE(ret.empty());
}

/**
 * @tc.name: OsAccountPhotoOperator_0020
 * @tc.desc: Test extremely long strings.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountPhotoOperatorTest, OsAccountPhotoOperator_0020, TestSize.Level3)
{
    std::string baseStr(1024, 'A'); // "AAAA..."
    std::string expected(768, '\0'); // Every 4 'A' are decoded into 3 \x00

    std::string ret = osAccountPhotoOperator_->DeCode(baseStr);
    EXPECT_EQ(ret, expected);
}
}  // namespace AccountSA
}  // namespace OHOS