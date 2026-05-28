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

#include <iomanip>
#include <mutex>
#include <vector>
#include <sstream>
#include <string>
#include <cstdio>
#include "account_error_no.h"
#include "account_info.h"
#include "account_mgr_service.h"
#include "iinner_os_account_manager.h"
#include "os_account_constants.h"
#include "os_account_info.h"
#include "osaccount/os_account_control_file_manager.h"
#include <openssl/sha.h>

namespace OHOS {
namespace AccountSA {

static std::mutex g_mockMutex;

constexpr std::uint32_t MAX_NAME_LENGTH = 256;
constexpr std::uint32_t MAX_UID_LENGTH = 512;
constexpr std::uint32_t HASH_LENGTH = 32;
constexpr std::uint32_t TEST_USERID = 100;
constexpr std::uint32_t WIDTH_FOR_HEX = 2;

struct MockState {
    std::vector<OsAccountInfo> createdOsAccounts;
    int32_t callingUid = 0;
    int32_t callingUserId = TEST_USERID;
    ErrCode forceUpdateSubspaceInfoFail = ERR_OK;
    ErrCode forceGetInfoByIdFail = ERR_OK;
};

static MockState &GetMockState()
{
    static MockState state;
    return state;
}

void ResetMockState()
{
    auto &state = GetMockState();
    state.createdOsAccounts.clear();
    state.callingUid = 0;
    state.callingUserId = TEST_USERID;
    state.forceUpdateSubspaceInfoFail = ERR_OK;
    state.forceGetInfoByIdFail = ERR_OK;
}

void MockForceUpdateSubspaceInfoFail(ErrCode errCode)
{
    GetMockState().forceUpdateSubspaceInfoFail = errCode;
}

void MockForceGetOsAccountInfoByIdFail(ErrCode errCode)
{
    GetMockState().forceGetInfoByIdFail = errCode;
}

void MockClearForceFailFlags()
{
    auto &state = GetMockState();
    state.forceUpdateSubspaceInfoFail = ERR_OK;
    state.forceGetInfoByIdFail = ERR_OK;
}

void MockSetCallingUid(int32_t uid)
{
    GetMockState().callingUid = uid;
}

void MockSetCallingUserId(int32_t userId)
{
    GetMockState().callingUserId = userId;
}

void MockSetCreatedOsAccounts(const std::vector<OsAccountInfo> &accounts)
{
    GetMockState().createdOsAccounts = accounts;
}

IInnerOsAccountManager &IInnerOsAccountManager::GetInstance()
{
    static IInnerOsAccountManager instance;
    return instance;
}

ErrCode IInnerOsAccountManager::QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos)
{
    osAccountInfos = GetMockState().createdOsAccounts;
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetOsAccountInfoById(const int id, OsAccountInfo &osAccountInfo)
{
    auto &state = GetMockState();
    if (state.forceGetInfoByIdFail != ERR_OK) {
        return state.forceGetInfoByIdFail;
    }
    for (const auto &info : state.createdOsAccounts) {
        if (info.GetLocalId() == id) {
            osAccountInfo = info;
            return ERR_OK;
        }
    }
    return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
}

ErrCode IInnerOsAccountManager::SetOsAccountForegroundSubspaceId(int32_t localId, int32_t subspaceId)
{
    for (auto &info : GetMockState().createdOsAccounts) {
        if (info.GetLocalId() == localId) {
            info.SetForegroundSubProfileId(subspaceId);
            return ERR_OK;
        }
    }
    return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
}

ErrCode IInnerOsAccountManager::UpdateOsAccountSubspaceInfo(
    int32_t localId, int32_t nextSubProfileId, const std::vector<std::string> &subProfileIdList)
{
    auto &state = GetMockState();
    if (state.forceUpdateSubspaceInfoFail != ERR_OK) {
        return state.forceUpdateSubspaceInfoFail;
    }
    for (auto &info : state.createdOsAccounts) {
        if (info.GetLocalId() == localId) {
            info.SetNextSubProfileId(nextSubProfileId);
            info.SetSubProfileIdList(subProfileIdList);
            return ERR_OK;
        }
    }
    return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
}

ErrCode IInnerOsAccountManager::CreateOsAccount(
    const std::string &name, const OsAccountType &type, OsAccountInfo &osAccountInfo)
{
    return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
}

ErrCode IInnerOsAccountManager::RemoveOsAccount(const int id)
{
    return ERR_OK;
}

static constexpr size_t FILE_CONTROLLER_BUF_SIZE = 4096;
alignas(std::max_align_t) static uint8_t g_fileControllerBuf[FILE_CONTROLLER_BUF_SIZE] = {0};

OsAccountControlFileManager &IInnerOsAccountManager::GetFileController()
{
    return *reinterpret_cast<OsAccountControlFileManager *>(g_fileControllerBuf);
}

namespace {
int32_t MockGetCallingUid()
{
    return GetMockState().callingUid;
}

int32_t MockGetCallingUserId()
{
    return GetMockState().callingUserId;
}
}

AccountMgrService &AccountMgrService::GetInstance()
{
    static AccountMgrService instance;
    return instance;
}

int32_t AccountMgrService::GetCallingUserID()
{
    return MockGetCallingUserId();
}

} // namespace AccountSA

namespace IPCSkeleton {
int32_t GetCallingUid()
{
    return AccountSA::MockGetCallingUid();
}
int32_t GetCallingUserId()
{
    return AccountSA::MockGetCallingUserId();
}
}

namespace AccountSA {
std::string GenerateOhosUdidWithSha256(const std::string &name, const std::string &uid)
{
    if (name.empty() || name.length() > MAX_NAME_LENGTH) {
        return "";
    }
    if (uid.empty() || uid.length() > MAX_UID_LENGTH) {
        return "";
    }

    unsigned char hash[HASH_LENGTH] = {0};
    SHA256(reinterpret_cast<const unsigned char *>(uid.c_str()), uid.length(), hash);

    std::string ohosUidStr;
    std::stringstream ss;
    for (std::uint32_t i = 0; i < HASH_LENGTH; ++i) {
        ss << std::hex << std::uppercase << std::setw(WIDTH_FOR_HEX) << std::setfill('0') << std::uint16_t(hash[i]);
    }
    ohosUidStr = ss.str();
    return ohosUidStr;
}
} // namespace AccountSA

} // namespace OHOS