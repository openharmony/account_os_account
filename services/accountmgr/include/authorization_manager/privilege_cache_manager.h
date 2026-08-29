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
#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_PRIVILEGE_CACHE_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_PRIVILEGE_CACHE_MANAGER_H

#include <optional>
#include <string>
#include "ipc_skeleton.h"
#include "json_utils.h"
#include "kernel_authorization_adapter.h"
#include "privilege_utils.h"
#include "privileges_map.h"

namespace OHOS {
namespace AccountSA {

enum class PrivilegeAuthStatus {
    NOT_REQUIRED = 0,
    UNCONFIRMED = 1,
    AUTHORIZED = 2,
};

std::string PrivilegeAuthStatusToString(PrivilegeAuthStatus authType);
PrivilegeAuthStatus StringToPrivilegeAuthStatus(const std::string &authTypeStr);

class PrivilegeRecord {
    friend class ProcessPrivilegeRecord;
public:
    PrivilegeRecord(uint32_t privilegeIdx, int64_t expiredTimeStamp, uint32_t safeStartTime)
        : privilegeIdx_(privilegeIdx), expiredTime_(expiredTimeStamp), safeStartTime_(safeStartTime) {};
    ~PrivilegeRecord() = default;

    static std::shared_ptr<PrivilegeRecord> FromJson(const cJSON *jsonObjPtr);
    ErrCode ToJson(CJsonUnique &jsonArrPtr);

    ErrCode GetRemainTimeSec(int64_t currentTimeStamp, int32_t &remainTime);
    bool NeedClean(int64_t currentTimeStamp);

    PrivilegeAuthStatus GetAuthStatus() const { return authStatus_; }
    void SetAuthStatus(PrivilegeAuthStatus authType) { authStatus_ = authType; }

protected:
    uint32_t privilegeIdx_ = 0;
    int64_t expiredTime_ = 0;
    uint32_t safeStartTime_ = 0;
    PrivilegeAuthStatus authStatus_ = PrivilegeAuthStatus::NOT_REQUIRED;
};

struct AuthenCallerInfo {
    int32_t pid = IPCSkeleton::GetCallingPid();
    int32_t uid = IPCSkeleton::GetCallingUid();
    uint32_t privilegeIdx = 0xFFFFFFFF;
    std::optional<sptr<IRemoteObject>> remoteObject = std::nullopt;
};

class ProcessPrivilegeRecord {
public:
    ProcessPrivilegeRecord() = default;
    ~ProcessPrivilegeRecord();
    static ErrCode CreateEmptyProcessPrivilegeRecord(
        const AuthenCallerInfo &callerInfo, std::shared_ptr<ProcessPrivilegeRecord> &processPrivilegeRecord);
    static ErrCode FromJson(
        const int64_t currTime, const cJSON *jsonObjPtr,
        std::shared_ptr<ProcessPrivilegeRecord> &processPrivilegeRecord);
    ErrCode ToJson(CJsonUnique &jsonObjPtr);

    ErrCode CheckPrivilege(const uint32_t privilegeIdx, int32_t &remainTime);
    ErrCode AddOrUpdatePrivilege(uint32_t privilegeIdx, uint32_t safeStartTime);
    std::shared_ptr<PrivilegeRecord> GetPrivilegeRecord(uint32_t privilegeIdx);
    std::map<uint32_t, std::shared_ptr<PrivilegeRecord>> &GetPrivilegeRecords() { return privilegeRecordMap_; }
    ErrCode RemovePrivilege(uint32_t privilegeIdx, std::shared_ptr<PrivilegeRecord> &removedRecord);
    void RollbackPrivilege(const std::shared_ptr<PrivilegeRecord> &removedRecord);
    ErrCode CleanCurrentExpiredPrivileges(const int64_t currentTimeStamp);
    size_t GetPrivilegeNum();
    int32_t GetProcessLocalId();
    int32_t GetPid();
private:
    std::recursive_mutex mutex_;
    std::map<uint32_t, std::shared_ptr<PrivilegeRecord>> privilegeRecordMap_;
    int32_t pid_ = -1;
    int32_t uid_ = -1;
    int64_t processStartTime_ = -1;
    SmartPidFd pidFdPtr_ = nullptr;
    // used for death recipient
    sptr<IRemoteObject> remoteObject_ = nullptr;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ = nullptr;
    bool CheckProcessAlive();
    ErrCode ParsePrivilegeRecordJsonArray(const int64_t currentTime, const cJSON *jsonObj);
    class PrivilegeDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        PrivilegeDeathRecipient(int32_t pid) : pid_(pid) {};
        ~PrivilegeDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    private:
        int32_t pid_ = -1;
    };
};

class PrivilegeCacheManager {
public:
    static PrivilegeCacheManager &GetInstance();
    ErrCode CheckPrivilege(const AuthenCallerInfo &callerInfo, int32_t &remainTime);
    ErrCode RemoveSingle(const AuthenCallerInfo &callerInfo);
    ErrCode AddCache(const AuthenCallerInfo &callerInfo, uint32_t safeStartTime);
    ErrCode AddCacheAndNotifyKernel(const AuthenCallerInfo &callerInfo,
        const std::string &kernelPermission);
    ErrCode HasKernelAuthorization(int32_t pid, uint32_t privilegeIdx,
        const std::string &kernelPermission, bool &isAuthorized);
    ErrCode RemoveUser(int32_t localId);
    ErrCode RemoveProcess(int32_t pid);

    ErrCode FromPersistFile();
    ErrCode CleanExpiredPrivilegesAndSaveToFile();
private:
    PrivilegeCacheManager() = default;
    ~PrivilegeCacheManager() = default;
    ErrCode ToPersistFile(const int64_t currTime);
    ErrCode GenerateDigestFromHuks(const int64_t updateTime, const std::string &jsonStr, std::vector<uint8_t> &digest);
    void ReadAndCheckPersistRecordValid(const int64_t currTime, std::string &recordStr, bool &needSkipLoading);
    bool CheckPersistDigestValid(const int64_t updateTime,
        const std::string &processRecordsStr, const std::vector<uint8_t> &storedDigest);
    ErrCode CheckUpdateTimeValid(const CJsonUnique &jsonObj, const int64_t currTime, int64_t &updateTime);
    bool MapToJsonString(std::string &output);
    ErrCode ToJsonString(const int64_t currTime, const std::string &recordStr,
        const std::vector<uint8_t> &digest, std::string &output);
    ErrCode AddNewProcessCacheInner(const AuthenCallerInfo &callerInfo, uint32_t safeStartTime);
    ErrCode SetAuthStatusForRecord(const AuthenCallerInfo &callerInfo, PrivilegeAuthStatus authType);
    ErrCode PrepareKernelAuthCache(const AuthenCallerInfo &callerInfo, int64_t &currTime);
    ErrCode SetKernelAuthWithTimer(int32_t pid, const std::string &kernelPermission);
    ErrCode QueryKernelAuthWithTimer(int32_t pid, const std::string &kernelPermission, bool &isAuthorized);
    ErrCode UpdateToAuthorized(const std::shared_ptr<PrivilegeRecord> &record);
    void StartCleanTask();
    void RollbackDelSingleRecord(const std::shared_ptr<ProcessPrivilegeRecord> &processRecord,
        const std::shared_ptr<PrivilegeRecord> &removedRecord);
    std::recursive_mutex mapMutex_;
    std::map<int32_t, std::shared_ptr<ProcessPrivilegeRecord>> processPrivilegeMap_;
};
} // namespace AccountSA
} // namespace OHOS
#endif // PRIVILEGE_CACHE_MANAGER_H