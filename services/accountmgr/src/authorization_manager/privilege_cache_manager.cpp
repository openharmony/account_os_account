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

#include "privilege_cache_manager.h"
#include <cinttypes>
#include <thread>
#include "account_file_operator.h"
#include "account_file_watcher_manager.h"
#include "account_log_wrapper.h"
#include "os_account_constants.h"
#include "privilege_hisysevent_utils.h"
#include "tee_auth_adapter.h"
#include "xcollie/xcollie.h"

namespace OHOS {
namespace AccountSA {
namespace {
const uint32_t EXPIRED_TIME_OFFSET = 2; // seconds
const int32_t UID_TRANSFORM_DIVISOR = 200000;
const int32_t DIGEST_LENGTH = 32;
const int32_t MS_TO_SECOND = 1000;
const char PRIVILEGE_RECORD_NAME[] = "privilegeName";
const char PRIVILEGE_RECORD_EXPIRED_TIMESTAMP[] = "expiredTimeStamp";
const char PRIVILEGE_RECORD_SAFE_START_TIME[] = "safeStartTime";
const char PROCESS_RECORD_PID[] = "pid";
const char PROCESS_RECORD_UID[] = "uid";
const char PROCESS_RECORD_START_TIME[] = "processStartTime";
const char PROCESS_RECORD_PRIVILEGE_RECORDS[] = "privilegeRecords";
const char CACHE_MANAGER_DIGEST[] = "digest";
const char CACHE_MANAGER_PROCESS_RECORDS[] = "processRecords";
const char CACHE_MANAGER_UPDATE_TIME[] = "updateTime";
const std::string PRIVILEGE_CACHE_FILE_PATH = Constants::USER_INFO_BASE +
    Constants::PATH_SEPARATOR + "privilege_cache.json";
const int32_t HUKS_TIMEOUT = 6; // seconds
}

std::shared_ptr<PrivilegeRecord> PrivilegeRecord::FromJson(const cJSON *jsonObjPtr)
{
    if ((jsonObjPtr == nullptr) || !IsObject(jsonObjPtr)) {
        ACCOUNT_LOGE("Input jsonObjPtr is null or not object");
        return nullptr;
    }
    int64_t expiredTime = -1;
    std::string privilegeName = "";
    if (!GetDataByType<std::string>(jsonObjPtr, PRIVILEGE_RECORD_NAME, privilegeName)) {
        ACCOUNT_LOGE("Get privilegeName failed");
        return nullptr;
    }
    uint32_t privilegeIdx = 0xff;
    if (!TransferPrivilegeToCode(privilegeName, privilegeIdx)) {
        ACCOUNT_LOGE("TransferPrivilegeToCode failed, name=%{public}s", privilegeName.c_str());
        return nullptr;
    }
    if (!GetDataByType<int64_t>(jsonObjPtr, PRIVILEGE_RECORD_EXPIRED_TIMESTAMP, expiredTime)) {
        ACCOUNT_LOGE("Get expiredTime failed");
        return nullptr;
    }
    int64_t safeStartTime = -1;
    if (!GetDataByType<int64_t>(jsonObjPtr, PRIVILEGE_RECORD_SAFE_START_TIME, safeStartTime)) {
        ACCOUNT_LOGE("Get expiredTime failed");
        return nullptr;
    }
    return std::make_shared<PrivilegeRecord>(privilegeIdx, expiredTime, static_cast<uint32_t>(safeStartTime));
}

ErrCode PrivilegeRecord::ToJson(CJsonUnique &jsonArrPtr)
{
    if (jsonArrPtr == nullptr) {
        ACCOUNT_LOGE("Input jsonArrPtr is null");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    auto curRecord = CreateJson();
    if (curRecord == nullptr) {
        ACCOUNT_LOGE("CreateJson for PrivilegeRecord failed");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    std::string privilegeName = TransferCodeToPrivilege(privilegeIdx_);
    if (!AddStringToJson(curRecord, PRIVILEGE_RECORD_NAME, privilegeName)) {
        ACCOUNT_LOGE("Add privilegeName to json failed");
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
    }
    if (!AddInt64ToJson(curRecord, PRIVILEGE_RECORD_EXPIRED_TIMESTAMP, expiredTime_)) {
        ACCOUNT_LOGE("Add expiredTime to json failed");
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
    }
    if (!AddInt64ToJson(curRecord, PRIVILEGE_RECORD_SAFE_START_TIME, static_cast<int64_t>(safeStartTime_))) {
        ACCOUNT_LOGE("Add safeStartTime to json failed");
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
    }
    if (!AddObjToArray(jsonArrPtr, curRecord)) {
        ACCOUNT_LOGE("Add PrivilegeRecord object to json array failed");
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
    }
    return ERR_OK;
}

ErrCode PrivilegeRecord::GetRemainTimeSec(int64_t currentTimeStamp, int32_t &remainTime)
{
    remainTime = 0;
    // if current time is within +-2s of expiredTime_, should check TA
    if (currentTimeStamp < DecTimePeriod(expiredTime_, EXPIRED_TIME_OFFSET)) {
        remainTime = static_cast<int32_t>((expiredTime_ - currentTimeStamp) / MS_TO_SECOND);
        return ERR_OK;
    }
    if (currentTimeStamp <= AddTimePeriod(expiredTime_, EXPIRED_TIME_OFFSET)) {
        OsAccountTeeAdapter teeAdapter;
        PrivilegeBriefDef privilegeBriefDef;
        (void) GetPrivilegeBriefDef(privilegeIdx_, privilegeBriefDef);
        int32_t remainTimeSec = -1;
        bool isValid = false;
        ErrCode ret =
            teeAdapter.CheckTimestampExpired(safeStartTime_, privilegeBriefDef.timeout, remainTimeSec, isValid);
        if (ret != ERR_OK) {
            ACCOUNT_LOGE("CheckTimestampExpired failed, ret = %{public}d", ret);
            return ret;
        }
        if (!isValid) {
            ACCOUNT_LOGW("Timestamp expired, remainTimeSec = %{public}d", remainTimeSec);
            remainTime = 0;
            return ERR_OK;
        }
        remainTime = remainTimeSec;
        return ERR_OK;
    }
    remainTime = 0;
    return ERR_OK;
}

bool PrivilegeRecord::NeedClean(int64_t currentTimeStamp)
{
    // if current time is within +2s of expiredTime_, should not delete yet
    return !(currentTimeStamp <= AddTimePeriod(expiredTime_, EXPIRED_TIME_OFFSET));
}

ProcessPrivilegeRecord::~ProcessPrivilegeRecord()
{
    if ((remoteObject_ != nullptr) && (deathRecipient_ != nullptr)) {
        remoteObject_->RemoveDeathRecipient(deathRecipient_);
    }
}

ErrCode ProcessPrivilegeRecord::CreateEmptyProcessPrivilegeRecord(
    const AuthenCallerInfo &callerInfo, std::shared_ptr<ProcessPrivilegeRecord> &processPrivilegeRecord)
{
#ifndef ACCOUNT_TEST
    if (!callerInfo.remoteObject.has_value() || callerInfo.remoteObject.value() == nullptr) {
        ACCOUNT_LOGE("remoteObject is unset or null");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
#endif // ACCOUNT_TEST
    auto record = std::make_shared<ProcessPrivilegeRecord>();
    record->pid_ = callerInfo.pid;
    record->uid_ = callerInfo.uid;
#ifndef ACCOUNT_TEST
    record->remoteObject_ = callerInfo.remoteObject.value();
#endif // ACCOUNT_TEST
    int64_t startTime = 0;
    ErrCode ret = GetProcessStartTime(callerInfo.pid, startTime);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("GetProcessStartTime failed, ret = %{public}d", ret);
        return ret;
    }
    record->processStartTime_ = startTime;
    SmartPidFd fdPtr = nullptr;
    ret = OpenSmartPidFd(record->pid_, fdPtr);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("OpenSmartPidFd failed, ret = %{public}d", ret);
        return ret;
    }
    record->pidFdPtr_ = std::move(fdPtr);
    record->deathRecipient_ = sptr<PrivilegeDeathRecipient>::MakeSptr(record->pid_);
#ifndef ACCOUNT_TEST
    if (!record->remoteObject_->AddDeathRecipient(record->deathRecipient_)) {
        ACCOUNT_LOGE("AddDeathRecipient failed");
        return ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT;
    }
#endif // ACCOUNT_TEST
    processPrivilegeRecord = std::move(record);
    return ERR_OK;
}

ErrCode ProcessPrivilegeRecord::ParsePrivilegeRecordJsonArray(const int64_t currentTime, const cJSON *jsonObj)
{
    cJSON *item = nullptr;
    cJSON_ArrayForEach(item, jsonObj) {
        if (item == nullptr) {
            ACCOUNT_LOGE("Item is nullptr");
            return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
        }
        auto record = PrivilegeRecord::FromJson(item);
        if (record == nullptr) {
            ACCOUNT_LOGE("Parse privilege record failed.");
            return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
        }
        if (record->NeedClean(currentTime)) {
            continue;
        }
        privilegeRecordMap_[record->privilegeIdx_] = record;
    }
    return ERR_OK;
}

ErrCode ProcessPrivilegeRecord::FromJson(
    const int64_t currTime, const cJSON *jsonObjPtr, std::shared_ptr<ProcessPrivilegeRecord> &processPrivilegeRecord)
{
    if (jsonObjPtr == nullptr) {
        ACCOUNT_LOGE("Json object invalid");
        return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
    }
    auto record = std::make_shared<ProcessPrivilegeRecord>();
    if (!GetDataByType<int32_t>(jsonObjPtr, PROCESS_RECORD_PID, record->pid_)) {
        ACCOUNT_LOGE("Get pid failed");
        return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
    }
    if (!GetDataByType<int32_t>(jsonObjPtr, PROCESS_RECORD_UID, record->uid_)) {
        ACCOUNT_LOGE("Get uid failed");
        return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
    }
    if (!GetDataByType<int64_t>(jsonObjPtr, PROCESS_RECORD_START_TIME, record->processStartTime_)) {
        ACCOUNT_LOGE("Get start time failed");
        return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
    }
    if (!record->CheckProcessAlive()) {
        ACCOUNT_LOGW("Process is not alive");
        return ERR_AUTHORIZATION_CHECK_TIME_FAILED;
    }
    ErrCode ret = OpenSmartPidFd(record->pid_, record->pidFdPtr_);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("OpenSmartPidFd failed, ret = %{public}d", ret);
        return ret;
    }
    auto arrayPtr = GetJsonArrayFromJson(jsonObjPtr, PROCESS_RECORD_PRIVILEGE_RECORDS);
    if ((arrayPtr == nullptr) || !IsArray(arrayPtr)) {
        ACCOUNT_LOGE("Get Array failed or obj is not array");
        return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
    }
    ret = record->ParsePrivilegeRecordJsonArray(currTime, arrayPtr);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("ParsePrivilegeRecordJsonArray failed, ret = %{public}d", ret);
        return ret;
    }
    if (record->GetPrivilegeNum() == 0) {
        ACCOUNT_LOGW("ProcessPrivilegeRecord is empty");
        processPrivilegeRecord = nullptr;
        return ERR_OK;
    }
    processPrivilegeRecord = std::move(record);
    return ERR_OK;
}

ErrCode ProcessPrivilegeRecord::ToJson(CJsonUnique &jsonObjPtr)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    jsonObjPtr = nullptr;
    if (GetPrivilegeNum() == 0) {
        ACCOUNT_LOGW("Record is empty, skip.");
        return ERR_OK;
    }
    auto jsonUnique = CreateJson();
    if (!AddIntToJson(jsonUnique, PROCESS_RECORD_PID, pid_)) {
        ACCOUNT_LOGE("Add pid to json failed");
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
    }
    if (!AddIntToJson(jsonUnique, PROCESS_RECORD_UID, uid_)) {
        ACCOUNT_LOGE("Add uid to json failed");
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
    }
    if (!AddInt64ToJson(jsonUnique, PROCESS_RECORD_START_TIME, processStartTime_)) {
        ACCOUNT_LOGE("Add start time to json failed");
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
    }
    auto privilegesArray = CreateJsonArray();
    for (const auto &[key, value] : privilegeRecordMap_) {
        ErrCode ret = value->ToJson(privilegesArray);
        if (ret != ERR_OK) {
            ACCOUNT_LOGE("AddObjToArray failed");
            return ret;
        }
    }
    if (!AddObjToJson(jsonUnique, PROCESS_RECORD_PRIVILEGE_RECORDS, privilegesArray)) {
        ACCOUNT_LOGE("Add privilege array failed");
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
    }
    jsonObjPtr = std::move(jsonUnique);
    return ERR_OK;
}

ErrCode ProcessPrivilegeRecord::CheckPrivilege(const uint32_t privilegeIdx, int32_t &remainTime)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    int64_t currTime = -1;
    ErrCode ret = GetUptimeMs(currTime);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("GetUptimeMs failed, ret = %{public}d", ret);
        return ret;
    }
    auto iter = privilegeRecordMap_.find(privilegeIdx);
    if (iter == privilegeRecordMap_.end()) {
        ACCOUNT_LOGW("Privilege not exist, idx = %{public}d", privilegeIdx);
        return ERR_AUTHORIZATION_PRIVILEGE_DENIED;
    }
    int32_t remainTimeTmp = -1;
    ret = iter->second->GetRemainTimeSec(currTime, remainTimeTmp);
    if (ret != ERR_OK) {
        ACCOUNT_LOGW("GetRemainTimeSec failed, ret = %{public}d", ret);
        return ret;
    }
    if (remainTimeTmp == 0) {
        ACCOUNT_LOGW("Privilege expired, idx = %{public}d", privilegeIdx);
        return ERR_AUTHORIZATION_PRIVILEGE_DENIED;
    }
    remainTime = remainTimeTmp;
    return ERR_OK;
}

ErrCode ProcessPrivilegeRecord::AddOrUpdatePrivilege(uint32_t privilegeIdx, uint32_t safeStartTime)
{
    int64_t currTime = -1;
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    ErrCode ret = GetUptimeMs(currTime);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("GetUptimeMs failed, ret = %{public}d", ret);
        return ret;
    }
    PrivilegeBriefDef privilegeBriefDef;
    (void) GetPrivilegeBriefDef(privilegeIdx, privilegeBriefDef);
    auto newRecord = std::make_shared<PrivilegeRecord>(
        privilegeIdx, AddTimePeriod(currTime, privilegeBriefDef.timeout), safeStartTime);
    privilegeRecordMap_[privilegeIdx] = newRecord;
    return ERR_OK;
}

ErrCode ProcessPrivilegeRecord::RemovePrivilege(uint32_t privilegeIdx)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto iter = privilegeRecordMap_.find(privilegeIdx);
    if (iter == privilegeRecordMap_.end()) {
        ACCOUNT_LOGW("Privilege not exist, idx = %{public}d", privilegeIdx);
        return ERR_OK;
    }
    privilegeRecordMap_.erase(iter);
    return ERR_OK;
}

ErrCode ProcessPrivilegeRecord::CleanCurrentExpiredPrivileges(const int64_t currentTimeStamp)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto iter = privilegeRecordMap_.begin();
    while (iter != privilegeRecordMap_.end()) {
        if (iter->second->NeedClean(currentTimeStamp)) {
            iter = privilegeRecordMap_.erase(iter);
            continue;
        }
        iter++;
    }
    return ERR_OK;
}

size_t ProcessPrivilegeRecord::GetPrivilegeNum()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return privilegeRecordMap_.size();
}

int32_t ProcessPrivilegeRecord::GetProcessLocalId()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return uid_ / UID_TRANSFORM_DIVISOR;
}

int32_t ProcessPrivilegeRecord::GetPid()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return pid_;
}

bool ProcessPrivilegeRecord::CheckProcessAlive()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (pid_ <= 0) {
        ACCOUNT_LOGE("Invalid pid");
        return false;
    }
    int64_t startTime = 0;
    ErrCode ret = GetProcessStartTime(pid_, startTime);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Get start time failed, ret = %{public}d", ret);
        return false;
    }
    if (startTime == processStartTime_) {
        return true;
    }
    ACCOUNT_LOGE("Process %{public}d start time check failed", pid_);
    return false;
}

void ProcessPrivilegeRecord::PrivilegeDeathRecipient::OnRemoteDied(
    const wptr<IRemoteObject> &remote)
{
    ACCOUNT_LOGI("OnRemoteDied, pid=%{public}d", pid_);
    (void) PrivilegeCacheManager::GetInstance().RemoveProcess(pid_);
}

PrivilegeCacheManager &PrivilegeCacheManager::GetInstance()
{
    static PrivilegeCacheManager instance;
    return instance;
}

ErrCode PrivilegeCacheManager::CheckPrivilege(const AuthenCallerInfo &callerInfo, int32_t &remainTime)
{
    // Step1. Check cache
    {
        std::lock_guard<std::recursive_mutex> lock(mapMutex_);
        auto iter = processPrivilegeMap_.find(callerInfo.pid);
        if (iter != processPrivilegeMap_.end()) {
            ErrCode ret = iter->second->CheckPrivilege(callerInfo.privilegeIdx, remainTime);
            if ((ret != ERR_OK) && (ret != ERR_AUTHORIZATION_PRIVILEGE_DENIED)) {
                ACCOUNT_LOGE("Check privilege failed, ret=%{public}d, pid=%{public}d", ret, callerInfo.pid);
            }
            if (ret != ERR_AUTHORIZATION_PRIVILEGE_DENIED) {
                return ret;
            }
        }
    }
    // Step2. Check if it is ACL granted
    remainTime = -1;
    int32_t aclLevel = -1;
    ErrCode ret = GetAcl(callerInfo.pid, aclLevel);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Get ACL level failed, ret=%{public}d", ret);
        return ret;
    }
    if (aclLevel >= 1) {
        ACCOUNT_LOGW("ACL level granted, pid=%{public}d", callerInfo.pid);
        return ERR_OK;
    }
    StartCleanTask();
    return ERR_AUTHORIZATION_PRIVILEGE_DENIED;
}

ErrCode PrivilegeCacheManager::RemoveSingle(const AuthenCallerInfo &callerInfo)
{
    std::lock_guard<std::recursive_mutex> lock(mapMutex_);
    auto iter = processPrivilegeMap_.find(callerInfo.pid);
    if (iter == processPrivilegeMap_.end()) {
        ACCOUNT_LOGW("Process privilege record not found, pid=%{public}d", callerInfo.pid);
        return ERR_OK;
    }
    (void) iter->second->RemovePrivilege(callerInfo.privilegeIdx);
    if (iter->second->GetPrivilegeNum() == 0) {
        processPrivilegeMap_.erase(iter);
    }
    // write persist file
    (void) CleanExpiredPrivilegesAndSaveToFile();
    return ERR_OK;
}

ErrCode PrivilegeCacheManager::AddCache(const AuthenCallerInfo &callerInfo, uint32_t safeStartTime)
{
    std::lock_guard<std::recursive_mutex> lock(mapMutex_);
    auto iter = processPrivilegeMap_.find(callerInfo.pid);
    if (iter == processPrivilegeMap_.end()) {
        // Process already exists, add or update privilege
        return AddNewProcessCacheInner(callerInfo, safeStartTime);
    }
    ErrCode ret = iter->second->AddOrUpdatePrivilege(callerInfo.privilegeIdx, safeStartTime);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("AddOrUpdatePrivilege failed, ret=%{public}d", ret);
        return ret;
    }
    (void) CleanExpiredPrivilegesAndSaveToFile();
    return ERR_OK;
}

ErrCode PrivilegeCacheManager::AddNewProcessCacheInner(const AuthenCallerInfo &callerInfo, uint32_t safeStartTime)
{
    // Create new process privilege record
    std::lock_guard<std::recursive_mutex> lock(mapMutex_);
    std::shared_ptr<ProcessPrivilegeRecord> record = nullptr;
    ErrCode ret = ProcessPrivilegeRecord::CreateEmptyProcessPrivilegeRecord(callerInfo, record);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("CreateEmptyProcessPrivilegeRecord failed, ret=%{public}d", ret);
        return ret;
    }
    ret = record->AddOrUpdatePrivilege(callerInfo.privilegeIdx, safeStartTime);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("AddOrUpdatePrivilege failed, ret=%{public}d", ret);
        return ret;
    }
    processPrivilegeMap_[callerInfo.pid] = record;
    (void) CleanExpiredPrivilegesAndSaveToFile();
    ACCOUNT_LOGI("Add privilege cache success, pid=%{public}d, privilegeIdx=%{public}u", callerInfo.pid,
        callerInfo.privilegeIdx);
    return ERR_OK;
}

ErrCode PrivilegeCacheManager::RemoveUser(int32_t localId)
{
    std::lock_guard<std::recursive_mutex> lock(mapMutex_);
    auto iter = processPrivilegeMap_.begin();
    while (iter != processPrivilegeMap_.end()) {
        int32_t recordLocalId = iter->second->GetProcessLocalId();
        if (recordLocalId == localId) {
            ACCOUNT_LOGI("Remove user privilege cache, userId=%{public}d, pid=%{public}d", localId, iter->first);
            iter = processPrivilegeMap_.erase(iter);
        } else {
            iter++;
        }
    }
    (void) CleanExpiredPrivilegesAndSaveToFile();
    ACCOUNT_LOGI("Remove user %{public}d cache success", localId);
    return ERR_OK;
}

ErrCode PrivilegeCacheManager::RemoveProcess(int32_t pid)
{
    std::lock_guard<std::recursive_mutex> lock(mapMutex_);
    auto iter = processPrivilegeMap_.find(pid);
    if (iter == processPrivilegeMap_.end()) {
        ACCOUNT_LOGW("Process privilege record not found, pid=%{public}d", pid);
        return ERR_OK;
    }
    processPrivilegeMap_.erase(iter);
    (void) CleanExpiredPrivilegesAndSaveToFile();
    ACCOUNT_LOGI("Remove process privilege cache success, pid=%{public}d", pid);
    return ERR_OK;
}

ErrCode PrivilegeCacheManager::FromPersistFile()
{
    std::lock_guard<std::recursive_mutex> lock(mapMutex_);
    int64_t currentTime = -1;
    ErrCode ret = GetUptimeMs(currentTime);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Get uptime failed, ret=%{public}d", ret);
        REPORT_OS_ACCOUNT_FAIL(-1, PRIVILEGE_OPT_RECOVER_PERSIST_CACHE, ret, "Get uptime failed");
        return ret;
    }
    std::string recordStr;
    bool needSkipLoading = false;
    ReadAndCheckPersistRecordValid(currentTime, recordStr, needSkipLoading);
    if (needSkipLoading) {
        ACCOUNT_LOGI("Need to skip loading privilege cache from file");
        return ERR_OK;
    }
    CJsonUnique processArray = CreateJsonFromString(recordStr);
    if ((processArray == nullptr) || !IsArray(processArray)) {
        ACCOUNT_LOGE("Parse process records to json array failed");
        return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
    }
    cJSON *item = nullptr;
    cJSON_ArrayForEach(item, processArray.get()) {
        if (item == nullptr) {
            ACCOUNT_LOGE("Item is nullptr");
            continue;
        }
        std::shared_ptr<ProcessPrivilegeRecord> record = nullptr;
        ret = ProcessPrivilegeRecord::FromJson(currentTime, item, record);
        if (ret != ERR_OK) {
            ACCOUNT_LOGW("Parse process privilege record failed, ret=%{public}d", ret);
            REPORT_OS_ACCOUNT_FAIL(-1, PRIVILEGE_OPT_RECOVER_PERSIST_CACHE, ret, "Parse process record failed");
            continue;
        }
        if (record == nullptr) {
            ACCOUNT_LOGW("No valid process privilege record");
            continue;
        }
        processPrivilegeMap_[record->GetPid()] = record;
    }
    ACCOUNT_LOGI("Load privilege cache from file success, count=%{public}zu",
        processPrivilegeMap_.size());
    return ERR_OK;
}

bool PrivilegeCacheManager::MapToJsonString(std::string &output)
{
    std::lock_guard<std::recursive_mutex> lock(mapMutex_);
    auto processArray = CreateJsonArray();
    for (const auto &[key, value] : processPrivilegeMap_) {
        CJsonUnique obj = nullptr;
        ErrCode ret = value->ToJson(obj);
        if (ret != ERR_OK) {
            ACCOUNT_LOGE("ToJson failed, ret=%{public}d", ret);
            return false;
        }
        if ((obj != nullptr) && !AddObjToArray(processArray, obj)) {
            ACCOUNT_LOGE("Add process record object to json array failed");
            return false;
        }
    }
    std::string jsonStr = PackJsonToString(processArray);
    if (jsonStr.empty()) {
        ACCOUNT_LOGE("Pack json to string failed");
        return false;
    }
    output = std::move(jsonStr);
    return true;
}

ErrCode PrivilegeCacheManager::ToJsonString(
    const int64_t currTime, const std::string &recordStr, const std::vector<uint8_t> &digest, std::string &output)
{
    auto jsonObj = CreateJson();
    if (!AddInt64ToJson(jsonObj, CACHE_MANAGER_UPDATE_TIME, currTime)) {
        ACCOUNT_LOGE("Add update time to json failed");
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
    }
    if (!AddVectorUint8ToJson(jsonObj, CACHE_MANAGER_DIGEST, digest)) {
        ACCOUNT_LOGE("Add digest to json failed");
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
    }
    if (!AddStringToJson(jsonObj, CACHE_MANAGER_PROCESS_RECORDS, recordStr)) {
        ACCOUNT_LOGE("Add record str to json failed");
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
    }
    std::string persistStr = PackJsonToString(jsonObj);
    if (persistStr.empty()) {
        ACCOUNT_LOGE("Pack persist json to string failed");
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
    }
    output = std::move(persistStr);
    return ERR_OK;
}

ErrCode PrivilegeCacheManager::ToPersistFile(const int64_t currTime)
{
    std::lock_guard<std::recursive_mutex> lock(mapMutex_);
    std::string jsonStr;
    AccountFileOperator fileOperator;
    if (processPrivilegeMap_.empty()) {
        ACCOUNT_LOGI("No privilege cache to persist");
        (void) fileOperator.DeleteFile(PRIVILEGE_CACHE_FILE_PATH);
        return ERR_OK;
    }
    if (!MapToJsonString(jsonStr)) {
        ACCOUNT_LOGE("Map to json string failed");
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
    }
    std::vector<uint8_t> digest;
    XCollieCallback callback = [](void *) {
        ACCOUNT_LOGE("Generate privilege digest during persist failed due to timeout.");
        REPORT_OS_ACCOUNT_FAIL(-1, PRIVILEGE_OPT_PERSIST_CACHE, ERR_ACCOUNT_COMMON_OPERATION_TIMEOUT,
            "Generate privilege digest during persist over time.");
    };
    int32_t timerId = HiviewDFX::XCollie::GetInstance().SetTimer(PRIVILEGE_OPT_PERSIST_CACHE, HUKS_TIMEOUT,
        callback, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
    ErrCode ret = GenerateDigestFromHuks(jsonStr, digest);
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Generate digest failed, ret=%{public}d", ret);
        REPORT_OS_ACCOUNT_FAIL(-1, PRIVILEGE_OPT_PERSIST_CACHE, ret, "Generate digest failed");
        return ret;
    }
    std::string persistStr;
    ret = ToJsonString(currTime, jsonStr, digest, persistStr);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("To json string failed, ret=%{public}d", ret);
        return ret;
    }
    ret = fileOperator.InputFileByPathAndContentWithTransaction(PRIVILEGE_CACHE_FILE_PATH, persistStr);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Write to file failed, path=%{public}s, ret=%{public}d",
            PRIVILEGE_CACHE_FILE_PATH.c_str(), ret);
        REPORT_OS_ACCOUNT_FAIL(-1, PRIVILEGE_OPT_PERSIST_CACHE, ret, "Write to file failed");
        return ret;
    }
    ACCOUNT_LOGI("Persist privilege cache to file success, path=%{public}s", PRIVILEGE_CACHE_FILE_PATH.c_str());
    return ERR_OK;
}

ErrCode PrivilegeCacheManager::CheckUpdateTimeValid(const CJsonUnique &jsonObj, const int64_t currTime)
{
    int64_t updateTime;
    if (!GetDataByType<int64_t>(jsonObj, CACHE_MANAGER_UPDATE_TIME, updateTime)) {
        ACCOUNT_LOGE("Get update time from json failed");
        return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
    }
    if (updateTime >= currTime) {
        ACCOUNT_LOGE(
            "Update time is invalid, updateTime=%{public}" PRIi64 ", current=%{public}" PRIi64, updateTime, currTime);
        AccountFileOperator fileOperator;
        (void) fileOperator.DeleteFile(PRIVILEGE_CACHE_FILE_PATH);
        return ERR_AUTHORIZATION_CHECK_TIME_FAILED;
    }
    return ERR_OK;
}

bool PrivilegeCacheManager::CheckPersistDigestValid(
    const std::string &processRecordsStr, const std::vector<uint8_t> &storedDigest)
{
    XCollieCallback callback = [](void *) {
        ACCOUNT_LOGE("Generate privilege digest during recover failed due to timeout.");
        REPORT_OS_ACCOUNT_FAIL(-1, PRIVILEGE_OPT_RECOVER_PERSIST_CACHE, ERR_ACCOUNT_COMMON_OPERATION_TIMEOUT,
            "Generate privilege digest during recover over time.");
    };
    int32_t timerId = HiviewDFX::XCollie::GetInstance().SetTimer(
        PRIVILEGE_OPT_RECOVER_PERSIST_CACHE, HUKS_TIMEOUT, callback, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);

    AccountFileOperator fileOperator;
    std::vector<uint8_t> calculatedDigest;
    ErrCode ret = GenerateDigestFromHuks(processRecordsStr, calculatedDigest);
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Generate digest from huks failed, ret=%{public}d", ret);
        REPORT_OS_ACCOUNT_FAIL(-1, PRIVILEGE_OPT_RECOVER_PERSIST_CACHE, ret, "Generate digest failed");
        return false;
    }
    if (storedDigest != calculatedDigest) {
        ACCOUNT_LOGE("Digest check failed");
        (void)fileOperator.DeleteFile(PRIVILEGE_CACHE_FILE_PATH);
        REPORT_OS_ACCOUNT_FAIL(-1, PRIVILEGE_OPT_RECOVER_PERSIST_CACHE, -1, "Generate digest not match");
        return false;
    }
    return true;
}

void PrivilegeCacheManager::ReadAndCheckPersistRecordValid(
    const int64_t currTime, std::string &recordStr, bool &needSkipLoading)
{
    AccountFileOperator fileOperator;
    needSkipLoading = true;
    if (!fileOperator.IsExistFile(PRIVILEGE_CACHE_FILE_PATH)) {
        ACCOUNT_LOGI("Privilege cache file not exist, path=%{public}s", PRIVILEGE_CACHE_FILE_PATH.c_str());
        return;
    }
    std::string fileContent;
    ErrCode ret = fileOperator.GetFileContentByPath(PRIVILEGE_CACHE_FILE_PATH, fileContent);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Read file failed, path=%{public}s, ret=%{public}d", PRIVILEGE_CACHE_FILE_PATH.c_str(), ret);
        REPORT_OS_ACCOUNT_FAIL(-1, PRIVILEGE_OPT_RECOVER_PERSIST_CACHE, ret, "Read cache file failed");
        return;
    }
    CJsonUnique jsonObj = CreateJsonFromString(fileContent);
    if ((jsonObj == nullptr) || !IsObject(jsonObj)) {
        ACCOUNT_LOGE("Parse file content to json failed");
        return;
    }
    ret = CheckUpdateTimeValid(jsonObj, currTime);
    if (ret == ERR_AUTHORIZATION_CHECK_TIME_FAILED) {
        ACCOUNT_LOGE("Update time check failed");
        (void) fileOperator.DeleteFile(PRIVILEGE_CACHE_FILE_PATH);
        return;
    }
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Update time check failed, ret=%{public}d", ret);
        return;
    }
    std::vector<uint8_t> storedDigest = GetVectorUint8FromJson(jsonObj, CACHE_MANAGER_DIGEST);
    std::string processRecordsStr;
    if (!GetDataByType<std::string>(jsonObj, CACHE_MANAGER_PROCESS_RECORDS, processRecordsStr)) {
        ACCOUNT_LOGE("Get process records from json failed");
        return;
    }
    if (!CheckPersistDigestValid(processRecordsStr, storedDigest)) {
        ACCOUNT_LOGE("Persist digest check failed");
        return;
    }
    recordStr = std::move(processRecordsStr);
    needSkipLoading = false;
    return;
}

ErrCode PrivilegeCacheManager::GenerateDigestFromHuks(const std::string &jsonStr, std::vector<uint8_t> &digest)
{
    digest.clear();
    uint8_t buf[DIGEST_LENGTH] = {0};
    ErrCode ret = GenerateAccountInfoDigest(jsonStr, buf, DIGEST_LENGTH);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Generate account info digest failed, ret=%{public}d", ret);
        return ret;
    }
    digest = std::vector<uint8_t>(buf, buf + DIGEST_LENGTH);
    return ERR_OK;
}

ErrCode PrivilegeCacheManager::CleanExpiredPrivilegesAndSaveToFile()
{
    std::lock_guard<std::recursive_mutex> lock(mapMutex_);
    int64_t currTime = -1;
    ErrCode ret = GetUptimeMs(currTime);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("GetUptimeMs failed, ret = %{public}d", ret);
        REPORT_OS_ACCOUNT_FAIL(-1, PRIVILEGE_OPT_PERSIST_CACHE, ret, "Get uptime failed");
        return ret;
    }
    auto iter = processPrivilegeMap_.begin();
    while (iter != processPrivilegeMap_.end()) {
        (void) iter->second->CleanCurrentExpiredPrivileges(currTime);
        if (iter->second->GetPrivilegeNum() == 0) {
            iter = processPrivilegeMap_.erase(iter);
            continue;
        }
        iter++;
    }
    ret = ToPersistFile(currTime);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("ToPersistFile failed, ret=%{public}d", ret);
    }
    return ret;
}

void PrivilegeCacheManager::StartCleanTask()
{
    auto task = []() {
        (void) PrivilegeCacheManager::GetInstance().CleanExpiredPrivilegesAndSaveToFile();
    };
    std::thread thread(task);
    pthread_setname_np(thread.native_handle(), "StartCleanTask");
    thread.detach();
}
} // namespace AccountSA
} // namespace OHOS