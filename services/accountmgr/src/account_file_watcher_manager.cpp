/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "account_file_watcher_manager.h"

#include <dlfcn.h>
#include <pthread.h>
#include <securec.h>
#include <thread>
#include "account_hisysevent_adapter.h"
#include "account_log_wrapper.h"
#include "account_timeout_task.h"
#ifdef HAS_HUKS_PART
#include "hks_api.h"
#include "hks_param.h"
#include "hks_type.h"
#endif // HAS_HUKS_PART
#include "hitrace_adapter.h"
#include "json_utils.h"
#include "os_account_constants.h"

namespace OHOS {
namespace AccountSA {
#ifdef ENABLE_FILE_WATCHER
namespace {
constexpr uint32_t FILE_WATCHER_LIMIT = 1024 * 100;
constexpr uint32_t BUF_COMMON_SIZE = 1024 * 100;
constexpr uint32_t ALG_COMMON_SIZE = 32;
#ifdef HAS_HUKS_PART
const struct HksParam g_genSignVerifyParams[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_HMAC
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_MAC
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_SHA256
    }, {
        .tag = HKS_TAG_AUTH_STORAGE_LEVEL,
        .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE
    }
};
constexpr int32_t TIMES = 4;
constexpr int32_t MAX_UPDATE_SIZE = 256 * 100;
constexpr int32_t MAX_OUTDATA_SIZE = MAX_UPDATE_SIZE * TIMES;
constexpr char ACCOUNT_KEY_ALIAS[] = "os_account_info_encryption_key";
const HksBlob g_keyAlias = { (uint32_t)strlen(ACCOUNT_KEY_ALIAS), (uint8_t *)ACCOUNT_KEY_ALIAS };
#endif // HAS_HUKS_PART
}

#ifdef HAS_HUKS_PART
static int32_t InitParamSet(struct HksParamSet **paramSet, const struct HksParam *params, uint32_t paramCount)
{
    int32_t ret = HksInitParamSet(paramSet);
    if (ret != 0) {
        ACCOUNT_LOGE("HksInitParamSet err = %{public}d", ret);
        return ret;
    }
    ret = HksAddParams(*paramSet, params, paramCount);
    if (ret != 0) {
        ACCOUNT_LOGE("HksAddParams err = %{public}d", ret);
        HksFreeParamSet(paramSet);
        return ret;
    }

    ret = HksBuildParamSet(paramSet);
    if (ret != 0) {
        ACCOUNT_LOGE("HksBuildParamSet err = %{public}d", ret);
        HksFreeParamSet(paramSet);
        return ret;
    }
    return ret;
}

static int32_t MallocAndCheckBlobData(struct HksBlob *blob, const uint32_t blobSize)
{
    if (blobSize == 0) {
        blob->data = NULL;
        return -1;
    }
    blob->data = static_cast<uint8_t *>(malloc(blobSize));
    if (blob->data == NULL) {
        ACCOUNT_LOGE("MallocAndCheckBlobData err");
        return -1;
    }
    return 0;
}

static int32_t HksUpdateOpt(
    const struct HksBlob *handle, const struct HksParamSet *paramSet, const struct HksBlob *inData)
{
    struct HksBlob inDataSeg = *inData;
    inDataSeg.size = MAX_UPDATE_SIZE;

    uint8_t *lastPtr = inData->data + inData->size - 1;
    struct HksBlob outDataSeg = {
        .size = MAX_OUTDATA_SIZE,
        .data = NULL
    };

    bool isFinished = false;
    while (inDataSeg.data <= lastPtr) {
        if (inDataSeg.data + MAX_UPDATE_SIZE <= lastPtr) {
            outDataSeg.size = MAX_OUTDATA_SIZE;
        } else {
            isFinished = true;
            inDataSeg.size = lastPtr - inDataSeg.data + 1;
            outDataSeg.size = inDataSeg.size + MAX_UPDATE_SIZE;
        }
        if (MallocAndCheckBlobData(&outDataSeg, outDataSeg.size) != 0) {
            return -1;
        }
        int32_t ret = HksUpdate(handle, paramSet, &inDataSeg, &outDataSeg);
        if (ret != 0) {
            ACCOUNT_LOGE("HksUpdate err, ret = %{public}d", ret);
            free(outDataSeg.data);
            outDataSeg.data = NULL;
            return -1;
        }
        free(outDataSeg.data);
        outDataSeg.data = NULL;
        if ((isFinished == false) && (inDataSeg.data + MAX_UPDATE_SIZE > lastPtr)) {
            return 0;
        }
        inDataSeg.data += MAX_UPDATE_SIZE;
    }
    return 0;
}

static int32_t InitEncryptionKey()
{
    struct HksParamSet *genParamSet = nullptr;

    int32_t ret;
    do {
        ret = InitParamSet(&genParamSet, g_genSignVerifyParams, sizeof(g_genSignVerifyParams) / sizeof(HksParam));
        if (ret != 0) {
            ACCOUNT_LOGE("InitParamSet genParamSet err = %{public}d", ret);
            break;
        }
        ret = HksGenerateKey(&g_keyAlias, genParamSet, nullptr);
        if (ret != 0) {
            ACCOUNT_LOGE("HksGenerateKey err = %{public}d", ret);
            break;
        }
    } while (0);
    HksFreeParamSet(&genParamSet);
    return ret;
}

static int32_t GetDigestDataFromHuks(struct HksParamSet *genParamSet, struct HksBlob &inDataBlob,
    uint8_t* outData, uint32_t size)
{
    uint8_t handleTmp[sizeof(uint64_t)] = {0};
    struct HksBlob handleGenDigest = { (uint32_t)sizeof(uint64_t), handleTmp };

    int32_t ret = HksInit(&g_keyAlias, genParamSet, &handleGenDigest, nullptr);
    if (ret != 0) {
        ACCOUNT_LOGE("HksInit err = %{public}d", ret);
        return ret;
    }
    ret = HksUpdateOpt(&handleGenDigest, genParamSet, &inDataBlob);
    if (ret != 0) {
        ACCOUNT_LOGE("HksUpdateOpt err = %{public}d", ret);
        HksAbort(&handleGenDigest, genParamSet);
        return ret;
    }
    struct HksBlob finishOut = { 0, nullptr };
    uint8_t outDataS[ALG_COMMON_SIZE] = "out";
    struct HksBlob outDataBlob = { ALG_COMMON_SIZE, outDataS };
    ret = HksFinish(&handleGenDigest, genParamSet, &finishOut, &outDataBlob);
    if (ret != 0) {
        ACCOUNT_LOGE("HksFinish failed = %{public}d", ret);
        HksAbort(&handleGenDigest, genParamSet);
        return ret;
    }
    if (memcpy_s(outData, size, outDataS, outDataBlob.size) != EOK) {
        ACCOUNT_LOGE("Get digest failed duo to memcpy_s failed");
        return -1;
    }
    return 0;
}

int32_t GenerateAccountInfoDigest(const std::string &inData, uint8_t* outData, uint32_t size)
{
    if (inData.empty()) {
        ACCOUNT_LOGW("inData is empty.");
        return 0;
    }
    size_t len = inData.size() + 1;
    uint8_t *buffer = static_cast<uint8_t *>(malloc(len));
    if (buffer == nullptr) {
        ACCOUNT_LOGE("buffer malloc err");
        return -1;
    }
    (void)memcpy_s(buffer, len, inData.c_str(), len);
    struct HksBlob inDataBlob = { inData.size(), buffer };
    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genSignVerifyParams, sizeof(g_genSignVerifyParams) / sizeof(HksParam));
    if (ret != 0) {
        free(buffer);
        ACCOUNT_LOGE("InitParamSet err = %{public}d", ret);
        return ret;
    }
    ret = GetDigestDataFromHuks(genParamSet, inDataBlob, outData, size);
    HksFreeParamSet(&genParamSet);
    free(buffer);
    return ret;
}
#endif // HAS_HUKS_PART

AccountFileWatcherMgr::AccountFileWatcherMgr()
{
    StartTraceAdapter("InitAccountFileWatcherMgr");
    std::shared_ptr<AccountTimeoutTask> task = std::make_shared<AccountTimeoutTask>();
    bool state = task->RunTask("InitEncryptionKey", [] {
#ifdef HAS_HUKS_PART
        StartTraceAdapter("InitEncryptionKey");
        InitEncryptionKey();
        FinishTraceAdapter();
#endif // HAS_HUKS_PART
    });
    if (!state) {
        ReportServiceStartFail(ERR_ACCOUNT_COMMON_OPERATION_TIMEOUT, "InitEncryptionKey timeout");
    }
    inotifyFd_ = inotify_init();
    if (inotifyFd_ < 0) {
        ACCOUNT_LOGE("failed to init notify, errCode:%{public}d", errno);
    }
    accountFileOperator_ = std::make_shared<AccountFileOperator>();
    FD_ZERO(&fds_);
    FinishTraceAdapter();
}

AccountFileWatcherMgr &AccountFileWatcherMgr::GetInstance()
{
    static AccountFileWatcherMgr *instance = new AccountFileWatcherMgr();
    return *instance;
}

void AccountFileWatcherMgr::DealWithFileEvent()
{
    std::vector<std::pair<std::shared_ptr<FileWatcher>, uint32_t>> eventMap;
    {
        std::lock_guard<std::mutex> lock(fileWatcherMgrLock_);
        char buf[BUF_COMMON_SIZE] = {0};
        struct inotify_event *event = nullptr;
        int len = 0;
        int index = 0;
        while (((len = read(inotifyFd_, &buf, sizeof(buf))) < 0) && (errno == EINTR)) {};
        while (index < len) {
            event = reinterpret_cast<inotify_event *>(buf + index);
            if (event->mask & (IN_MODIFY | IN_DELETE_SELF | IN_MOVE_SELF)) {
                if (fileNameMgrMap_.find(event->wd) != fileNameMgrMap_.end()) {
                    std::shared_ptr<FileWatcher> fileWatcher = fileNameMgrMap_[event->wd];
                    eventMap.emplace_back(std::make_pair(fileWatcher, event->mask));
                }
            }
            index += static_cast<int>(sizeof(struct inotify_event) + event->len);
        }
    }
    for (auto it : eventMap) {
        it.first->CheckNotifyEvent(it.second);
    }
}

void AccountFileWatcherMgr::GetNotifyEvent()
{
    FD_SET(inotifyFd_, &fds_);
    while (run_) {
        if (inotifyFd_ < 0) {
            ACCOUNT_LOGE("failed to run notify because no fd available.");
            break;
        }
        if (select(inotifyFd_ + 1, &fds_, nullptr, nullptr, nullptr) <= 0) {
            continue;
        }
        DealWithFileEvent();
    }
}

void AccountFileWatcherMgr::StartWatch() // start watcher
{
    if (run_) {
        return;
    }
    run_ = true;
    auto task = [this] { this->GetNotifyEvent(); };
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), "fileWatcher");
    taskThread.detach();
}

void AccountFileWatcherMgr::AddFileWatcher(
    int32_t id, CheckNotifyEventCallbackFunc checkCallbackFunc, const std::string &filePath)
{
    if (checkCallbackFunc == nullptr) {
        ACCOUNT_LOGE("Notify event callback is nullptr");
        return;
    }
    std::lock_guard<std::mutex> lock(fileWatcherMgrLock_);
    if (inotifyFd_ < 0) {
        inotifyFd_ = inotify_init();
        if (inotifyFd_ < 0) {
            ACCOUNT_LOGE("failed to init notify, errCode:%{public}d", errno);
            return;
        }
    }
    if (fileNameMgrMap_.size() > FILE_WATCHER_LIMIT) {
        ACCOUNT_LOGW("the fileWatcher limit has been reached, fileName = %{public}s", filePath.c_str());
        return;
    }
    std::shared_ptr<FileWatcher> fileWatcher;
    if (!filePath.empty()) {
        fileWatcher = std::make_shared<FileWatcher>(id, filePath, checkCallbackFunc);
    } else {
        fileWatcher = std::make_shared<FileWatcher>(id, checkCallbackFunc);
    }
    if (!fileWatcher->StartNotify(inotifyFd_, IN_MODIFY | IN_DELETE_SELF| IN_MOVE_SELF)) {
        ACCOUNT_LOGI("fileWatcher StartNotify failed, fileName = %{public}s", filePath.c_str());
        return;
    }
    fileNameMgrMap_[fileWatcher->GetWd()] = fileWatcher;
    {
        std::unique_lock<std::shared_timed_mutex> fileLock(accountFileOperator_->fileLock_);
        accountFileOperator_->SetValidModifyFileOperationFlag(filePath, false);
    }

    StartWatch();
}

void AccountFileWatcherMgr::RemoveFileWatcher(int32_t id, const std::string &filePath)
{
    std::lock_guard<std::mutex> lock(fileWatcherMgrLock_);
    int targetWd = -1;
    for (auto it : fileNameMgrMap_) {
        if ((it.second->GetLocalId() == id) && (it.second->GetFilePath() == filePath)) {
            targetWd = it.second->GetWd();
            break;
        }
    }
    if (targetWd == -1) {
        return;
    }
    fileNameMgrMap_[targetWd]->CloseNotify(inotifyFd_);
    fileNameMgrMap_.erase(targetWd);
}

ErrCode AccountFileWatcherMgr::GetAccountInfoDigestFromFile(const std::string &path, uint8_t *digest, uint32_t size)
{
    std::string accountInfoDigest;
    std::lock_guard<std::mutex> lock(accountInfoDigestFileLock_);
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(Constants::ACCOUNT_INFO_DIGEST_FILE_PATH,
        accountInfoDigest);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetFileContentByPath failed! error code %{public}d.", errCode);
        return errCode;
    }
    auto accountInfoDigestJson = CreateJsonFromString(accountInfoDigest);
    if (accountInfoDigestJson == nullptr) {
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
    }
    std::vector<uint8_t> digestTmp;
    digestTmp = GetVectorUint8FromJson(accountInfoDigestJson, path);
    if (digestTmp.size() != ALG_COMMON_SIZE) {
        ACCOUNT_LOGE("Invalid digest size: expected %{public}d, got %{public}zu", ALG_COMMON_SIZE, digestTmp.size());
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
    }
    if (memcpy_s(digest, size, digestTmp.data(), ALG_COMMON_SIZE) != EOK) {
        ACCOUNT_LOGE("Get digest failed duo to memcpy_s failed");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    return ERR_OK;
}

ErrCode AccountFileWatcherMgr::GenerateAccountInfoDigestStr(
    const std::string &userInfoPath, const std::string &accountInfoStr, std::string &digestStr)
{
    uint8_t digestOutData[ALG_COMMON_SIZE];
#ifdef HAS_HUKS_PART
    StartTraceAdapter("GenerateAccountInfoDigest Using Huks");
    int32_t result = GenerateAccountInfoDigest(accountInfoStr, digestOutData, ALG_COMMON_SIZE);
    if (result != ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(-1, "fileWatcher", result, "Generate account info digest failed");
    }

    FinishTraceAdapter();
#endif // HAS_HUKS_PART

    std::string accountInfoDigest;
    std::lock_guard<std::mutex> lock(accountInfoDigestFileLock_);
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(Constants::ACCOUNT_INFO_DIGEST_FILE_PATH,
        accountInfoDigest);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get file content failed! error code %{public}d.", errCode);
        return errCode;
    }
    auto accountInfoDigestJson = CreateJsonFromString(accountInfoDigest);
    if (accountInfoDigestJson == nullptr) {
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
    }
    AddVectorUint8ToJson(accountInfoDigestJson, userInfoPath,
                         std::vector<uint8_t>(digestOutData, digestOutData + ALG_COMMON_SIZE));
    digestStr = PackJsonToString(accountInfoDigestJson);
    if (digestStr.empty()) {
        ACCOUNT_LOGE("failed to dump json object.");
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
    }
    return ERR_OK;
}

ErrCode AccountFileWatcherMgr::AddAccountInfoDigest(const std::string accountInfo, const std::string &userInfoPath)
{
    std::string digestStr;
    if (GenerateAccountInfoDigestStr(userInfoPath, accountInfo, digestStr) == ERR_OK) {
        std::lock_guard<std::mutex> lock(accountInfoDigestFileLock_);
        return accountFileOperator_->InputFileByPathAndContent(Constants::ACCOUNT_INFO_DIGEST_FILE_PATH, digestStr);
    }
    return ERR_OK;
}

ErrCode AccountFileWatcherMgr::DeleteAccountInfoDigest(const std::string &userInfoPath)
{
    std::string accountInfoDigest;
    std::lock_guard<std::mutex> lock(accountInfoDigestFileLock_);
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(Constants::ACCOUNT_INFO_DIGEST_FILE_PATH,
        accountInfoDigest);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get file content failed! error code %{public}d.", errCode);
        return errCode;
    }
    auto accountInfoDigestJson = CreateJsonFromString(accountInfoDigest);
    if (accountInfoDigestJson == nullptr) {
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
    }
    if (!IsKeyExist(accountInfoDigestJson, userInfoPath)) {
        return ERR_OK;
    }
    DeleteItemFromJson(accountInfoDigestJson, userInfoPath);
    std::string jsonString = PackJsonToString(accountInfoDigestJson);
    ErrCode result = accountFileOperator_->InputFileByPathAndContent(
        Constants::ACCOUNT_INFO_DIGEST_FILE_PATH, jsonString);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("cannot save digest info to file, code %{public}d.", result);
        return result;
    }
    return ERR_OK;
}

FileWatcher::FileWatcher(int32_t id, const CheckNotifyEventCallbackFunc &checkCallbackFunc)
    : id_(id), eventCallbackFunc_(checkCallbackFunc)
{
    filePath_ = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id) +
        Constants::PATH_SEPARATOR + Constants::USER_INFO_FILE_NAME;
}

FileWatcher::FileWatcher(int32_t id, const std::string &filePath,
    const CheckNotifyEventCallbackFunc &checkCallbackFunc)
    : id_(id), filePath_(filePath), eventCallbackFunc_(checkCallbackFunc)
{}

FileWatcher::~FileWatcher()
{}

std::string FileWatcher::GetFilePath() const
{
    return filePath_;
}

bool FileWatcher::StartNotify(int32_t fd, const uint32_t &watchEvents)
{
    wd_ = inotify_add_watch(fd, filePath_.c_str(), watchEvents);
    if (wd_ < 0) {
        ACCOUNT_LOGE("failed to start notify, errCode:%{public}d", errno);
        return false;
    }
    return true;
}

bool FileWatcher::CheckNotifyEvent(uint32_t event)
{
    if (eventCallbackFunc_ == nullptr) {
        ACCOUNT_LOGW("eventCallbackFunc_ is nullptr.");
        return false;
    }
    if (!eventCallbackFunc_(filePath_, id_, event)) {
        ACCOUNT_LOGW("deal notify event failed.");
        return false;
    }
    return true;
}

int32_t FileWatcher::GetLocalId() const
{
    return id_;
}

int32_t FileWatcher::GetWd() const
{
    return wd_;
}

void FileWatcher::CloseNotify(int32_t fd)
{
    if (inotify_rm_watch(fd, wd_) == -1) {
        ACCOUNT_LOGE("failed to remove wd, err:%{public}d", errno);
        if (access(filePath_.c_str(), F_OK) == 0) {
            ACCOUNT_LOGE("file already exist");
            return;
        }
    }
    wd_ = -1;
}
#endif // ENABLE_FILE_WATCHER
}  // namespace AccountSA
}  // namespace OHOS