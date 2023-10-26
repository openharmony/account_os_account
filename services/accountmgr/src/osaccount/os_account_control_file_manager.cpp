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
#include "os_account_control_file_manager.h"
#include <dirent.h>
#ifdef WITH_SELINUX
#include <policycoreutils.h>
#endif // WITH_SELINUX
#include <pthread.h>
#include <securec.h>
#include <sstream>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

#include "account_log_wrapper.h"
#include "hisysevent_adapter.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_type.h"
#include "os_account_constants.h"
#include "os_account_interface.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::string DEFAULT_ACTIVATED_ACCOUNT_ID = "DefaultActivatedAccountID";
const int32_t MAX_LOCAL_ID = 10736; // int32 max value reduce 200000 be divisible by 200000

const std::string OS_ACCOUNT_STORE_ID = "os_account_info";
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
    }
};
const uint32_t ALG_COMMON_SIZE = 32;
const uint32_t BUF_COMMON_SIZE = 1024;
const int32_t TIMES = 4;
const int32_t MAX_UPDATE_SIZE = 256;
const int32_t MAX_OUTDATA_SIZE = MAX_UPDATE_SIZE * TIMES;
const char ACCOUNT_KEY_ALIAS[] = "os_account_info_encryption_key";
const HksBlob g_keyAlias = { (uint32_t)strlen(ACCOUNT_KEY_ALIAS), (uint8_t *)ACCOUNT_KEY_ALIAS };
}

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
    blob->data = (uint8_t *)malloc(blobSize);
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

static int32_t GenerateAccountInfoGigest(const std::string &inData, uint8_t* outData, uint32_t size)
{
    if (inData.empty()) {
        ACCOUNT_LOGW("inData is empty.");
        return 0;
    }
    const char *tmpInData = inData.c_str();
    struct HksBlob inDataBlob = { (uint32_t)strlen(tmpInData), (uint8_t *)tmpInData };
    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genSignVerifyParams, sizeof(g_genSignVerifyParams) / sizeof(HksParam));
    if (ret != 0) {
        ACCOUNT_LOGE("InitParamSet err = %{public}d", ret);
        return ret;
    }
    uint8_t handleTmp[sizeof(uint64_t)] = {0};
    struct HksBlob handleGenDigest = { (uint32_t)sizeof(uint64_t), handleTmp };
        ret = HksInit(&g_keyAlias, genParamSet, &handleGenDigest, nullptr);
    if (ret != 0) {
        ACCOUNT_LOGE("HksInit err = %{public}d", ret);
        return ret;
    }
    // Update loop
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
    HksFreeParamSet(&genParamSet);
    return ret;
}

bool GetValidAccountID(const std::string& dirName, std::int32_t& accountID)
{
    // check length first
    if (dirName.empty() || dirName.size() > Constants::MAX_USER_ID_LENGTH) {
        return false;
    }

    auto iter = std::any_of(dirName.begin(), dirName.end(),
        [dirName](char c) {
            return (c < '0' || c > '9');
        });
    if (iter) {
        return false;
    }

    // convert to osaccount id
    std::stringstream sstream;
    sstream << dirName;
    sstream >> accountID;
    return (accountID >= Constants::ADMIN_LOCAL_ID && accountID <= Constants::MAX_USER_ID);
}

FileWatcher::FileWatcher(const int32_t id) : id_(id)
{
    filePath_ = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id) +
        Constants::PATH_SEPARATOR + Constants::USER_INFO_FILE_NAME;
}

FileWatcher::FileWatcher(const std::string &filePath) : filePath_(filePath)
{}

FileWatcher::~FileWatcher()
{}

int32_t FileWatcher::GetNotifyId()
{
    return notifyFd_;
}

std::string FileWatcher::GetFilePath()
{
    return filePath_;
}

bool FileWatcher::InitNotify()
{
    notifyFd_ = inotify_init();
    if (notifyFd_ < 0) {
        ACCOUNT_LOGE("failed to init notify, errCode:%{public}d", errno);
        return false;
    }
    return true;
}

bool FileWatcher::StartNotify(const uint32_t &watchEvents)
{
    wd_ = inotify_add_watch(notifyFd_, filePath_.c_str(), watchEvents);
    if (wd_ < 0) {
        ACCOUNT_LOGE("failed to init notify, errCode:%{public}d", errno);
        return false;
    }
    return true;
}

bool FileWatcher::CheckNotifyEvent()
{
    if (!eventCallbackFunc_(filePath_, id_)) {
        ACCOUNT_LOGW("deal notify event failed.");
        return false;
    }
    return true;
}

void OsAccountControlFileManager::DealWithFileEvent()
{
    std::lock_guard<std::mutex> lock(fileWatcherMgrLock_);
    for (int32_t i : fdArray_) {
        if (FD_ISSET(i, &fds_)) { // check which fd has event
            char buf[BUF_COMMON_SIZE] = {0};
            struct inotify_event *event = nullptr;
            int len, index = 0;
            while (((len = read(i, &buf, sizeof(buf))) < 0) && (errno == EINTR)) {};
            while (index < len) {
                event = reinterpret_cast<inotify_event *>(buf + index);
                std::shared_ptr<FileWatcher> fileWatcher = fileNameMgrMap_[i];
                fileWatcher->CheckNotifyEvent();
                index += sizeof(struct inotify_event) + event->len;
            }
        } else {
            FD_SET(i, &fds_); // recover this fd for next check
        }
    }
    return;
}

void OsAccountControlFileManager::GetNotifyEvent()
{
    while (run_) {
        if (maxNotifyFd_ < 0) {
            ACCOUNT_LOGE("failed to run notify because no fd available.");
            run_ = false;
            break;
        }
        if (select(maxNotifyFd_ + 1, &fds_, nullptr, nullptr, nullptr) <= 0) {
            continue;
        }
        DealWithFileEvent();
    }
}

void FileWatcher::SetEventCallback(CheckNotifyEventCallbackFunc &func)
{
    eventCallbackFunc_ = func;
}

int32_t FileWatcher::GetLocalId()
{
    return id_;
}

bool FileWatcher::CloseNotifyFd()
{
    if (inotify_rm_watch(notifyFd_, wd_) == -1) {
        ACCOUNT_LOGE("failed to exec inotify_rm_watch, err:%{public}d", errno);
        if (access(filePath_.c_str(), F_OK) == 0) {
            close(notifyFd_);
            return true;
        }
    }
    int closeRet = close(notifyFd_);
    if (closeRet != 0) {
        ACCOUNT_LOGE("failed to close fd err:%{public}d", closeRet);
        return false;
    }
    notifyFd_ = -1;
    return true;
}

void OsAccountControlFileManager::RemoveFileWatcher(const int32_t id)
{
    std::lock_guard<std::mutex> lock(fileWatcherMgrLock_);
    int targetFd = -1;
    for (auto it : fileNameMgrMap_) {
        if (it.second->GetLocalId() == id) {
            targetFd = it.second->GetNotifyId();
            break;
        }
    }
    if (targetFd == -1) {
        return;
    }
    FD_CLR(targetFd, &fds_);
    if (!fileNameMgrMap_[targetFd]->CloseNotifyFd()) {
        ACCOUNT_LOGE("failed to close notifyId, userId = %{public}d", id);
    }
    fdArray_.erase(
        std::remove(fdArray_.begin(), fdArray_.end(), targetFd), fdArray_.end());

    if (maxNotifyFd_ == targetFd) {
        maxNotifyFd_ = *max_element(fdArray_.begin(), fdArray_.end());
    }
    fileNameMgrMap_.erase(targetFd);
    return;
}

void OsAccountControlFileManager::AddFileWatcher(const int32_t id)
{
    std::shared_ptr<FileWatcher> fileWatcher;
    if (id < Constants::START_USER_ID) {
        fileWatcher = std::make_shared<FileWatcher>(Constants::ACCOUNT_LIST_FILE_JSON_PATH);
    } else {
        fileWatcher = std::make_shared<FileWatcher>(id);
    }
    if (!fileWatcher->InitNotify()) {
        return;
    }
    SubscribeEventFunction(fileWatcher);
    if (!fileWatcher->StartNotify(IN_MODIFY)) {
        return;
    }
    std::lock_guard<std::mutex> lock(fileWatcherMgrLock_);
    if (fileWatcher->GetNotifyId() > maxNotifyFd_) {
        maxNotifyFd_ = fileWatcher->GetNotifyId();
    }
    fileNameMgrMap_[fileWatcher->GetNotifyId()] = fileWatcher;
    fdArray_.emplace_back(fileWatcher->GetNotifyId());
    FD_SET(fileWatcher->GetNotifyId(), &fds_);
}

bool OsAccountControlFileManager::RecoverAccountData(const std::string &fileName, const int32_t id)
{
#ifdef HAS_KV_STORE_PART
    std::string recoverDataStr;
    if (fileName == Constants::ACCOUNT_LIST_FILE_JSON_PATH) {
        Json accountListJson;
        osAccountDataBaseOperator_->GetAccountListFromStoreID(OS_ACCOUNT_STORE_ID, accountListJson);
        recoverDataStr = accountListJson.dump();
    } else {
        OsAccountInfo osAccountInfo;
        GetOsAccountFromDatabase(OS_ACCOUNT_STORE_ID, id, osAccountInfo);
        recoverDataStr = osAccountInfo.ToString();
    }
    // recover data
    ErrCode result = accountFileOperator_->InputFileByPathAndContent(fileName, recoverDataStr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("recover local file data failed, err = %{public}d", result);
        return false;
    }
    // update local digest
    std::string digestStr;
    if (GenerateAccountInfoDigestStr(fileName, recoverDataStr, digestStr) != ERR_OK) {
        return false;
    }
    accountFileOperator_->InputFileByPathAndContent(Constants::ACCOUNT_INFO_DIGEST_FILE_PATH, digestStr);
#endif
    return true;
}

void OsAccountControlFileManager::SubscribeEventFunction(std::shared_ptr<FileWatcher> &fileWatcher)
{
    CheckNotifyEventCallbackFunc checkCallbackFunc =
        [this](const std::string &fileName, const int32_t id) {
            if (accountFileOperator_->GetValidWriteFileOptFlag()) {
                ACCOUNT_LOGD("this is valid service operate, no need to deal with it.");
                accountFileOperator_->SetValidWriteFileOptFlag(false);
                return true;
            }
            std::string fileInfoStr;
            std::lock_guard<std::mutex> lock(accountInfoFileLock_);
            if (accountFileOperator_->GetFileContentByPath(fileName, fileInfoStr) != ERR_OK) {
                ACCOUNT_LOGE("get content from file %{public}s failed!", fileName.c_str());
                return false;
            }
            uint8_t localDigestData[ALG_COMMON_SIZE];
            GetAccountInfoDigestFromFile(fileName, localDigestData, ALG_COMMON_SIZE);
            uint8_t newDigestData[ALG_COMMON_SIZE];
            GenerateAccountInfoGigest(fileInfoStr, newDigestData, ALG_COMMON_SIZE);

            if (memcmp(localDigestData, newDigestData, ALG_COMMON_SIZE) == EOK) {
                ACCOUNT_LOGD("No need to recover local file data.");
                return true;
            }
            ACCOUNT_LOGW("local file data has been changed");
            return RecoverAccountData(fileName, id);
        };
    fileWatcher->SetEventCallback(checkCallbackFunc);
    return;
}

void OsAccountControlFileManager::WatchOsAccountInfoFile()
{
    if (run_) {
        return;
    }
    run_ = true;
    auto task = std::bind(&OsAccountControlFileManager::GetNotifyEvent, this);
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), "fileWatcher");
    taskThread.detach();
}

OsAccountControlFileManager::OsAccountControlFileManager()
{
    accountFileOperator_ = std::make_shared<AccountFileOperator>();
#ifdef HAS_KV_STORE_PART
    osAccountDataBaseOperator_ = std::make_shared<OsAccountDatabaseOperator>();
#endif
    osAccountFileOperator_ = std::make_shared<OsAccountFileOperator>();
    osAccountPhotoOperator_ = std::make_shared<OsAccountPhotoOperator>();
    FD_ZERO(&fds_);
}
OsAccountControlFileManager::~OsAccountControlFileManager()
{}

void OsAccountControlFileManager::Init()
{
    InitEncryptionKey();
    osAccountFileOperator_->Init();
    FileInit();
    Json accountListJson;
    ErrCode result = GetAccountListFromFile(accountListJson);
    if (result != ERR_OK) {
        return;
    }
    auto jsonEnd = accountListJson.end();
    std::vector<std::string> accountIdList;
    OHOS::AccountSA::GetDataByType<std::vector<std::string>>(
        accountListJson, jsonEnd, Constants::ACCOUNT_LIST, accountIdList, OHOS::AccountSA::JsonType::ARRAY);
    if (!accountIdList.empty()) {
        nextLocalId_ = atoi(accountIdList[accountIdList.size() - 1].c_str()) + 1;
        InitFileWatcherInfo(accountIdList);
    }
    ACCOUNT_LOGI("OsAccountControlFileManager Init end");
}

void OsAccountControlFileManager::FileInit()
{
    if (!accountFileOperator_->IsJsonFileReady(Constants::ACCOUNT_LIST_FILE_JSON_PATH)) {
        ACCOUNT_LOGI("OsAccountControlFileManager there is not have valid account list, create!");
        RecoverAccountListJsonFile();
#ifdef WITH_SELINUX
        Restorecon(Constants::ACCOUNT_LIST_FILE_JSON_PATH.c_str());
#endif // WITH_SELINUX
    }
    AddFileWatcher(-1); // -1 is special refers to accountList file.
    if (!accountFileOperator_->IsJsonFileReady(Constants::ACCOUNT_INFO_DIGEST_FILE_PATH)) {
        ACCOUNT_LOGI("OsAccountControlFileManager there is not have valid account info digest file, create!");
        RecoverAccountInfoDigestJsonFile();
#ifdef WITH_SELINUX
        Restorecon(Constants::ACCOUNT_INFO_DIGEST_FILE_PATH.c_str());
#endif // WITH_SELINUX
    }
    if (!accountFileOperator_->IsJsonFileReady(Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH)) {
        ACCOUNT_LOGI("OsAccountControlFileManager there is not have valid account list, create!");
        BuildAndSaveBaseOAConstraintsJsonFile();
#ifdef WITH_SELINUX
        Restorecon(Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH.c_str());
#endif // WITH_SELINUX
    }
    if (!accountFileOperator_->IsJsonFileReady(Constants::GLOBAL_OSACCOUNT_CONSTRAINTS_JSON_PATH)) {
        ACCOUNT_LOGI("OsAccountControlFileManager there is not have valid account list, create!");
        BuildAndSaveGlobalOAConstraintsJsonFile();
#ifdef WITH_SELINUX
        Restorecon(Constants::GLOBAL_OSACCOUNT_CONSTRAINTS_JSON_PATH.c_str());
#endif // WITH_SELINUX
    }
    if (!accountFileOperator_->IsJsonFileReady(Constants::SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH)) {
        ACCOUNT_LOGI("OsAccountControlFileManager there is not have valid account list, create!");
        BuildAndSaveSpecificOAConstraintsJsonFile();
#ifdef WITH_SELINUX
        Restorecon(Constants::SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH.c_str());
#endif // WITH_SELINUX
    }
}

void OsAccountControlFileManager::InitFileWatcherInfo(std::vector<std::string> &accountIdList)
{
    for (std::string i : accountIdList) {
        AddFileWatcher(stoi(i));
    }
    WatchOsAccountInfoFile();
}

void OsAccountControlFileManager::BuildAndSaveAccountListJsonFile(const std::vector<std::string>& accounts)
{
    ACCOUNT_LOGD("enter.");
    Json accountList = Json {
        {Constants::ACCOUNT_LIST, accounts},
        {Constants::COUNT_ACCOUNT_NUM, accounts.size()},
        {DEFAULT_ACTIVATED_ACCOUNT_ID, Constants::START_USER_ID},
        {Constants::MAX_ALLOW_CREATE_ACCOUNT_ID, Constants::MAX_USER_ID},
        {Constants::SERIAL_NUMBER_NUM, Constants::SERIAL_NUMBER_NUM_START},
        {Constants::IS_SERIAL_NUMBER_FULL, Constants::IS_SERIAL_NUMBER_FULL_INIT_VALUE},
    };
    SaveAccountListToFile(accountList);
}

void OsAccountControlFileManager::BuildAndSaveBaseOAConstraintsJsonFile()
{
    ACCOUNT_LOGI("enter.");
    std::vector<std::string> baseOAConstraints;
    if (osAccountFileOperator_->GetConstraintsByType(OsAccountType::ADMIN, baseOAConstraints) != ERR_OK) {
        ACCOUNT_LOGE("get %{public}d base os account constraints failed.", Constants::START_USER_ID);
        return;
    }
    Json baseOsAccountConstraints = Json {
        {Constants::START_USER_STRING_ID, baseOAConstraints}
    };
    SaveBaseOAConstraintsToFile(baseOsAccountConstraints);
}

void OsAccountControlFileManager::BuildAndSaveGlobalOAConstraintsJsonFile()
{
    ACCOUNT_LOGI("enter.");
    Json globalOsAccountConstraints = Json {
        {Constants::DEVICE_OWNER_ID, -1},
        {Constants::ALL_GLOBAL_CONSTRAINTS, {}}
    };
    SaveGlobalOAConstraintsToFile(globalOsAccountConstraints);
}

void OsAccountControlFileManager::BuildAndSaveSpecificOAConstraintsJsonFile()
{
    Json OsAccountConstraintsList = Json {
        {Constants::ALL_SPECIFIC_CONSTRAINTS, {}},
    };
    Json specificOsAccountConstraints = Json {
        {Constants::START_USER_STRING_ID, OsAccountConstraintsList},
    };
    SaveSpecificOAConstraintsToFile(specificOsAccountConstraints);
}

void OsAccountControlFileManager::RecoverAccountInfoDigestJsonFile()
{
    std::string listInfoStr;
    accountFileOperator_->GetFileContentByPath(Constants::ACCOUNT_LIST_FILE_JSON_PATH, listInfoStr);
    uint8_t digestOutData[ALG_COMMON_SIZE] = {0};
    GenerateAccountInfoGigest(listInfoStr, digestOutData, ALG_COMMON_SIZE);
    Json digestJsonData = Json {
        {Constants::ACCOUNT_LIST_FILE_JSON_PATH, digestOutData},
    };
    accountFileOperator_->InputFileByPathAndContent(Constants::ACCOUNT_INFO_DIGEST_FILE_PATH, digestJsonData.dump());
    return;
}

void OsAccountControlFileManager::RecoverAccountListJsonFile()
{
    // get account list
    std::vector<std::string> accounts;
    DIR* rootDir = opendir(Constants::USER_INFO_BASE.c_str());
    if (rootDir == nullptr) {
        accounts.push_back(std::to_string(Constants::START_USER_ID));  // account 100 always exists
        BuildAndSaveAccountListJsonFile(accounts);
        ACCOUNT_LOGE("cannot open dir %{public}s, err %{public}d.", Constants::USER_INFO_BASE.c_str(), errno);
        return;
    }

    struct dirent* curDir = nullptr;
    while ((curDir = readdir(rootDir)) != nullptr) {
        std::string curDirName(curDir->d_name);
        if (curDirName == "." || curDirName == ".." || curDir->d_type != DT_DIR) {
            continue;
        }

        // get and check os account id
        std::int32_t accountID = Constants::INVALID_OS_ACCOUNT_ID;
        if (!GetValidAccountID(curDirName, accountID)) {
            ACCOUNT_LOGE("invalid account id %{public}s detected in %{public}s.", curDirName.c_str(),
                Constants::USER_INFO_BASE.c_str());
            continue;
        }

        // check repeat
        bool sameAccountID = false;
        std::string curAccountIDStr = std::to_string(accountID);
        for (size_t i = 0; i < accounts.size(); ++i) {
            if (accounts[i] == curAccountIDStr) {
                ACCOUNT_LOGE("repeated account id %{public}s detected in %{public}s.", curAccountIDStr.c_str(),
                    Constants::USER_INFO_BASE.c_str());
                sameAccountID = true;
                break;
            }
        }

        if (!sameAccountID && accountID >= Constants::START_USER_ID) {
            accounts.push_back(curAccountIDStr);
        }
    }

    (void)closedir(rootDir);
    BuildAndSaveAccountListJsonFile(accounts);
}

ErrCode OsAccountControlFileManager::GetOsAccountList(std::vector<OsAccountInfo> &osAccountList)
{
    osAccountList.clear();
    Json accountListJson;
    ErrCode result = GetAccountListFromFile(accountListJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("GetAccountListFromFile failed!");
#ifdef HAS_KV_STORE_PART
        if (osAccountDataBaseOperator_->GetAccountListFromStoreID("", accountListJson) == ERR_OK) {
            SaveAccountListToFile(accountListJson);
        } else {
            return result;
        }
#else
        return result;
#endif
    }
    const auto &jsonObjectEnd = accountListJson.end();
    std::vector<std::string> idList;
    OHOS::AccountSA::GetDataByType<std::vector<std::string>>(
        accountListJson, jsonObjectEnd, Constants::ACCOUNT_LIST, idList, OHOS::AccountSA::JsonType::ARRAY);
    if (!idList.empty()) {
        for (auto it : idList) {
            OsAccountInfo osAccountInfo;
            if (GetOsAccountInfoById(std::atoi(it.c_str()), osAccountInfo) == ERR_OK) {
                if (osAccountInfo.GetPhoto() != "") {
                    std::string photo = osAccountInfo.GetPhoto();
                    GetPhotoById(osAccountInfo.GetLocalId(), photo);
                    osAccountInfo.SetPhoto(photo);
                }
                osAccountList.push_back(osAccountInfo);
            }
        }
    }
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetOsAccountInfoById(const int id, OsAccountInfo &osAccountInfo)
{
    std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id) +
                       Constants::PATH_SEPARATOR + Constants::USER_INFO_FILE_NAME;
    if (!accountFileOperator_->IsExistFile(path)) {
        if (GetOsAccountFromDatabase("", id, osAccountInfo) == ERR_OK) {
            InsertOsAccount(osAccountInfo);
            return ERR_OK;
        }
        ACCOUNT_LOGE("file %{public}s does not exist err", path.c_str());
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    std::string accountInfoStr;
    if (accountFileOperator_->GetFileContentByPath(path, accountInfoStr) != ERR_OK) {
        ACCOUNT_LOGE("get content from file %{public}s failed!", path.c_str());
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    osAccountInfo.FromJson(Json::parse(accountInfoStr, nullptr, false));
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetConstraintsByType(
    const OsAccountType type, std::vector<std::string> &constraints)
{
    int typeInit = static_cast<int>(type);
    return osAccountFileOperator_->GetConstraintsByType(typeInit, constraints);
}

ErrCode OsAccountControlFileManager::UpdateBaseOAConstraints(const std::string& idStr,
    const std::vector<std::string>& ConstraintStr, bool isAdd)
{
    Json baseOAConstraintsJson;
    ErrCode result = GetBaseOAConstraintsFromFile(baseOAConstraintsJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("get baseOAConstraints from json file failed!");
        return result;
    }

    if (baseOAConstraintsJson.find(idStr) == baseOAConstraintsJson.end()) {
        if (!isAdd) {
            return ERR_OK;
        }
        baseOAConstraintsJson.emplace(idStr, ConstraintStr);
    } else {
        std::vector<std::string> baseOAConstraints;
        auto jsonEnd = baseOAConstraintsJson.end();
        OHOS::AccountSA::GetDataByType<std::vector<std::string>>(
            baseOAConstraintsJson, jsonEnd, idStr, baseOAConstraints, OHOS::AccountSA::JsonType::ARRAY);
        for (auto it = ConstraintStr.begin(); it != ConstraintStr.end(); it++) {
            if (!isAdd) {
                baseOAConstraints.erase(std::remove(baseOAConstraints.begin(), baseOAConstraints.end(), *it),
                    baseOAConstraints.end());
                continue;
            }
            if (std::find(baseOAConstraints.begin(), baseOAConstraints.end(), *it) == baseOAConstraints.end()) {
                baseOAConstraints.emplace_back(*it);
            }
        }
        baseOAConstraintsJson[idStr] = baseOAConstraints;
    }
    return SaveBaseOAConstraintsToFile(baseOAConstraintsJson);
}

ErrCode OsAccountControlFileManager::UpdateGlobalOAConstraints(
    const std::string& idStr, const std::vector<std::string>& ConstraintStr, bool isAdd)
{
    Json globalOAConstraintsJson;
    ErrCode result = GetGlobalOAConstraintsFromFile(globalOAConstraintsJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("get globalOAConstraints from file failed!");
        return result;
    }
    GlobalConstraintsDataOperate(idStr, ConstraintStr, isAdd, globalOAConstraintsJson);
    return SaveGlobalOAConstraintsToFile(globalOAConstraintsJson);
}

void OsAccountControlFileManager::GlobalConstraintsDataOperate(const std::string& idStr,
    const std::vector<std::string>& ConstraintStr, bool isAdd, Json &globalOAConstraintsJson)
{
    std::vector<std::string> globalOAConstraintsList;
    OHOS::AccountSA::GetDataByType<std::vector<std::string>>(globalOAConstraintsJson, globalOAConstraintsJson.end(),
        Constants::ALL_GLOBAL_CONSTRAINTS, globalOAConstraintsList, OHOS::AccountSA::JsonType::ARRAY);
    std::vector<std::string> waitForErase;
    for (auto it = ConstraintStr.begin(); it != ConstraintStr.end(); it++) {
        if (!isAdd) {
            if (std::find(globalOAConstraintsList.begin(),
            globalOAConstraintsList.end(), *it) == globalOAConstraintsList.end()) {
                continue;
            }
            std::vector<std::string> constraintSourceList;
            OHOS::AccountSA::GetDataByType<std::vector<std::string>>(globalOAConstraintsJson,
                globalOAConstraintsJson.end(), *it, constraintSourceList, OHOS::AccountSA::JsonType::ARRAY);
            constraintSourceList.erase(std::remove(constraintSourceList.begin(), constraintSourceList.end(), idStr),
                constraintSourceList.end());
            if (constraintSourceList.size() == 0) {
                globalOAConstraintsList.erase(std::remove(globalOAConstraintsList.begin(),
                    globalOAConstraintsList.end(), *it), globalOAConstraintsList.end());
                globalOAConstraintsJson[Constants::ALL_GLOBAL_CONSTRAINTS] = globalOAConstraintsList;
                waitForErase.push_back(*it);
            } else {
                globalOAConstraintsJson[*it] = constraintSourceList;
            }
            continue;
        }
        if (std::find(globalOAConstraintsList.begin(),
            globalOAConstraintsList.end(), *it) != globalOAConstraintsList.end()) {
            std::vector<std::string> constraintSourceList;
            OHOS::AccountSA::GetDataByType<std::vector<std::string>>(globalOAConstraintsJson,
                globalOAConstraintsJson.end(), *it, constraintSourceList, OHOS::AccountSA::JsonType::ARRAY);
            if (std::find(constraintSourceList.begin(),
                constraintSourceList.end(), idStr) == constraintSourceList.end()) {
                constraintSourceList.emplace_back(idStr);
                globalOAConstraintsJson[*it] = constraintSourceList;
            }
            continue;
        }
        std::vector<std::string> constraintSourceList;
        constraintSourceList.emplace_back(idStr);
        globalOAConstraintsList.emplace_back(*it);
        globalOAConstraintsJson.emplace(*it, constraintSourceList);
        globalOAConstraintsJson[Constants::ALL_GLOBAL_CONSTRAINTS] = globalOAConstraintsList;
    }
    for (auto keyStr : waitForErase) {
        globalOAConstraintsJson.erase(keyStr);
    }
}

ErrCode OsAccountControlFileManager::UpdateSpecificOAConstraints(
    const std::string& idStr, const std::string& targetIdStr, const std::vector<std::string>& ConstraintStr, bool isAdd)
{
    Json specificOAConstraintsJson;
    ErrCode result = GetSpecificOAConstraintsFromFile(specificOAConstraintsJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("get specificOAConstraints from file failed!");
        return result;
    }
    if (specificOAConstraintsJson.find(targetIdStr) == specificOAConstraintsJson.end()) {
        if (!isAdd) {
            return ERR_OK;
        }
        Json osAccountConstraintsList = Json {
            {Constants::ALL_SPECIFIC_CONSTRAINTS, {}},
        };
        specificOAConstraintsJson.emplace(targetIdStr, osAccountConstraintsList);
    }
    Json userPrivateConstraintsDataJson = specificOAConstraintsJson[targetIdStr];
    SpecificConstraintsDataOperate(idStr, targetIdStr, ConstraintStr, isAdd, userPrivateConstraintsDataJson);
    specificOAConstraintsJson[targetIdStr] = userPrivateConstraintsDataJson;
    return SaveSpecificOAConstraintsToFile(specificOAConstraintsJson);
}

void OsAccountControlFileManager::SpecificConstraintsDataOperate(
    const std::string& idStr, const std::string& targetIdStr, const std::vector<std::string>& ConstraintStr,
    bool isAdd, Json& userPrivateConstraintsDataJson)
{
    std::vector<std::string> specificOAConstraintsList;
    OHOS::AccountSA::GetDataByType<std::vector<std::string>>(userPrivateConstraintsDataJson,
        userPrivateConstraintsDataJson.end(), Constants::ALL_SPECIFIC_CONSTRAINTS,
        specificOAConstraintsList, OHOS::AccountSA::JsonType::ARRAY);
    std::vector<std::string> waitForErase;
    for (auto it = ConstraintStr.begin(); it != ConstraintStr.end(); it++) {
        if (!isAdd) {
            if (userPrivateConstraintsDataJson.find(*it) == userPrivateConstraintsDataJson.end()) {
                continue;
            }
            std::vector<std::string> constraintSourceList;
            OHOS::AccountSA::GetDataByType<std::vector<std::string>>(userPrivateConstraintsDataJson,
                userPrivateConstraintsDataJson.end(), *it, constraintSourceList, OHOS::AccountSA::JsonType::ARRAY);
            constraintSourceList.erase(std::remove(constraintSourceList.begin(), constraintSourceList.end(), idStr),
                constraintSourceList.end());
            if (constraintSourceList.size() == 0) {
                specificOAConstraintsList.erase(std::remove(specificOAConstraintsList.begin(),
                    specificOAConstraintsList.end(), *it), specificOAConstraintsList.end());
                userPrivateConstraintsDataJson[Constants::ALL_SPECIFIC_CONSTRAINTS] = specificOAConstraintsList;
                waitForErase.push_back(*it);
            } else {
                userPrivateConstraintsDataJson[*it] = constraintSourceList;
            }
            continue;
        }
        if (std::find(specificOAConstraintsList.begin(),
            specificOAConstraintsList.end(), *it) != specificOAConstraintsList.end()) {
            std::vector<std::string> constraintSourceList;
            OHOS::AccountSA::GetDataByType<std::vector<std::string>>(userPrivateConstraintsDataJson,
            userPrivateConstraintsDataJson.end(), *it, constraintSourceList, OHOS::AccountSA::JsonType::ARRAY);
            if (std::find(constraintSourceList.begin(),
                constraintSourceList.end(), idStr) == constraintSourceList.end()) {
                constraintSourceList.emplace_back(idStr);
                userPrivateConstraintsDataJson[*it] = constraintSourceList;
            }
            continue;
        }
        std::vector<std::string> constraintSourceList;
        constraintSourceList.emplace_back(idStr);
        specificOAConstraintsList.emplace_back(*it);
        userPrivateConstraintsDataJson.emplace(*it, constraintSourceList);
        userPrivateConstraintsDataJson[Constants::ALL_SPECIFIC_CONSTRAINTS] = specificOAConstraintsList;
    }
    for (auto keyStr : waitForErase) {
        userPrivateConstraintsDataJson.erase(keyStr);
    }
}

ErrCode OsAccountControlFileManager::RemoveOAConstraintsInfo(const int32_t id)
{
    ErrCode errCode = RemoveOABaseConstraintsInfo(id);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("remove os account %{public}d base constraints info failed!", id);
        return errCode;
    }
    errCode = RemoveOAGlobalConstraintsInfo(id);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("remove os account %{public}d global constraints info failed!", id);
        return errCode;
    }
    errCode = RemoveOASpecificConstraintsInfo(id);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("remove os account %{public}d specific constraints info failed!", id);
        return errCode;
    }
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::RemoveOABaseConstraintsInfo(const int32_t id)
{
    Json baseOAConstraintsJson;
    ErrCode result = GetBaseOAConstraintsFromFile(baseOAConstraintsJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("get baseOAConstraints from file failed!");
        return result;
    }
    baseOAConstraintsJson.erase(std::to_string(id));
    result = SaveBaseOAConstraintsToFile(baseOAConstraintsJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SaveBaseOAConstraintsToFile failed!");
        return result;
    }
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::RemoveOAGlobalConstraintsInfo(const int32_t id)
{
    Json globalOAConstraintsJson;
    ErrCode result = GetGlobalOAConstraintsFromFile(globalOAConstraintsJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("get globalOAConstraints from file failed!");
        return result;
    }
    std::vector<std::string> waitForErase;
    for (auto it = globalOAConstraintsJson.begin(); it != globalOAConstraintsJson.end(); it++) {
        if (it.key() != Constants::ALL_GLOBAL_CONSTRAINTS && it.key() != Constants::DEVICE_OWNER_ID) {
            std::vector<std::string> sourceList;
            OHOS::AccountSA::GetDataByType<std::vector<std::string>>(globalOAConstraintsJson,
                globalOAConstraintsJson.end(),
                it.key(),
                sourceList,
                OHOS::AccountSA::JsonType::ARRAY);
            sourceList.erase(std::remove(sourceList.begin(), sourceList.end(), std::to_string(id)), sourceList.end());
            if (sourceList.size() == 0) {
                std::vector<std::string> allGlobalConstraints;
                OHOS::AccountSA::GetDataByType<std::vector<std::string>>(globalOAConstraintsJson,
                    globalOAConstraintsJson.end(),
                    Constants::ALL_GLOBAL_CONSTRAINTS,
                    allGlobalConstraints,
                    OHOS::AccountSA::JsonType::ARRAY);
                allGlobalConstraints.erase(std::remove(allGlobalConstraints.begin(),
                    allGlobalConstraints.end(), it.key()), allGlobalConstraints.end());
                globalOAConstraintsJson[Constants::ALL_GLOBAL_CONSTRAINTS] = allGlobalConstraints;
                waitForErase.push_back(it.key());
            } else {
                globalOAConstraintsJson[it.key()] = sourceList;
            }
        }
    }
    for (auto keyStr : waitForErase) {
        globalOAConstraintsJson.erase(keyStr);
    }
    return SaveGlobalOAConstraintsToFile(globalOAConstraintsJson);
}

ErrCode OsAccountControlFileManager::RemoveOASpecificConstraintsInfo(const int32_t id)
{
    Json specificOAConstraintsJson;
    ErrCode result = GetSpecificOAConstraintsFromFile(specificOAConstraintsJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("get specificOAConstraints from file failed!");
        return result;
    }
    if (specificOAConstraintsJson.find(std::to_string(id)) != specificOAConstraintsJson.end()) {
        specificOAConstraintsJson.erase(std::to_string(id));
    }
    for (auto it = specificOAConstraintsJson.begin(); it != specificOAConstraintsJson.end(); it++) {
        std::vector<std::string> waitForErase;
        Json userPrivateConstraintsJson;
        OHOS::AccountSA::GetDataByType<Json>(specificOAConstraintsJson, specificOAConstraintsJson.end(),
            it.key(), userPrivateConstraintsJson, OHOS::AccountSA::JsonType::OBJECT);
        std::vector<std::string> allSpecificConstraints;
        OHOS::AccountSA::GetDataByType<std::vector<std::string>>(userPrivateConstraintsJson,
            userPrivateConstraintsJson.end(), Constants::ALL_SPECIFIC_CONSTRAINTS,
            allSpecificConstraints, OHOS::AccountSA::JsonType::ARRAY);
        if (allSpecificConstraints.size() == 0) {
            continue;
        }
        for (auto item = userPrivateConstraintsJson.begin(); item != userPrivateConstraintsJson.end(); item++) {
            if (item.key() == Constants::ALL_SPECIFIC_CONSTRAINTS) {
                continue;
            }
            std::vector<std::string> sourceList;
            OHOS::AccountSA::GetDataByType<std::vector<std::string>>(userPrivateConstraintsJson,
                userPrivateConstraintsJson.end(), item.key(), sourceList, OHOS::AccountSA::JsonType::ARRAY);
            sourceList.erase(std::remove(sourceList.begin(),
                sourceList.end(), std::to_string(id)), sourceList.end());
            if (sourceList.size() == 0) {
                allSpecificConstraints.erase(std::remove(allSpecificConstraints.begin(),
                    allSpecificConstraints.end(), item.key()), allSpecificConstraints.end());
                userPrivateConstraintsJson[Constants::ALL_SPECIFIC_CONSTRAINTS] = allSpecificConstraints;
                waitForErase.push_back(item.key());
            } else {
                userPrivateConstraintsJson[item.key()] = sourceList;
            }
        }
        for (auto keyStr : waitForErase) {
            userPrivateConstraintsJson.erase(keyStr);
        }
        specificOAConstraintsJson[it.key()] = userPrivateConstraintsJson;
    }
    return SaveSpecificOAConstraintsToFile(specificOAConstraintsJson);
}

ErrCode OsAccountControlFileManager::UpdateAccountList(const std::string& idStr, bool isAdd)
{
    Json accountListJson;
    ErrCode result = GetAccountListFromFile(accountListJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("get account list failed!");
        return result;
    }

    std::vector<std::string> accountIdList;
    auto jsonEnd = accountListJson.end();
    OHOS::AccountSA::GetDataByType<std::vector<std::string>>(
        accountListJson, jsonEnd, Constants::ACCOUNT_LIST, accountIdList, OHOS::AccountSA::JsonType::ARRAY);

    if (isAdd) {
        // check repeat
        if (std::find(accountIdList.begin(), accountIdList.end(), idStr) != accountIdList.end()) {
            return ERR_OK;  // already exist, no need to add.
        }
        accountIdList.emplace_back(idStr);
    } else {
        accountIdList.erase(std::remove(accountIdList.begin(), accountIdList.end(), idStr), accountIdList.end());
    }
    accountListJson[Constants::ACCOUNT_LIST] = accountIdList;
    accountListJson[Constants::COUNT_ACCOUNT_NUM] = accountIdList.size();
    return SaveAccountListToFileAndDataBase(accountListJson);
}

ErrCode OsAccountControlFileManager::InsertOsAccount(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGD("enter");
    if (osAccountInfo.GetLocalId() < Constants::ADMIN_LOCAL_ID ||
        osAccountInfo.GetLocalId() > Constants::MAX_USER_ID) {
        ACCOUNT_LOGE("error id %{public}d cannot insert", osAccountInfo.GetLocalId());
        return ERR_OSACCOUNT_SERVICE_CONTROL_ID_CANNOT_CREATE_ERROR;
    }

    std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + osAccountInfo.GetPrimeKey() +
                       Constants::PATH_SEPARATOR + Constants::USER_INFO_FILE_NAME;
    if (accountFileOperator_->IsExistFile(path) && accountFileOperator_->IsJsonFormat(path)) {
        ACCOUNT_LOGE("OsAccountControlFileManagerInsertOsAccountControlFileManagerCreateAccountDir ERR");
        return ERR_OSACCOUNT_SERVICE_CONTROL_INSERT_FILE_EXISTS_ERROR;
    }

    std::string accountInfoStr = osAccountInfo.ToString();
    if (accountInfoStr.empty()) {
        ACCOUNT_LOGE("os account info is empty! maybe some illegal characters caused exception!");
        return ERR_OSACCOUNT_SERVICE_ACCOUNT_INFO_EMPTY_ERROR;
    }
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    ErrCode result = accountFileOperator_->InputFileByPathAndContent(path, accountInfoStr);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("InputFileByPathAndContent failed! path %{public}s.", path.c_str());
        return result;
    }
#ifdef HAS_KV_STORE_PART
    osAccountDataBaseOperator_->InsertOsAccountIntoDataBase(osAccountInfo);
#endif

    if (osAccountInfo.GetLocalId() >= Constants::START_USER_ID) {
        std::string digestStr;
        if (GenerateAccountInfoDigestStr(path, accountInfoStr, digestStr) == ERR_OK) {
            accountFileOperator_->InputFileByPathAndContent(Constants::ACCOUNT_INFO_DIGEST_FILE_PATH, digestStr);
        }
        AddFileWatcher(osAccountInfo.GetLocalId());
        WatchOsAccountInfoFile();
        return UpdateAccountList(osAccountInfo.GetPrimeKey(), true);
    }
    ACCOUNT_LOGD("end");
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::DelOsAccount(const int id)
{
    ACCOUNT_LOGD("enter");
    if (id <= Constants::START_USER_ID || id > Constants::MAX_USER_ID) {
        ACCOUNT_LOGE("invalid input id %{public}d to delete!", id);
        return ERR_OSACCOUNT_SERVICE_CONTROL_CANNOT_DELETE_ID_ERROR;
    }
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id);
    ErrCode result = accountFileOperator_->DeleteDirOrFile(path);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("DeleteDirOrFile failed! path %{public}s.", path.c_str());
        return result;
    }
#ifdef HAS_KV_STORE_PART
    osAccountDataBaseOperator_->DelOsAccountFromDatabase(id);
#endif
    path += Constants::PATH_SEPARATOR + Constants::USER_INFO_FILE_NAME;
    DeleteAccountInfoDigest(path);
    return UpdateAccountList(std::to_string(id), false);
}

ErrCode OsAccountControlFileManager::GenerateAccountInfoDigestStr(
    const std::string &userInfoPath, const std::string &accountInfoStr, std::string &digestStr)
{
    uint8_t digestOutData[ALG_COMMON_SIZE];
    GenerateAccountInfoGigest(accountInfoStr, digestOutData, ALG_COMMON_SIZE);

    std::string accountInfoDigest;
    std::lock_guard<std::mutex> lock(accountInfoDigestFileLock_);
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(Constants::ACCOUNT_INFO_DIGEST_FILE_PATH,
        accountInfoDigest);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get file content failed! error code %{public}d.", errCode);
        return errCode;
    }
    Json accountInfoDigestJson;
    try {
        accountInfoDigestJson = Json::parse(accountInfoDigest, nullptr, false);
    } catch (Json::type_error& err) {
        ACCOUNT_LOGE("accountInfoDigestJson parse failed! reason: %{public}s", err.what());
    }
    accountInfoDigestJson[userInfoPath] = digestOutData;
    try {
        digestStr = accountInfoDigestJson.dump();
    } catch (Json::type_error& err) {
        ACCOUNT_LOGE("failed to dump json object, reason: %{public}s", err.what());
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::DeleteAccountInfoDigest(const std::string &userInfoPath)
{
    Json accountInfoDigestJson;
    std::string accountInfoDigest;
    std::lock_guard<std::mutex> lock(accountInfoDigestFileLock_);
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(Constants::ACCOUNT_INFO_DIGEST_FILE_PATH,
        accountInfoDigest);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get file content failed! error code %{public}d.", errCode);
        return errCode;
    }
    try {
        accountInfoDigestJson = Json::parse(accountInfoDigest, nullptr, false);
    } catch (Json::type_error& err) {
        ACCOUNT_LOGE("accountInfoDigestJson parse failed! reason: %{public}s", err.what());
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
    }
    accountInfoDigestJson.erase(userInfoPath);

    ErrCode result = accountFileOperator_->InputFileByPathAndContent(
        Constants::ACCOUNT_INFO_DIGEST_FILE_PATH, accountInfoDigestJson.dump());
    if (result != ERR_OK) {
        ACCOUNT_LOGE("cannot save digest info to file, code %{public}d.", result);
        return result;
    }
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::UpdateOsAccount(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGD("start");
    std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + osAccountInfo.GetPrimeKey() +
                       Constants::PATH_SEPARATOR + Constants::USER_INFO_FILE_NAME;
    if (!accountFileOperator_->IsExistFile(path)) {
        ACCOUNT_LOGE("path %{public}s does not exist!", path.c_str());
        return ERR_OSACCOUNT_SERVICE_CONTROL_UPDATE_FILE_NOT_EXISTS_ERROR;
    }

    std::string accountInfoStr = osAccountInfo.ToString();
    if (accountInfoStr.empty()) {
        ACCOUNT_LOGE("account info str is empty!");
        return ERR_OSACCOUNT_SERVICE_ACCOUNT_INFO_EMPTY_ERROR;
    }
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    ErrCode result = accountFileOperator_->InputFileByPathAndContent(path, accountInfoStr);
    if (result != ERR_OK) {
        return result;
    }

#if defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
    // update in database
    if (osAccountInfo.GetLocalId() >= Constants::START_USER_ID) {
        osAccountDataBaseOperator_->UpdateOsAccountInDatabase(osAccountInfo);
    }
#else  // DISTRIBUTED_FEATURE_ENABLED
    ACCOUNT_LOGI("No distributed feature!");
#endif // DISTRIBUTED_FEATURE_ENABLED

    std::string digestStr;
    if (GenerateAccountInfoDigestStr(path, accountInfoStr, digestStr) == ERR_OK) {
        accountFileOperator_->InputFileByPathAndContent(Constants::ACCOUNT_INFO_DIGEST_FILE_PATH, digestStr);
    }
    ACCOUNT_LOGD("end");
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetMaxCreatedOsAccountNum(int &maxCreatedOsAccountNum)
{
    ACCOUNT_LOGD("start");
    Json accountListJson;
    ErrCode result = GetAccountListFromFile(accountListJson);
    if (result != ERR_OK) {
        return result;
    }
    OHOS::AccountSA::GetDataByType<int>(accountListJson,
        accountListJson.end(),
        Constants::MAX_ALLOW_CREATE_ACCOUNT_ID,
        maxCreatedOsAccountNum,
        OHOS::AccountSA::JsonType::NUMBER);
    maxCreatedOsAccountNum -= Constants::START_USER_ID;
    ACCOUNT_LOGD("end");
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetSerialNumber(int64_t &serialNumber)
{
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    Json accountListJson;
    ErrCode result = GetAccountListFromFile(accountListJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("GetSerialNumber get accountList error");
        return result;
    }
    OHOS::AccountSA::GetDataByType<int64_t>(accountListJson, accountListJson.end(), Constants::SERIAL_NUMBER_NUM,
        serialNumber, OHOS::AccountSA::JsonType::NUMBER);
    if (serialNumber == Constants::CARRY_NUM) {
        accountListJson[Constants::IS_SERIAL_NUMBER_FULL] = true;
        serialNumber = Constants::SERIAL_NUMBER_NUM_START;
    }
    bool isSerialNumberFull = false;
    OHOS::AccountSA::GetDataByType<bool>(accountListJson, accountListJson.end(), Constants::IS_SERIAL_NUMBER_FULL,
        isSerialNumberFull, OHOS::AccountSA::JsonType::BOOLEAN);
    if (isSerialNumberFull) {
        std::vector<OsAccountInfo> osAccountInfos;
        result = GetOsAccountList(osAccountInfos);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("GetSerialNumber get accountList error");
            return result;
        }
        while (serialNumber < Constants::CARRY_NUM) {
            bool exists = false;
            for (auto it = osAccountInfos.begin(); it != osAccountInfos.end(); it++) {
                if (it->GetSerialNumber() ==
                    Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN * Constants::CARRY_NUM + serialNumber) {
                    exists = true;
                    break;
                }
            }
            if (!exists) {
                break;
            }
            serialNumber++;
            serialNumber = (serialNumber == Constants::CARRY_NUM) ? Constants::SERIAL_NUMBER_NUM_START : serialNumber;
        }
    }
    accountListJson[Constants::SERIAL_NUMBER_NUM] = serialNumber + 1;
    result = SaveAccountListToFileAndDataBase(accountListJson);
    if (result != ERR_OK) {
        return result;
    }
    serialNumber = serialNumber + Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN * Constants::CARRY_NUM;
    return ERR_OK;
}

int OsAccountControlFileManager::GetNextLocalId(const std::vector<std::string> &accountIdList)
{
    std::lock_guard<std::mutex> lock(operatingIdMutex_);
    do {
        if (nextLocalId_ > MAX_LOCAL_ID) {
            nextLocalId_ = Constants::START_USER_ID;
        }
        if (std::find(accountIdList.begin(), accountIdList.end(), std::to_string(nextLocalId_)) ==
            accountIdList.end()) {
            break;
        }
        nextLocalId_++;
    } while (true);
    return nextLocalId_;
}

ErrCode OsAccountControlFileManager::GetAllowCreateId(int &id)
{
    Json accountListJson;
    ErrCode result = GetAccountListFromFile(accountListJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("GetAllowCreateId get accountList error");
        return result;
    }
    auto jsonEnd = accountListJson.end();
    std::vector<std::string> accountIdList;
    OHOS::AccountSA::GetDataByType<std::vector<std::string>>(
        accountListJson, jsonEnd, Constants::ACCOUNT_LIST, accountIdList, OHOS::AccountSA::JsonType::ARRAY);
    if (accountIdList.size() >= Constants::MAX_USER_ID) {
        ACCOUNT_LOGE("GetAllowCreateId cannot create more account error");
        return ERR_OSACCOUNT_SERVICE_CONTROL_MAX_CAN_CREATE_ERROR;
    }
    id = GetNextLocalId(accountIdList);
    nextLocalId_++;
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetAccountInfoDigestFromFile(
    const std::string &path, uint8_t *digest, uint32_t size)
{
    Json accountInfoDigestJson;
    std::string accountInfoDigest;
    std::lock_guard<std::mutex> lock(accountInfoDigestFileLock_);
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(Constants::ACCOUNT_INFO_DIGEST_FILE_PATH,
        accountInfoDigest);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetFileContentByPath failed! error code %{public}d.", errCode);
        return errCode;
    }
    try {
        accountInfoDigestJson = Json::parse(accountInfoDigest, nullptr, false);
    } catch (Json::type_error& err) {
        ACCOUNT_LOGE("accountInfoDigestJson parse failed! reason: %{public}s", err.what());
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
    }
    std::vector<uint8_t> digestTmp;
    OHOS::AccountSA::GetDataByType<std::vector<uint8_t>>(accountInfoDigestJson,
        accountInfoDigestJson.end(), path, digestTmp, OHOS::AccountSA::JsonType::ARRAY);
    if (memcpy_s(digest, size, digestTmp.data(), ALG_COMMON_SIZE) != EOK) {
        ACCOUNT_LOGE("Get digest failed duo to memcpy_s failed");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetAccountListFromFile(Json &accountListJson)
{
    ACCOUNT_LOGD("enter");
    accountListJson.clear();
    std::string accountList;
    std::lock_guard<std::mutex> lock(accountListFileLock_);
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(Constants::ACCOUNT_LIST_FILE_JSON_PATH,
        accountList);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetFileContentByPath failed! error code %{public}d.", errCode);
        return errCode;
    }
    accountListJson = Json::parse(accountList, nullptr, false);
    ACCOUNT_LOGD("end");
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetBaseOAConstraintsFromFile(Json &baseOAConstraintsJson)
{
    baseOAConstraintsJson.clear();
    std::string baseOAConstraints;
    std::lock_guard<std::mutex> lock(baseOAConstraintsFileLock_);
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(
        Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH, baseOAConstraints);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetFileContentByPath failed! error code %{public}d.", errCode);
        return errCode;
    }
    baseOAConstraintsJson = Json::parse(baseOAConstraints, nullptr, false);
    if (!baseOAConstraintsJson.is_object()) {
        ACCOUNT_LOGE("base constraints json data parse failed code.");
        return errCode;
    }

    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetGlobalOAConstraintsFromFile(Json &globalOAConstraintsJson)
{
    globalOAConstraintsJson.clear();
    std::string globalOAConstraints;
    std::lock_guard<std::mutex> lock(globalOAConstraintsFileLock_);
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(
        Constants::GLOBAL_OSACCOUNT_CONSTRAINTS_JSON_PATH, globalOAConstraints);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetFileContentByPath failed! error code %{public}d.", errCode);
        return errCode;
    }
    globalOAConstraintsJson = Json::parse(globalOAConstraints, nullptr, false);
    if (!globalOAConstraintsJson.is_object()) {
        ACCOUNT_LOGE("global constraints json data parse failed code.");
        return errCode;
    }

    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetSpecificOAConstraintsFromFile(Json &specificOAConstraintsJson)
{
    specificOAConstraintsJson.clear();
    std::string specificOAConstraints;
    std::lock_guard<std::mutex> lock(specificOAConstraintsFileLock_);
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(
        Constants::SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH, specificOAConstraints);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetFileContentByPath failed! error code %{public}d.", errCode);
        return errCode;
    }
    specificOAConstraintsJson = Json::parse(specificOAConstraints, nullptr, false);
    if (!specificOAConstraintsJson.is_object()) {
        ACCOUNT_LOGE("specific constraints json data parse failed code.");
        return errCode;
    }

    return ERR_OK;
}

ErrCode OsAccountControlFileManager::IsFromBaseOAConstraintsList(
    const int32_t id, const std::string constraint, bool &isExist)
{
    isExist = false;
    std::vector<std::string> constraintsList;
    ErrCode errCode = osAccountFileOperator_->GetBaseOAConstraintsList(id, constraintsList);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetBaseOAConstraintsList failed! error code %{public}d.", errCode);
        return errCode;
    }

    if (std::find(constraintsList.begin(), constraintsList.end(), constraint) != constraintsList.end()) {
        isExist = true;
    }

    return ERR_OK;
}

ErrCode OsAccountControlFileManager::IsFromGlobalOAConstraintsList(const int32_t id, const int32_t deviceOwnerId,
    const std::string constraint, std::vector<ConstraintSourceTypeInfo> &globalSourceList)
{
    globalSourceList.clear();
    std::vector<std::string> constraintsList;
    ErrCode errCode = osAccountFileOperator_->GetGlobalOAConstraintsList(constraintsList);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetGlobalOAConstraintsList failed! error code %{public}d.", errCode);
        return errCode;
    }
    if (constraintsList.size() == 0) {
        return ERR_OK;
    }
    if (std::find(constraintsList.begin(), constraintsList.end(), constraint) != constraintsList.end()) {
        Json globalOAConstraintsJson;
        errCode = GetGlobalOAConstraintsFromFile(globalOAConstraintsJson);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("get globalOAConstraints from file failed!");
            return errCode;
        }
        std::vector<std::string> globalOAConstraintsList;
        OHOS::AccountSA::GetDataByType<std::vector<std::string>>(
            globalOAConstraintsJson,
            globalOAConstraintsJson.end(),
            constraint,
            globalOAConstraintsList,
            OHOS::AccountSA::JsonType::ARRAY);
        ConstraintSourceTypeInfo constraintSourceTypeInfo;
        for (auto it = globalOAConstraintsList.begin(); it != globalOAConstraintsList.end(); it++) {
            if (stoi(*it) == deviceOwnerId) {
                constraintSourceTypeInfo.localId = stoi(*it);
                constraintSourceTypeInfo.typeInfo = ConstraintSourceType::CONSTRAINT_TYPE_DEVICE_OWNER;
                globalSourceList.push_back(constraintSourceTypeInfo);
            } else {
                constraintSourceTypeInfo.localId = stoi(*it);
                constraintSourceTypeInfo.typeInfo = ConstraintSourceType::CONSTRAINT_TYPE_PROFILE_OWNER;
                globalSourceList.push_back(constraintSourceTypeInfo);
            }
        }
    }
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::IsFromSpecificOAConstraintsList(const int32_t id, const int32_t deviceOwnerId,
    const std::string constraint, std::vector<ConstraintSourceTypeInfo> &specificSourceList)
{
    specificSourceList.clear();
    std::vector<std::string> constraintsList;
    ErrCode errCode = osAccountFileOperator_->GetSpecificOAConstraintsList(id, constraintsList);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetSpecificOAConstraintsList failed! error code %{public}d.", errCode);
        return errCode;
    }

    if (std::find(constraintsList.begin(), constraintsList.end(), constraint) != constraintsList.end()) {
        Json specificOAConstraintsJson;
        errCode = GetSpecificOAConstraintsFromFile(specificOAConstraintsJson);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("get specificOAConstraints from file failed!");
            return errCode;
        }
        Json specificOAConstraintsInfo;
        OHOS::AccountSA::GetDataByType<Json>(specificOAConstraintsJson, specificOAConstraintsJson.end(),
            std::to_string(id), specificOAConstraintsInfo, OHOS::AccountSA::JsonType::OBJECT);
        std::vector<std::string> specificConstraintSource;
        OHOS::AccountSA::GetDataByType<std::vector<std::string>>(specificOAConstraintsInfo,
            specificOAConstraintsInfo.end(), constraint,
            specificConstraintSource, OHOS::AccountSA::JsonType::ARRAY);
        ConstraintSourceTypeInfo constraintSourceTypeInfo;
        for (auto it = specificConstraintSource.begin(); it != specificConstraintSource.end(); it++) {
            if (stoi(*it) == deviceOwnerId) {
                constraintSourceTypeInfo.localId =stoi(*it);
                constraintSourceTypeInfo.typeInfo =  ConstraintSourceType::CONSTRAINT_TYPE_DEVICE_OWNER;
                specificSourceList.push_back(constraintSourceTypeInfo);
            } else {
                constraintSourceTypeInfo.localId =stoi(*it);
                constraintSourceTypeInfo.typeInfo =  ConstraintSourceType::CONSTRAINT_TYPE_PROFILE_OWNER;
                specificSourceList.push_back(constraintSourceTypeInfo);
            }
        }
    }
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::SaveAccountListToFile(const Json &accountListJson)
{
    std::lock_guard<std::mutex> lock(accountListFileLock_);
    ErrCode result =
        accountFileOperator_->InputFileByPathAndContent(Constants::ACCOUNT_LIST_FILE_JSON_PATH, accountListJson.dump());
    if (result != ERR_OK) {
        ACCOUNT_LOGE("cannot save save account list file content!");
        return result;
    }
    std::string digestStr;
    result = GenerateAccountInfoDigestStr(Constants::ACCOUNT_LIST_FILE_JSON_PATH, accountListJson.dump(), digestStr);
    if (result == ERR_OK) {
        accountFileOperator_->InputFileByPathAndContent(Constants::ACCOUNT_INFO_DIGEST_FILE_PATH, digestStr);
    }
    ACCOUNT_LOGD("save account list file succeed!");
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::SaveBaseOAConstraintsToFile(const Json &baseOAConstraints)
{
    std::lock_guard<std::mutex> lock(baseOAConstraintsFileLock_);
    ErrCode result = accountFileOperator_->InputFileByPathAndContent(
        Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH, baseOAConstraints.dump());
    if (result != ERR_OK) {
        ACCOUNT_LOGE("cannot save base osaccount constraints file content!");
        return result;
    }

    return ERR_OK;
}

ErrCode OsAccountControlFileManager::SaveGlobalOAConstraintsToFile(const Json &globalOAConstraints)
{
    std::lock_guard<std::mutex> lock(globalOAConstraintsFileLock_);
    ErrCode result = accountFileOperator_->InputFileByPathAndContent(
        Constants::GLOBAL_OSACCOUNT_CONSTRAINTS_JSON_PATH, globalOAConstraints.dump());
    if (result != ERR_OK) {
        ACCOUNT_LOGE("cannot save global osAccount constraints file content!");
        return result;
    }

    return ERR_OK;
}

ErrCode OsAccountControlFileManager::SaveSpecificOAConstraintsToFile(const Json &specificOAConstraints)
{
    std::lock_guard<std::mutex> lock(specificOAConstraintsFileLock_);
    ErrCode result = accountFileOperator_->InputFileByPathAndContent(
        Constants::SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH, specificOAConstraints.dump());
    if (result != ERR_OK) {
        ACCOUNT_LOGE("cannot save specific osAccount constraints file content!");
        return result;
    }

    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetDeviceOwnerId(int &deviceOwnerId)
{
    Json globalOAConstraintsJson;
    ErrCode result = GetGlobalOAConstraintsFromFile(globalOAConstraintsJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("get global json data from file failed!");
        return result;
    }
    OHOS::AccountSA::GetDataByType<int>(
        globalOAConstraintsJson,
        globalOAConstraintsJson.end(),
        Constants::DEVICE_OWNER_ID,
        deviceOwnerId,
        OHOS::AccountSA::JsonType::NUMBER);
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::UpdateDeviceOwnerId(const int deviceOwnerId)
{
    Json globalOAConstraintsJson;
    ErrCode result = GetGlobalOAConstraintsFromFile(globalOAConstraintsJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("get global json data from file failed!");
        return result;
    }
    globalOAConstraintsJson[Constants::DEVICE_OWNER_ID] = deviceOwnerId;
    return SaveGlobalOAConstraintsToFile(globalOAConstraintsJson);
}

ErrCode OsAccountControlFileManager::SetDefaultActivatedOsAccount(const int32_t id)
{
    std::lock_guard<std::mutex> lock(accountInfoFileLock_);
    Json accountListJson;
    ErrCode result = GetAccountListFromFile(accountListJson);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("get account list failed!");
        return result;
    }

    accountListJson[DEFAULT_ACTIVATED_ACCOUNT_ID] = id;
    return SaveAccountListToFileAndDataBase(accountListJson);
}

ErrCode OsAccountControlFileManager::GetDefaultActivatedOsAccount(int32_t &id)
{
    Json accountListJsonData;
    ErrCode result = GetAccountListFromFile(accountListJsonData);
    if (result != ERR_OK) {
        return result;
    }
    OHOS::AccountSA::GetDataByType<int>(accountListJsonData,
        accountListJsonData.end(),
        DEFAULT_ACTIVATED_ACCOUNT_ID,
        id,
        OHOS::AccountSA::JsonType::NUMBER);
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::SaveAccountListToFileAndDataBase(const Json &accountListJson)
{
#ifdef HAS_KV_STORE_PART
    osAccountDataBaseOperator_->UpdateOsAccountIDListInDatabase(accountListJson);
#endif
    return SaveAccountListToFile(accountListJson);
}

ErrCode OsAccountControlFileManager::IsOsAccountExists(const int id, bool &isExists)
{
    isExists = false;
    std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id) +
                       Constants::PATH_SEPARATOR + Constants::USER_INFO_FILE_NAME;
    // check exist
    if (!accountFileOperator_->IsExistFile(path)) {
        ACCOUNT_LOGI("IsOsAccountExists path %{public}s does not exist!", path.c_str());
        return ERR_OK;
    }

    // check format
    if (!accountFileOperator_->IsJsonFormat(path)) {
        ACCOUNT_LOGI("IsOsAccountExists path %{public}s wrong format!", path.c_str());
        return ERR_OK;
    }

    isExists = true;
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetPhotoById(const int id, std::string &photo)
{
    std::string path =
        Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id) + Constants::PATH_SEPARATOR + photo;
    std::string byteStr = "";
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(path, byteStr);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetPhotoById cannot find photo file error");
        return errCode;
    }
    if (photo == Constants::USER_PHOTO_FILE_JPG_NAME) {
        photo =
            Constants::USER_PHOTO_BASE_JPG_HEAD + osAccountPhotoOperator_->EnCode(byteStr.c_str(), byteStr.length());
    } else {
        photo =
            Constants::USER_PHOTO_BASE_PNG_HEAD + osAccountPhotoOperator_->EnCode(byteStr.c_str(), byteStr.length());
    }
    std::string substr = "\r\n";
    while (photo.find(substr) != std::string::npos) {
        photo.erase(photo.find(substr), substr.length());
    }
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::SetPhotoById(const int id, const std::string &photo)
{
    std::string path = "";
    std::string subPhoto = "";
    if (photo.find(Constants::USER_PHOTO_BASE_JPG_HEAD) != std::string::npos) {
        path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id) + Constants::PATH_SEPARATOR +
               Constants::USER_PHOTO_FILE_JPG_NAME;
        subPhoto = photo.substr(Constants::USER_PHOTO_BASE_JPG_HEAD.size());
    } else if (photo.find(Constants::USER_PHOTO_BASE_PNG_HEAD) != std::string::npos) {
        path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(id) + Constants::PATH_SEPARATOR +
               Constants::USER_PHOTO_FILE_PNG_NAME;
        subPhoto = photo.substr(Constants::USER_PHOTO_BASE_PNG_HEAD.size());
    } else {
        ACCOUNT_LOGE("SetPhotoById photo str error");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    std::string bytePhoto = osAccountPhotoOperator_->DeCode(subPhoto);
    ErrCode errCode = accountFileOperator_->InputFileByPathAndContent(path, bytePhoto);
    if (errCode != ERR_OK) {
        return errCode;
    }
    return ERR_OK;
}

ErrCode OsAccountControlFileManager::GetGlobalOAConstraintsList(std::vector<std::string> &constraintsList)
{
    return osAccountFileOperator_->GetGlobalOAConstraintsList(constraintsList);
}

ErrCode OsAccountControlFileManager::GetSpecificOAConstraintsList(
    const int32_t id, std::vector<std::string> &constraintsList)
{
    return osAccountFileOperator_->GetSpecificOAConstraintsList(id, constraintsList);
}

ErrCode OsAccountControlFileManager::GetIsMultiOsAccountEnable(bool &isMultiOsAccountEnable)
{
    return osAccountFileOperator_->GetIsMultiOsAccountEnable(isMultiOsAccountEnable);
}
ErrCode OsAccountControlFileManager::CheckConstraintsList(
    const std::vector<std::string> &constraints, bool &isExists, bool &isOverSize)
{
    return osAccountFileOperator_->CheckConstraintsList(constraints, isExists, isOverSize);
}

ErrCode OsAccountControlFileManager::IsAllowedCreateAdmin(bool &isAllowedCreateAdmin)
{
    return osAccountFileOperator_->IsAllowedCreateAdmin(isAllowedCreateAdmin);
}

ErrCode OsAccountControlFileManager::GetCreatedOsAccountNumFromDatabase(const std::string& storeID,
    int &createdOsAccountNum)
{
#ifdef HAS_KV_STORE_PART
    return osAccountDataBaseOperator_->GetCreatedOsAccountNumFromDatabase(storeID, createdOsAccountNum);
#else
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
#endif
}

ErrCode OsAccountControlFileManager::GetSerialNumberFromDatabase(const std::string& storeID,
    int64_t &serialNumber)
{
#ifdef HAS_KV_STORE_PART
    return osAccountDataBaseOperator_->GetSerialNumberFromDatabase(storeID, serialNumber);
#else
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
#endif
}

ErrCode OsAccountControlFileManager::GetMaxAllowCreateIdFromDatabase(const std::string& storeID,
    int &id)
{
#ifdef HAS_KV_STORE_PART
    return osAccountDataBaseOperator_->GetMaxAllowCreateIdFromDatabase(storeID, id);
#else
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
#endif
}

ErrCode OsAccountControlFileManager::GetOsAccountFromDatabase(const std::string& storeID,
    const int id, OsAccountInfo &osAccountInfo)
{
#ifdef HAS_KV_STORE_PART
    return osAccountDataBaseOperator_->GetOsAccountFromDatabase(storeID, id, osAccountInfo);
#else
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
#endif
}

ErrCode OsAccountControlFileManager::GetOsAccountListFromDatabase(const std::string& storeID,
    std::vector<OsAccountInfo> &osAccountList)
{
#ifdef HAS_KV_STORE_PART
    return osAccountDataBaseOperator_->GetOsAccountListFromDatabase(storeID, osAccountList);
#else
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
#endif
}
}  // namespace AccountSA
}  // namespace OHOS