/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "ability_manager_proxy.h"
#include "ability_manager_errors.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AAFwk {
using namespace AccountSA;
bool AbilityManagerProxy::WriteInterfaceToken(MessageParcel &data)
{
    if (!data.WriteInterfaceToken(AbilityManagerProxy::GetDescriptor())) {
        ACCOUNT_LOGE("write interface token failed.");
        return false;
    }
    return true;
}

int AbilityManagerProxy::StartAbility(const Want &want, int32_t userId, int requestCode)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

AppExecFwk::ElementName AbilityManagerProxy::GetTopAbility()
{
    ACCOUNT_LOGE("interface not support!");
    AppExecFwk::ElementName result;
    return result;
}

int AbilityManagerProxy::StartAbility(const Want &want, const AbilityStartSetting &abilityStartSetting,
    const sptr<IRemoteObject> &callerToken, int32_t userId, int requestCode)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::StartAbility(
    const Want &want, const sptr<IRemoteObject> &callerToken, int32_t userId, int requestCode)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::StartAbility(const Want &want, const StartOptions &startOptions,
    const sptr<IRemoteObject> &callerToken, int32_t userId, int requestCode)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::StartExtensionAbility(const Want &want, const sptr<IRemoteObject> &callerToken,
    int32_t userId, AppExecFwk::ExtensionAbilityType extensionType)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::StopExtensionAbility(const Want &want, const sptr<IRemoteObject> &callerToken,
    int32_t userId, AppExecFwk::ExtensionAbilityType extensionType)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::TerminateAbility(const sptr<IRemoteObject> &token, int resultCode, const Want *resultWant)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::TerminateAbility(const sptr<IRemoteObject> &token,
    int resultCode, const Want *resultWant, bool flag)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::SendResultToAbility(int32_t requestCode, int32_t resultCode, Want& resultWant)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::TerminateAbilityByCaller(const sptr<IRemoteObject> &callerToken, int requestCode)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::CloseAbility(const sptr<IRemoteObject> &token, int resultCode, const Want *resultWant)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::ConnectAbility(
    const Want &want, const sptr<IAbilityConnection> &connect, const sptr<IRemoteObject> &callerToken, int32_t userId)
{
    int error;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!WriteInterfaceToken(data)) {
        return INNER_ERR;
    }
    if (!data.WriteParcelable(&want)) {
        ACCOUNT_LOGE("want write failed.");
        return ERR_INVALID_VALUE;
    }
    if (connect == nullptr) {
        ACCOUNT_LOGE("connect ability fail, connect is nullptr");
        return ERR_INVALID_VALUE;
    }
    if (connect->AsObject()) {
        if (!data.WriteBool(true) || !data.WriteRemoteObject(connect->AsObject())) {
            ACCOUNT_LOGE("flag and connect write failed.");
            return ERR_INVALID_VALUE;
        }
    } else {
        if (!data.WriteBool(false)) {
            ACCOUNT_LOGE("flag write failed.");
            return ERR_INVALID_VALUE;
        }
    }
    if (callerToken) {
        if (!data.WriteBool(true) || !data.WriteRemoteObject(callerToken)) {
            ACCOUNT_LOGE("flag and callerToken write failed.");
            return ERR_INVALID_VALUE;
        }
    } else {
        if (!data.WriteBool(false)) {
            ACCOUNT_LOGE("flag write failed.");
            return ERR_INVALID_VALUE;
        }
    }
    if (!data.WriteInt32(userId)) {
        ACCOUNT_LOGE("userId write failed.");
        return INNER_ERR;
    }
    error = Remote()->SendRequest(IAbilityManager::CONNECT_ABILITY, data, reply, option);
    if (error != NO_ERROR) {
        ACCOUNT_LOGE("Send request error: %{public}d", error);
        return error;
    }
    return reply.ReadInt32();
}

int AbilityManagerProxy::DisconnectAbility(const sptr<IAbilityConnection> &connect)
{
    int error;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (connect == nullptr) {
        ACCOUNT_LOGE("disconnect ability fail, connect is nullptr");
        return ERR_INVALID_VALUE;
    }
    if (!WriteInterfaceToken(data)) {
        return INNER_ERR;
    }
    if (!data.WriteRemoteObject(connect->AsObject())) {
        ACCOUNT_LOGE("connect write failed.");
        return ERR_INVALID_VALUE;
    }

    error = Remote()->SendRequest(IAbilityManager::DISCONNECT_ABILITY, data, reply, option);
    if (error != NO_ERROR) {
        ACCOUNT_LOGE("Send request error: %{public}d", error);
        return error;
    }
    return reply.ReadInt32();
}

sptr<IAbilityScheduler> AbilityManagerProxy::AcquireDataAbility(
    const Uri &uri, bool tryBind, const sptr<IRemoteObject> &callerToken)
{
    ACCOUNT_LOGE("interface not support!");
    return nullptr;
}

int AbilityManagerProxy::ReleaseDataAbility(
    sptr<IAbilityScheduler> dataAbilityScheduler, const sptr<IRemoteObject> &callerToken)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::AttachAbilityThread(const sptr<IAbilityScheduler> &scheduler, const sptr<IRemoteObject> &token)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::AbilityTransitionDone(const sptr<IRemoteObject> &token, int state, const PacMap &saveData)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::ScheduleConnectAbilityDone(
    const sptr<IRemoteObject> &token, const sptr<IRemoteObject> &remoteObject)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::ScheduleDisconnectAbilityDone(const sptr<IRemoteObject> &token)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::ScheduleCommandAbilityDone(const sptr<IRemoteObject> &token)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

void AbilityManagerProxy::DumpSysState(
    const std::string& args, std::vector<std::string>& state, bool isClient, bool isUserId, int UserId)
{
    ACCOUNT_LOGE("interface not support!");
}

void AbilityManagerProxy::DumpState(const std::string &args, std::vector<std::string> &state)
{
    ACCOUNT_LOGE("interface not support!");
}

int AbilityManagerProxy::TerminateAbilityResult(const sptr<IRemoteObject> &token, int startId)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::MinimizeAbility(const sptr<IRemoteObject> &token, bool fromUser)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::StopServiceAbility(const Want &want, int32_t userId)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

template <typename T>
int AbilityManagerProxy::GetParcelableInfos(MessageParcel &reply, std::vector<T> &parcelableInfos)
{
    int32_t infoSize = reply.ReadInt32();
    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<T> info(reply.ReadParcelable<T>());
        if (!info) {
            ACCOUNT_LOGE("Read Parcelable infos failed.");
            return ERR_INVALID_VALUE;
        }
        parcelableInfos.emplace_back(*info);
    }
    return NO_ERROR;
}

int AbilityManagerProxy::GetMissionSnapshot(const std::string& deviceId, int32_t missionId, MissionSnapshot& snapshot)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::KillProcess(const std::string &bundleName)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

#ifdef ABILITY_COMMAND_FOR_TEST
int AbilityManagerProxy::ForceTimeoutForTest(const std::string &abilityName, const std::string &state)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}
#endif

int AbilityManagerProxy::ClearUpApplicationData(const std::string &bundleName)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::UninstallApp(const std::string &bundleName, int32_t uid)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::UpdateConfiguration(const AppExecFwk::Configuration &config)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

sptr<IWantSender> AbilityManagerProxy::GetWantSender(
    const WantSenderInfo &wantSenderInfo, const sptr<IRemoteObject> &callerToken)
{
    ACCOUNT_LOGE("interface not support!");
    return nullptr;
}

int AbilityManagerProxy::SendWantSender(const sptr<IWantSender> &target, const SenderInfo &senderInfo)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

void AbilityManagerProxy::CancelWantSender(const sptr<IWantSender> &sender)
{
    ACCOUNT_LOGE("interface not support!");
}

int AbilityManagerProxy::GetPendingWantUid(const sptr<IWantSender> &target)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::GetPendingWantUserId(const sptr<IWantSender> &target)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

std::string AbilityManagerProxy::GetPendingWantBundleName(const sptr<IWantSender> &target)
{
    ACCOUNT_LOGE("interface not support!");
    return "";
}

int AbilityManagerProxy::GetPendingWantCode(const sptr<IWantSender> &target)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::GetPendingWantType(const sptr<IWantSender> &target)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

void AbilityManagerProxy::RegisterCancelListener(const sptr<IWantSender> &sender, const sptr<IWantReceiver> &receiver)
{
    ACCOUNT_LOGE("interface not support!");
}

void AbilityManagerProxy::UnregisterCancelListener(const sptr<IWantSender> &sender, const sptr<IWantReceiver> &receiver)
{
    ACCOUNT_LOGE("interface not support!");
}

int AbilityManagerProxy::GetPendingRequestWant(const sptr<IWantSender> &target, std::shared_ptr<Want> &want)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::GetWantSenderInfo(const sptr<IWantSender> &target, std::shared_ptr<WantSenderInfo> &info)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

void AbilityManagerProxy::GetSystemMemoryAttr(AppExecFwk::SystemMemoryAttr &memoryInfo)
{
    ACCOUNT_LOGE("interface not support!");
}

int AbilityManagerProxy::GetAppMemorySize()
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

bool AbilityManagerProxy::IsRamConstrainedDevice()
{
    ACCOUNT_LOGE("interface not support!");
    return false;
}

int AbilityManagerProxy::ContinueMission(const std::string &srcDeviceId, const std::string &dstDeviceId,
    int32_t missionId, const sptr<IRemoteObject> &callBack, AAFwk::WantParams &wantParams)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::ContinueAbility(const std::string &deviceId, int32_t missionId, uint32_t versionCode)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::StartContinuation(const Want &want, const sptr<IRemoteObject> &abilityToken, int32_t status)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

void AbilityManagerProxy::NotifyCompleteContinuation(const std::string &deviceId, int32_t sessionId, bool isSuccess)
{
    ACCOUNT_LOGE("interface not support!");
}

int AbilityManagerProxy::NotifyContinuationResult(int32_t missionId, int32_t result)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::LockMissionForCleanup(int32_t missionId)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::UnlockMissionForCleanup(int32_t missionId)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::RegisterMissionListener(const sptr<IMissionListener> &listener)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::RegisterMissionListener(const std::string &deviceId,
    const sptr<IRemoteMissionListener> &listener)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::UnRegisterMissionListener(const sptr<IMissionListener> &listener)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::GetMissionInfos(const std::string& deviceId, int32_t numMax,
    std::vector<MissionInfo> &missionInfos)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::GetMissionInfo(const std::string& deviceId, int32_t missionId,
    MissionInfo &missionInfo)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::CleanMission(int32_t missionId)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::CleanAllMissions()
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::MoveMissionToFront(int32_t missionId)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::MoveMissionToFront(int32_t missionId, const StartOptions &startOptions)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::StartUser(int userId)
{
    int error;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!WriteInterfaceToken(data)) {
        return INNER_ERR;
    }
    if (!data.WriteInt32(userId)) {
        ACCOUNT_LOGE("StartUser:WriteInt32 fail.");
        return ERR_INVALID_VALUE;
    }
    error = Remote()->SendRequest(IAbilityManager::START_USER, data, reply, option);
    if (error != NO_ERROR) {
        ACCOUNT_LOGE("StartUser:SendRequest error: %{public}d", error);
        return error;
    }
    return reply.ReadInt32();
}

int AbilityManagerProxy::StopUser(int userId, const sptr<IStopUserCallback> &callback)
{
    int error;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!WriteInterfaceToken(data)) {
        return INNER_ERR;
    }
    if (!data.WriteInt32(userId)) {
        ACCOUNT_LOGE("StopUser:WriteInt32 fail.");
        return ERR_INVALID_VALUE;
    }

    if (!callback) {
        data.WriteBool(false);
    } else {
        data.WriteBool(true);
        if (!data.WriteRemoteObject(callback->AsObject())) {
            ACCOUNT_LOGE("StopUser:write IStopUserCallback fail.");
            return ERR_INVALID_VALUE;
        }
    }
    error = Remote()->SendRequest(IAbilityManager::STOP_USER, data, reply, option);
    if (error != NO_ERROR) {
        ACCOUNT_LOGE("StopUser:SendRequest error: %{public}d", error);
        return error;
    }
    return reply.ReadInt32();
}

#ifdef SUPPORT_GRAPHICS
int AbilityManagerProxy::SetMissionLabel(const sptr<IRemoteObject> &token, const std::string &label)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::SetMissionIcon(const sptr<IRemoteObject> &token,
    const std::shared_ptr<OHOS::Media::PixelMap> &icon)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::RegisterWindowManagerServiceHandler(const sptr<IWindowManagerServiceHandler>& handler)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

void AbilityManagerProxy::CompleteFirstFrameDrawing(const sptr<IRemoteObject> &abilityToken)
{
    ACCOUNT_LOGE("interface not support!");
}
#endif

int AbilityManagerProxy::GetAbilityRunningInfos(std::vector<AbilityRunningInfo> &info)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::GetExtensionRunningInfos(int upperLimit, std::vector<ExtensionRunningInfo> &info)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::GetProcessRunningInfos(std::vector<AppExecFwk::RunningProcessInfo> &info)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::StartSyncRemoteMissions(const std::string& devId, bool fixConflict, int64_t tag)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int32_t AbilityManagerProxy::StopSyncRemoteMissions(const std::string& devId)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::UnRegisterMissionListener(const std::string &deviceId,
    const sptr<IRemoteMissionListener> &listener)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::StartAbilityByCall(
    const Want &want, const sptr<IAbilityConnection> &connect, const sptr<IRemoteObject> &callerToken)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::ReleaseAbility(const sptr<IAbilityConnection> &connect, const AppExecFwk::ElementName &element)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::RegisterSnapshotHandler(const sptr<ISnapshotHandler>& handler)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::SetAbilityController(const sptr<AppExecFwk::IAbilityController> &abilityController,
    bool imAStabilityTest)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

bool AbilityManagerProxy::IsRunningInStabilityTest()
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::StartUserTest(const Want &want, const sptr<IRemoteObject> &observer)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::FinishUserTest(
    const std::string &msg, const int64_t &resultCode, const std::string &bundleName)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::GetTopAbility(sptr<IRemoteObject> &token)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::DelegatorDoAbilityForeground(const sptr<IRemoteObject> &token)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::DelegatorDoAbilityBackground(const sptr<IRemoteObject> &token)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::DoAbilityForeground(const sptr<IRemoteObject> &token, uint32_t flag)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::DoAbilityBackground(const sptr<IRemoteObject> &token, uint32_t flag)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::SendANRProcessID(int pid)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int32_t AbilityManagerProxy::GetMissionIdByToken(const sptr<IRemoteObject> &token)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

#ifdef ABILITY_COMMAND_FOR_TEST
int AbilityManagerProxy::BlockAmsService()
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::BlockAbility(int32_t abilityRecordId)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::BlockAppService()
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}
#endif
int AbilityManagerProxy::FreeInstallAbilityFromRemote(const Want &want, const sptr<IRemoteObject> &callback,
    int32_t userId, int requestCode)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

int AbilityManagerProxy::DumpAbilityInfoDone(std::vector<std::string> &infos, const sptr<IRemoteObject> &callerToken)
{
    ACCOUNT_LOGE("interface not support!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}
}  // namespace AAFwk
}  // namespace OHOS
