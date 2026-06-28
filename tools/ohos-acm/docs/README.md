# ohos-acm 使用文档

## 简介

`ohos-acm` 是 OpenHarmony 系统账号管理的 CLI 工具，提供 OS Account 相关信息的查询功能。

## 功能特性

- 获取当前调用进程所属 OS 账号的本地 ID

## 命令说明

### get-current-userid

获取当前调用进程所属 OS 账号的本地 ID。

```bash
ohos-acm get-current-userid
```

**成功输出示例**:
```json
{"type":"result","status":"success","data":{"userId":100}}
```

**失败输出示例**:
```json
{"type":"result","status":"failed","errCode":"ERR_GET_CURRENT_USERID","errMsg":"Failed to get OS account local ID from process","suggestion":"Check if OS account service is running properly"}
```

**说明**: 返回当前进程所属的系统账号本地 ID。返回值是一个整数，在系统启动时由 OS Account 服务分配。主账号 ID 通常为 100。

---

### --help

显示帮助信息。

```bash
ohos-acm --help
ohos-acm get-current-userid --help
```

**输出示例**:
```
ohos-acm - OS Account management command-line utility

Usage:
  ohos-acm <command> [options]

Parameters:
  --help             Display this help message

SubCommands:
  get-current-userid Get the local ID of the current OS account for the calling process

Examples:
  ohos-acm --help
  ohos-acm get-current-userid
  ohos-acm get-current-userid --help
```

---

## 通用错误码

| 错误码 | 说明 | 常见原因 |
|--------|------|----------|
| `ERR_UNKNOWN_COMMAND` | 未知命令 | 使用了不存在的子命令 |
| `ERR_GET_CURRENT_USERID` | 获取当前用户 ID 失败 | OS Account 服务未启动或异常 |

## 注意事项

1. **权限要求**: `get-current-userid` 子命令无需任何特殊权限。可通过任意进程直接调用。

2. **返回值**: `userId` 为整数类型，表示调用方进程所属 OS 账号的本地 ID。

3. **JSON 输出格式**: 所有命令返回统一的 JSON 格式，包含 `type`、`status`、`data`（成功时）或 `errCode`、`errMsg`、`suggestion`（失败时）字段。

4. **可执行文件路径**: 安装后位于 `/system/bin/cli_tool/executable/ohos-acm`。

## 使用场景

- **智能体交互**: 智能体通过 CLI 查询当前所属的 OS 账号 ID，确定操作上下文
- **脚本开发**: Shell 脚本中获取当前用户 ID 用于条件判断
- **系统诊断**: 运维人员确认进程运行在预期账号下

## 故障排除

### 问题 1: 命令返回未知命令错误

**现象**:
```json
{"type":"result","status":"failed","errCode":"ERR_UNKNOWN_COMMAND","errMsg":"Unknown command: xxx","suggestion":"Use --help to see available commands"}
```

**解决方法**:
- 使用 `ohos-acm --help` 查看可用命令列表
- 确认子命令拼写正确

### 问题 2: 获取用户 ID 失败

**现象**:
```json
{"type":"result","status":"failed","errCode":"ERR_GET_CURRENT_USERID","errMsg":"Failed to get OS account local ID from process","suggestion":"Check if OS account service is running properly"}
```

**解决方法**:
- 确认 `accountmgr` 系统能力（SA 200）已启动
- 检查系统日志: `hilog \| grep -i C01B00`

## 相关资源
- [OS Account 账号子系统](https://gitcode.com/openharmony/account_os_account)
- [系统账号API参考](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis-basic-services-kit/js-apis-osAccount-sys.md)
