# ohos-acm 使用文档

## 简介

`ohos-acm` 是 OpenHarmony 系统账号管理的 CLI 工具，基于 Claw CLI 框架构建，提供 OS Account 相关信息的查询功能。

## 目录结构

| 目录/文件 | 说明 |
|-----------|------|
| `src/main.cpp` | 程序入口，负责参数解析与命令分发 |
| `src/commands.cpp` | 命令具体实现，包含帮助信息、版本输出、输出格式化 |
| `include/commands.h` | 头文件，声明命令接口与公共类型 |
| `ohos-acm.json` | Claw 规范配置文件，定义输入输出 Schema |
| `tests/` | 单元测试目录 |
| `docs/` | 文档目录 |

## 命令行说明

### 顶层参数

| 参数 | 类型 | 说明 |
|------|------|------|
| `--help` | boolean | 显示完整帮助信息，包含所有可用子命令及用法示例 |

### 子命令

| 子命令 | 参数 | 类型 | 说明 | 所需权限 |
|--------|------|------|------|----------|
| `get-current-userid` | — | — | 获取当前调用进程所属 OS 账号的本地 ID | 无 |
| `get-current-userid` | `--help` | boolean | 显示该子命令的帮助信息 | 无 |

---

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

显示帮助信息。支持顶层和子命令两个层级：

```bash
# 显示完整帮助（所有子命令列表）
ohos-acm --help

# 显示指定子命令的帮助
ohos-acm get-current-userid --help
```

**完整帮助输出示例**:
```
ohos-acm - OS Account management command-line utility

Usage:
  ohos-acm <command> [options]

Parameters:
  --help             Show this help message

SubCommands:
  get-current-userid Get the local ID of the current OS account

Examples:
  ohos-acm --help
  ohos-acm get-current-userid
  ohos-acm get-current-userid --help
```

**子命令帮助输出示例**:
```
ohos-acm get-current-userid - Get the local ID of the current OS account

Usage:
  ohos-acm get-current-userid [options]

Parameters:
  --help             Display this help message

Examples:
  ohos-acm get-current-userid
```

---

## Claw 规范合规性

`ohos-acm` 遵循 OpenHarmony Claw CLI 框架规范：

### 命名规范

- 工具名称: `ohos-<domain>` 格式（`ohos-acm`）
- 子命令: 小写字母加连字符（`get-current-userid`）
- 参数: `--<paramname>` 长选项格式

### 输入格式

工具通过 `ohos-acm.json` 定义输入/输出 Schema：
- 顶层 `inputSchema.properties` 包含 `help` 布尔类型属性
- 每个子命令的 `inputSchema.properties` 包含 `help` 布尔类型属性
- JS 应用可通过 Claw 框架以 JSON 格式传入参数

### 输出格式

所有命令的返回值格式为统一 JSON 结构：

**成功响应**:
```json
{
    "type": "result",
    "status": "success",
    "data": {
        "...": "..."
    }
}
```

**失败响应**:
```json
{
    "type": "result",
    "status": "failed",
    "errCode": "ERR_...",
    "errMsg": "...",
    "suggestion": "..."
}
```

## 通用错误码

| 错误码 | 说明 | 常见原因 |
|--------|------|----------|
| `ERR_UNKNOWN_COMMAND` | 未知命令 | 使用了不存在的子命令，或拼写错误 |
| `ERR_GET_CURRENT_USERID` | 获取当前用户 ID 失败 | OS Account 服务未启动或异常 |
| `ERR_JSON_CREATE` | JSON 对象创建失败 | 系统内存不足 |

## 使用示例

### 命令行直接调用

```bash
# 查看帮助
ohos-acm --help

# 获取当前用户 ID
ohos-acm get-current-userid

# 查看子命令帮助
ohos-acm get-current-userid --help
```

### JS 应用通过 Claw 框架调用

```javascript
// 获取当前用户 ID
claw.invoke('ohos-acm', { subcommand: 'get-current-userid' })

// 查看子命令帮助
claw.invoke('ohos-acm', { subcommand: 'get-current-userid', params: { help: true } })
```

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
- 检查系统日志: `hilog | grep -i C01B00`

### 问题 3: 子命令 --help 不可用

**现象**:
JS 应用执行 `ohos-acm get-current-userid --help` 时无法获取帮助信息。

**解决方法**:
- 确认 `ohos-acm.json` 文件中子命令的 `inputSchema.properties` 包含 `help` 属性
- 确保 Claw 框架版本支持子命令级别的参数传递

## 相关资源
- [OS Account 账号子系统](https://gitcode.com/openharmony/account_os_account)
- [系统账号API参考](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis-basic-services-kit/js-apis-osAccount-sys.md)
