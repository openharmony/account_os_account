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
| `get-os-account-local-id` | — | — | 获取当前调用进程所属 OS 账号的本地 ID | 无 |
| `get-os-account-local-id` | `--help` | boolean | 显示该子命令的帮助信息 | 无 |

---

### get-os-account-local-id

获取当前调用进程所属 OS 账号的本地 ID。

```bash
ohos-acm get-os-account-local-id
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
ohos-acm get-os-account-local-id --help
```

**完整帮助输出示例**:
```
ohos-acm - OS Account management command-line utility

Usage:
  ohos-acm <command> [options]

Parameters:
  --help             Show this help message

SubCommands:
  get-os-account-local-id Get the local ID of the current OS account

Examples:
  ohos-acm --help
  ohos-acm get-os-account-local-id
  ohos-acm get-os-account-local-id --help
```

**子命令帮助输出示例**:
```
ohos-acm get-os-account-local-id - Get the local ID of the current OS account

Usage:
  ohos-acm get-os-account-local-id [options]

Parameters:
  --help             Show this help message

Examples:
  ohos-acm get-os-account-local-id
```

---

## Claw 规范合规性

`ohos-acm` 遵循 OpenHarmony Claw CLI 框架规范：

### 命名规范

- 工具名称: `ohos-<domain>` 格式（`ohos-acm`）
- 子命令: 小写字母加连字符（`get-os-account-local-id`）
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

```bash
# 查看帮助
ohos-acm --help

# 获取当前用户 ID
ohos-acm get-os-account-local-id

# 查看子命令帮助
ohos-acm get-os-account-local-id --help
```

## 相关资源
- [OS Account 账号子系统](https://gitcode.com/openharmony/account_os_account)
- [系统账号API参考](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/reference/apis-basic-services-kit/js-apis-osAccount-sys.md)
