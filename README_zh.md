# 系统帐号组件<a name="ZH-CN_TOPIC_0000001123681215"></a>

-   [简介](#section11660541593)
-   [组件架构图](#section1412183212132)
-   [目录](#section161941989596)
-   [说明](#section1312121216216)
    -   [接口说明](#section1551164914237)

-   [相关仓](#section1371113476307)

## 简介<a name="section11660541593"></a>

在标准系统上，系统帐号组件主要提供分布式帐号登录状态管理能力，及应用帐号添加删除等基础管理能力。

## 组件架构图<a name="section1412183212132"></a>

**图 1**  系统帐号组件架构图<a name="fig4460722185514"></a>


![](figures/zh-cn_image_account_struct.png)

## 目录<a name="section161941989596"></a>

```
/base/account/os_account
├── figures                  README图片
├── frameworks               帐号子系统kit代码
│   ├── appaccount           应用帐号kit代码
│   │   ├── core             应用帐号ipc
│   │   └── native           应用帐号内部接口
│   ├── common               共通基础代码
│   │   ├── account_error    错误码
│   │   ├── database         数据库基础代码
│   │   ├── log              打印日志代码
│   │   ├── perf_stat        性能统计
│   │   └── test             共通模块测试代码
│   ├── ohosaccount          云帐号kit代码
│   │   ├── native           应用帐号kit头文件的实现
│   │   └── test             应用帐号kit测试
│   └── osaccount            本地帐号kit代码
│       ├── core             本地帐号ipc
│       └── native           本地帐号内部接口
├── interfaces               对外公开的API
│   ├── innerkits            内部模块头文件
│   │   ├── appaccount       应用帐号内部头文件
│   │   ├── ohosaccount      云帐号内部头文件
│   │   └── osaccount        本地帐号内部头文件
│   └── kits                 内部框架
│       └── napi             系统帐号组件开发框架
├── sa_profile               帐号SA配置文件定义目录
├── services                 服务代码
│   ├── accountmgr           系统帐号组件服务代码
│   │   ├── include          系统帐号组件服务代码头文件 
│   │   ├── src              系统帐号组件服务代码头文件的实现
│   │   └── test             系统帐号组件服务代码测试
└── test                     测试代码 
    └── resource             测试资源文件
```

## 说明<a name="section1312121216216"></a>

### 接口说明<a name="section1551164914237"></a>

#### 1，分布式帐号

分布式帐号的功能主要包括查询和更新帐号登录状态，仅支持系统应用。

**表 1**  分布式帐号模块说明

<a name="table1650615420620"></a>

<table><thead align="left"><tr id="row175061254462"><th class="cellrowborder" valign="top" width="51.53%" id="mcps1.2.3.1.1"><p id="p1250613547612"><a name="p1250613547612"></a><a name="p1250613547612"></a>模块名</p>
</th>
<th class="cellrowborder" valign="top" width="48.47%" id="mcps1.2.3.1.2"><p id="p85066541767"><a name="p85066541767"></a><a name="p85066541767"></a>描述</p>
</th>
</tr>
</thead>
<tbody>
<tr id="row0506185417614"><td class="cellrowborder" valign="top" width="51.53%" headers="mcps1.2.3.1.1 "><p id="p1561112131788"><a name="p1561112131788"></a><a name="p1561112131788"></a>distributedAccount</p>
</td>
<td class="cellrowborder" valign="top" width="48.47%" headers="mcps1.2.3.1.2 "><p id="p1954531161115"><a name="p1954531161115"></a><a name="p1954531161115"></a>提供分布式帐号模块管理方法</p>
</td>    
</tr>
</tbody>
</table>

**表 2**  分布式帐号类说明

<a name="table1324102194217"></a>
<table><thead align="left"><tr id="row43241021174219"><th class="cellrowborder" valign="top" width="51.61%" id="mcps1.2.3.1.1"><p id="p10324621104214"><a name="p10324621104214"></a><a name="p10324621104214"></a>类名</p>
</th>
<th class="cellrowborder" valign="top" width="48.39%" id="mcps1.2.3.1.2"><p id="p2324221174213"><a name="p2324221174213"></a><a name="p2324221174213"></a>描述</p>
</th>
</tr>
</thead>
<tbody><tr id="row1432413213425"><td class="cellrowborder" valign="top" width="51.61%" headers="mcps1.2.3.1.1 "><p id="p1732472184212"><a name="p1732472184212"></a><a name="p1732472184212"></a>DistributedAccountAbility</p>
</td>
<td class="cellrowborder" valign="top" width="48.39%" headers="mcps1.2.3.1.2 "><p id="p1932432110421"><a name="p1932432110421"></a><a name="p1932432110421"></a>提供查询和更新分布式帐号登录状态方法</p>
</td>
</tr>
<tr id="row12324162116427"><td class="cellrowborder" valign="top" width="51.61%" headers="mcps1.2.3.1.1 "><p id="p1232422184216"><a name="p1232422184216"></a><a name="p1232422184216"></a>DistributedInfo</p>
</td>
<td class="cellrowborder" valign="top" width="48.39%" headers="mcps1.2.3.1.2 "><p id="p1324821164215"><a name="p1324821164215"></a><a name="p1324821164215"></a>提供分布式帐号信息，主要包括帐号名、帐号UID和帐号登录状态。</p>
</td>
</tr>
</tbody>
</table>

**表 3**  分布式帐号模块方法说明

<a name="table6561120114219"></a>
<table><thead align="left"><tr id="row115642084211"><th class="cellrowborder" valign="top" width="51.67%" id="mcps1.2.3.1.1"><p id="p7565201424"><a name="p7565201424"></a><a name="p7565201424"></a>方法</p>
</th>
<th class="cellrowborder" valign="top" width="48.33%" id="mcps1.2.3.1.2"><p id="p0568204427"><a name="p0568204427"></a><a name="p0568204427"></a>描述</p>
</th>
</tr>
</thead>
<tbody><tr id="row456162064218"><td class="cellrowborder" valign="top" width="51.67%" headers="mcps1.2.3.1.1 "><p id="p8388718174317"><a name="p8388718174317"></a><a name="p8388718174317"></a>function getDistributedAccountAbility(): DistributedAccountAbility</p>
</td>
<td class="cellrowborder" valign="top" width="48.33%" headers="mcps1.2.3.1.2 "><p id="p5561920194211"><a name="p5561920194211"></a><a name="p5561920194211"></a>获取分布式帐号单实例对象</p>
</td>
</tr>
</tbody>
</table>

**表 4**  DistributedAccountAbility方法说明

<a name="table1738121244713"></a>
<table><thead align="left"><tr id="row4381111254710"><th class="cellrowborder" valign="top" width="64.72%" id="mcps1.2.3.1.1"><p id="p1738116127470"><a name="p1738116127470"></a><a name="p1738116127470"></a>方法</p>
</th>
<th class="cellrowborder" valign="top" width="35.28%" id="mcps1.2.3.1.2"><p id="p10381161224717"><a name="p10381161224717"></a><a name="p10381161224717"></a>描述</p>
</th>
</tr>
</thead>
<tbody><tr id="row18381121274715"><td class="cellrowborder" valign="top" width="64.72%" headers="mcps1.2.3.1.1 "><p id="p1671817233812"><a name="p1671817233812"></a><a name="p1671817233812"></a>queryOsAccountDistributedInfo(callback: AsyncCallback&lt;DistributedInfo&gt;): void</p>
</td>
<td class="cellrowborder" valign="top" width="35.28%" headers="mcps1.2.3.1.2 "><p id="p63421233134612"><a name="p63421233134612"></a><a name="p63421233134612"></a>查询分布式帐号信息</p>
</td>
</tr>
<tr id="row1938113125470"><td class="cellrowborder" valign="top" width="64.72%" headers="mcps1.2.3.1.1 "><p id="p73429332466"><a name="p73429332466"></a><a name="p73429332466"></a>queryOsAccountDistributedInfo(): Promise&lt;DistributedInfo&gt;</p>
</td>
<td class="cellrowborder" valign="top" width="35.28%" headers="mcps1.2.3.1.2 "><p id="p7342133394620"><a name="p7342133394620"></a><a name="p7342133394620"></a>查询分布式帐号信息</p>
</td>
</tr>
<tr id="row13811912164716"><td class="cellrowborder" valign="top" width="64.72%" headers="mcps1.2.3.1.1 "><p id="p186182593814"><a name="p186182593814"></a><a name="p186182593814"></a>updateOsAccountDistributedInfo(accountInfo: DistributedInfo, callback: AsyncCallback&lt;boolean&gt;): void</p>
</td>
<td class="cellrowborder" valign="top" width="35.28%" headers="mcps1.2.3.1.2 "><p id="p1534263304617"><a name="p1534263304617"></a><a name="p1534263304617"></a>更新分布式帐号信息</p>
</td>
</tr>
<tr id="row10382181218477"><td class="cellrowborder" valign="top" width="64.72%" headers="mcps1.2.3.1.1 "><p id="p686934433810"><a name="p686934433810"></a><a name="p686934433810"></a>updateOsAccountDistributedInfo(accountInfo: DistributedInfo): Promise&lt;boolean&gt;</p>
</td>
<td class="cellrowborder" valign="top" width="35.28%" headers="mcps1.2.3.1.2 "><p id="p0342193384611"><a name="p0342193384611"></a><a name="p0342193384611"></a>更新分布式帐号信息</p>
</td>
</tr>
</tbody>
</table>


#### 2，应用帐号

应用帐号的主要功能包括应用帐号的添加、删除，查询，修改，授权等功能，提供帐号数据落盘和数据同步的能力。

**表 1**  应用帐号模块说明

<a name="table1650615420620"></a>

<table><thead align="left"><tr id="row175061254462"><th class="cellrowborder" valign="top" width="51.53%" id="mcps1.2.3.1.1"><p id="p1250613547612"><a name="p1250613547612"></a><a name="p1250613547612"></a>模块名</p>
</th>
<th class="cellrowborder" valign="top" width="48.47%" id="mcps1.2.3.1.2"><p id="p85066541767"><a name="p85066541767"></a><a name="p85066541767"></a>描述</p>
</th>
</tr>
</thead>
<tbody>
<tr id="row0506185417614"><td class="cellrowborder" valign="top" width="51.53%" headers="mcps1.2.3.1.1 "><p id="p1561112131788"><a name="p1561112131788"></a><a name="p1561112131788"></a>appAccount</p>
</td>
<td class="cellrowborder" valign="top" width="48.47%" headers="mcps1.2.3.1.2 "><p id="p1954531161115"><a name="p1954531161115"></a><a name="p1954531161115"></a>提供应用帐号模块管理方法</p>
</td>    
</tr>
</tbody>
</table>

**表 2**  应用帐号类说明

<a name="table1324102194217"></a>

<table><thead align="left"><tr id="row43241021174219"><th class="cellrowborder" valign="top" width="51.61%" id="mcps1.2.3.1.1"><p id="p10324621104214"><a name="p10324621104214"></a><a name="p10324621104214"></a>类名</p>
</th>
<th class="cellrowborder" valign="top" width="48.39%" id="mcps1.2.3.1.2"><p id="p2324221174213"><a name="p2324221174213"></a><a name="p2324221174213"></a>描述</p>
</th>
</tr>
</thead>
<tbody><tr id="row1432413213425"><td class="cellrowborder" valign="top" width="51.61%" headers="mcps1.2.3.1.1 "><p id="p1732472184212"><a name="p1732472184212"></a><a name="p1732472184212"></a>AppAccountManager</p>
</td>
<td class="cellrowborder" valign="top" width="48.39%" headers="mcps1.2.3.1.2 "><p id="p1932432110421"><a name="p1932432110421"></a><a name="p1932432110421"></a>提供查询、增加、删除、授权等应用帐号相关方法</p>
</td>
</tr>
<tr id="row12324162116427"><td class="cellrowborder" valign="top" width="51.61%" headers="mcps1.2.3.1.1 "><p id="p1232422184216"><a name="p1232422184216"></a><a name="p1232422184216"></a>AppAccountInfo</p>
</td>
<td class="cellrowborder" valign="top" width="48.39%" headers="mcps1.2.3.1.2 "><p id="p1324821164215"><a name="p1324821164215"></a><a name="p1324821164215"></a>提供应用帐号信息，包括应用帐号名称，所属包名。</p>
</td>
</tr>
</tbody>
</table>

**表 3**  应用帐号模块方法说明

<a name="table6561120114219"></a>

<table><thead align="left"><tr id="row115642084211"><th class="cellrowborder" valign="top" width="51.67%" id="mcps1.2.3.1.1"><p id="p7565201424"><a name="p7565201424"></a><a name="p7565201424"></a>方法</p>
</th>
<th class="cellrowborder" valign="top" width="48.33%" id="mcps1.2.3.1.2"><p id="p0568204427"><a name="p0568204427"></a><a name="p0568204427"></a>描述</p>
</th>
</tr>
</thead>
<tbody><tr id="row456162064218"><td class="cellrowborder" valign="top" width="51.67%" headers="mcps1.2.3.1.1 "><p id="p8388718174317"><a name="p8388718174317"></a><a name="p8388718174317"></a>function createAppAccountManager(): AppAccountManager</p>
</td>
<td class="cellrowborder" valign="top" width="48.33%" headers="mcps1.2.3.1.2 "><p id="p5561920194211"><a name="p5561920194211"></a><a name="p5561920194211"></a>获取应用帐号单实例对象</p>
</td>
</tr>
</tbody>
</table>

**表 4**  AppAccountManager方法说明

<a name="table1738121244713"></a>

<table><thead align="left"><tr id="row4381111254710"><th class="cellrowborder" valign="top" width="64.72%" id="mcps1.2.3.1.1"><p id="p1738116127470"><a name="p1738116127470"></a><a name="p1738116127470"></a>方法</p>
</th>
<th class="cellrowborder" valign="top" width="35.28%" id="mcps1.2.3.1.2"><p id="p10381161224717"><a name="p10381161224717"></a><a name="p10381161224717"></a>描述</p>
</th>
</tr>
</thead>
<tbody><tr id="row18381121274715"><td class="cellrowborder" valign="top" width="64.72%" headers="mcps1.2.3.1.1 "><p id="p1671817233812"><a name="p1671817233812"></a><a name="p1671817233812"></a>addAccount(name: string, callback: AsyncCallback<void>): void;</p>
</td>
<td class="cellrowborder" valign="top" width="35.28%" headers="mcps1.2.3.1.2 "><p id="p63421233134612"><a name="p63421233134612"></a><a name="p63421233134612"></a>添加应用帐号</p>
</td>
</tr>
<tr id="row1938113125470"><td class="cellrowborder" valign="top" width="64.72%" headers="mcps1.2.3.1.1 "><p id="p73429332466"><a name="p73429332466"></a><a name="p73429332466"></a>deleteAccount(name: string, callback: AsyncCallback<void>): void;</p>
</td>
<td class="cellrowborder" valign="top" width="35.28%" headers="mcps1.2.3.1.2 "><p id="p7342133394620"><a name="p7342133394620"></a><a name="p7342133394620"></a>删除应用帐号</p>
</td>
</tr>
<tr id="row13811912164716"><td class="cellrowborder" valign="top" width="64.72%" headers="mcps1.2.3.1.1 "><p id="p186182593814"><a name="p186182593814"></a><a name="p186182593814"></a>enableAppAccess(name: string, bundleName: string, callback: AsyncCallback<void>): void;</p>
</td>
<td class="cellrowborder" valign="top" width="35.28%" headers="mcps1.2.3.1.2 "><p id="p1534263304617"><a name="p1534263304617"></a><a name="p1534263304617"></a>应用帐号信息访问授权</p>
</td>
</tr>
<tr id="row10382181218477"><td class="cellrowborder" valign="top" width="64.72%" headers="mcps1.2.3.1.1 "><p id="p686934433810"><a name="p686934433810"></a><a name="p686934433810"></a>disableAppAccess(name: string, bundleName: string, callback: AsyncCallback<void>): void;</p>
</td>
<td class="cellrowborder" valign="top" width="35.28%" headers="mcps1.2.3.1.2 "><p id="p0342193384611"><a name="p0342193384611"></a><a name="p0342193384611"></a>应用帐号信息访问取消授权</p>
</td>
</tr>
<tr id="row10382181218477"><td class="cellrowborder" valign="top" width="64.72%" headers="mcps1.2.3.1.1 "><p id="p686934433810"><a name="p686934433810"></a><a name="p686934433810"></a>checkAppAccountSyncEnable(name: string, callback: AsyncCallback<boolean>): void;</p>
</td>
<td class="cellrowborder" valign="top" width="35.28%" headers="mcps1.2.3.1.2 "><p id="p0342193384611"><a name="p0342193384611"></a><a name="p0342193384611"></a>检查应用帐号同步状态</p>
</td>
</tr>
<tr id="row10382181218477"><td class="cellrowborder" valign="top" width="64.72%" headers="mcps1.2.3.1.1 "><p id="p686934433810"><a name="p686934433810"></a><a name="p686934433810"></a>setAccountCredential(name: string, credentialType: string, credential: string,callback: AsyncCallback<void>): void;</p>
</td>
<td class="cellrowborder" valign="top" width="35.28%" headers="mcps1.2.3.1.2 "><p id="p0342193384611"><a name="p0342193384611"></a><a name="p0342193384611"></a>设置应用帐号认证信息</p>
</td>
</tr>
<tr id="row10382181218477"><td class="cellrowborder" valign="top" width="64.72%" headers="mcps1.2.3.1.1 "><p id="p686934433810"><a name="p686934433810"></a><a name="p686934433810"></a>setAccountExtraInfo(name: string, extraInfo: string, callback: AsyncCallback<void>): void;</p>
</td>
<td class="cellrowborder" valign="top" width="35.28%" headers="mcps1.2.3.1.2 "><p id="p0342193384611"><a name="p0342193384611"></a><a name="p0342193384611"></a>设置应用帐号附加信息</p>
</td>
</tr>
<tr id="row10382181218477"><td class="cellrowborder" valign="top" width="64.72%" headers="mcps1.2.3.1.1 "><p id="p686934433810"><a name="p686934433810"></a><a name="p686934433810"></a>setAppAccountSyncEnable(name: string, isEnable: boolean, callback: AsyncCallback<void>): void;</p>
</td>
<td class="cellrowborder" valign="top" width="35.28%" headers="mcps1.2.3.1.2 "><p id="p0342193384611"><a name="p0342193384611"></a><a name="p0342193384611"></a>设置应用帐号同步状态</p>
</td>
</tr>
<tr id="row10382181218477"><td class="cellrowborder" valign="top" width="64.72%" headers="mcps1.2.3.1.1 "><p id="p686934433810"><a name="p686934433810"></a><a name="p686934433810"></a>setAssociatedData(name: string, key: string, value: string, callback: AsyncCallback<void>): void;</p>
</td>
<td class="cellrowborder" valign="top" width="35.28%" headers="mcps1.2.3.1.2 "><p id="p0342193384611"><a name="p0342193384611"></a><a name="p0342193384611"></a>设置应用帐号关联数据</p>
</td>
</tr>
<tr id="row10382181218477"><td class="cellrowborder" valign="top" width="64.72%" headers="mcps1.2.3.1.1 "><p id="p686934433810"><a name="p686934433810"></a><a name="p686934433810"></a>getAllAccessibleAccounts(callback: AsyncCallback &#60;Array&#60; AppAccountInfo>>): void;</p>
</td>
<td class="cellrowborder" valign="top" width="35.28%" headers="mcps1.2.3.1.2 "><p id="p0342193384611"><a name="p0342193384611"></a><a name="p0342193384611"></a>查询授权过的应用帐号信息</p>
</td>
</tr>
<tr id="row10382181218477"><td class="cellrowborder" valign="top" width="64.72%" headers="mcps1.2.3.1.1 "><p id="p686934433810"><a name="p686934433810"></a><a name="p686934433810"></a>getAllAccounts(owner: string, callback: AsyncCallback&#60;Array&#60;AppAccountInfo>>): void;</p>
</td>
<td class="cellrowborder" valign="top" width="35.28%" headers="mcps1.2.3.1.2 "><p id="p0342193384611"><a name="p0342193384611"></a><a name="p0342193384611"></a>查询指定报名下应用帐号信息</p>
</td>
</tr>
<tr id="row10382181218477"><td class="cellrowborder" valign="top" width="64.72%" headers="mcps1.2.3.1.1 "><p id="p686934433810"><a name="p686934433810"></a><a name="p686934433810"></a>getAccountCredential(name: string, credentialType: string, callback: AsyncCallback<string>): void;</p>
</td>
<td class="cellrowborder" valign="top" width="35.28%" headers="mcps1.2.3.1.2 "><p id="p0342193384611"><a name="p0342193384611"></a><a name="p0342193384611"></a>查询应用帐号认证信息</p>
</td>
</tr>
<tr id="row10382181218477"><td class="cellrowborder" valign="top" width="64.72%" headers="mcps1.2.3.1.1 "><p id="p686934433810"><a name="p686934433810"></a><a name="p686934433810"></a>getAccountExtraInfo(name: string, callback: AsyncCallback<string>): void;</p>
</td>
<td class="cellrowborder" valign="top" width="35.28%" headers="mcps1.2.3.1.2 "><p id="p0342193384611"><a name="p0342193384611"></a><a name="p0342193384611"></a>查询应用帐号附加信息</p>
</td>
</tr>
<tr id="row10382181218477"><td class="cellrowborder" valign="top" width="64.72%" headers="mcps1.2.3.1.1 "><p id="p686934433810"><a name="p686934433810"></a><a name="p686934433810"></a>getAssociatedData(name: string, key: string, callback: AsyncCallback<string>): void;</p>
</td>
<td class="cellrowborder" valign="top" width="35.28%" headers="mcps1.2.3.1.2 "><p id="p0342193384611"><a name="p0342193384611"></a><a name="p0342193384611"></a>查询应用帐号关联信息</p>
</td>
</tr>
<tr id="row10382181218477"><td class="cellrowborder" valign="top" width="64.72%" headers="mcps1.2.3.1.1 "><p id="p686934433810"><a name="p686934433810"></a><a name="p686934433810"></a>on(type: 'change', owners: Array<string>, callback: Callback&#60;Array&#60;AppAccountInfo>>): void;</p>
</td>
<td class="cellrowborder" valign="top" width="35.28%" headers="mcps1.2.3.1.2 "><p id="p0342193384611"><a name="p0342193384611"></a><a name="p0342193384611"></a>订阅应用帐号信息变化</p>
</td>
</tr>
<tr id="row10382181218477"><td class="cellrowborder" valign="top" width="64.72%" headers="mcps1.2.3.1.1 "><p id="p686934433810"><a name="p686934433810"></a><a name="p686934433810"></a>off(type: 'change', callback?: Callback&#60;void>): void;</p>
</td>
<td class="cellrowborder" valign="top" width="35.28%" headers="mcps1.2.3.1.2 "><p id="p0342193384611"><a name="p0342193384611"></a><a name="p0342193384611"></a>取消订阅应用帐号信息变化</p>
</td>
</tr>
</tbody>
</table>

## 相关仓<a name="section1371113476307"></a>

帐号子系统

**account\_os\_account**

