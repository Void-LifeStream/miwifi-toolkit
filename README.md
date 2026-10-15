# miwifi-toolkit

两个零依赖的 Node 脚本，用来跟**小米路由器（MiWiFi）的 Web 后台**打交道。

其中一个能做的事，官方界面上**做不到**：**设置「弱信号剔除 / 漫游阈值」**。

> 实测环境：小米万兆路由器（固件内部代号 **RC01**），MiWiFi 稳定版 **1.1.56**。
> 其它型号/固件大概率同源可用，但**未经验证**。

---

## 为什么会有这个项目

### 发现 1：登录哈希不是页面源码里写的那个

想用脚本登录小米路由器后台，你会自然而然地打开登录页、读它的 JS，然后看到：

```js
var newEncryptMode = ''
var Encrypt = {
  key: 'a2ffa5c9be07488bbb04a3a47d3c5f6a',
  oldPwd: function (pwd) {
    if (newEncryptMode == 1) {
      return CryptoJS.SHA256(this.nonce + CryptoJS.SHA256(pwd + this.key).toString()).toString();
    } else {
      return CryptoJS.SHA1(this.nonce + CryptoJS.SHA1(pwd + this.key).toString()).toString();
    }
  }
}
```

`newEncryptMode` 是空字符串 → 按源码该走 **SHA1**。

**但运行时它会被置成 `'1'`，实际用的是 SHA256。**

用 SHA1 的后果是：所有参数看起来都对，服务端却只回一句 `{"code":401,"msg":"not auth"}`
——**它绝不会告诉你"你算法不对"**。作者在这一步上花了整整一晚。

> 教训：**别读纸面上的字，去问正在跑的那个对象。**
> （在浏览器 console 里直接调 `Encrypt.oldPwd('test')`，返回 64 个字符就说明是 SHA256。）

### 发现 2：漫游阈值的界面被官方删了，接口还在

小米一直没有「弱信号剔除」的设置项（[MIUI 论坛里有人正式提过需求](https://web.vip.miui.com/page/info/mio/mio/detail?postId=5001678)，
[V2EX](https://cn.v2ex.com/t/1107219) 上也一直有人问）。

实际上固件里**有**这套功能，只是**界面被移除、代码还在**：

- 前端仍保留两个隐藏表单 `roam24` / `roam50` 及其提交函数 `roamSubmitHandler`；
- 它向 `/api/xqnetwork/set_wifi` 提交 **恰好四个字段**：
  `wifiIndex`、`weakenable`、`weakthreshold`、`kickthreshold`；
- 固件自己的校验文案给出了合法区间：
  - `weakthreshold`：**-95 ~ -65**（dBm）
  - `kickthreshold`：**-100 ~ -70**（dBm）
- 那几个表单的 HTML 模板已被删除，所以**界面上永远点不到** —— 但**接口照收**。

实测写入返回 `{"code":0}`，读回确认生效；且**SSID / 密码 / 信道 / 带宽 / 加密全部未受影响**
（请求会逐字段照抄当前值，只额外附加三个阈值参数）。

---

## 用法

### 准备密码文件

```
~/.miwifi-password        # 单行：PASSWORD=你的路由器管理密码
```

用环境变量可以改路径/主机：

| 变量 | 默认值 | 说明 |
|---|---|---|
| `MIWIFI_HOST` | `192.168.1.1` | 路由器地址 |
| `MIWIFI_SECRET` | `~/.miwifi-password` | 密码文件 |
| `MIWIFI_STATE` | `~/.miwifi-session.json` | 会话缓存（stok）|
| `MIWIFI_DEVID` | 自动探测本机 MAC | nonce 里的设备标识 |
| `MIWIFI_SHOW_SECRETS` | 不设置 | 设为 `1` 才不脱敏输出 |
| `MIWIFI_DEBUG` | 不设置 | 设为 `1` 打印 HTTP 调试信息 |

### 通用 API 客户端

```bash
node miwifi.cjs login                        # 验证登录
node miwifi.cjs GET  /api/misystem/devicelist      # 设备列表
node miwifi.cjs GET  /api/xqnetwork/wifi_detail_all # 各射频详情
node miwifi.cjs POST /api/xqnetwork/set_wifi wifiIndex=1 bandwidth=20
node miwifi.cjs logout                       # 清掉会话缓存
```

> 路由器**不允许短时间内连续登录**（第二次会回 `1582 Invalid nonce`），
> 所以脚本会缓存 `stok` 复用；会话失效时自动重登一次。

### 漫游阈值

```bash
node miwifi-roam.cjs show                        # 看三个频段的当前值
node miwifi-roam.cjs backup                      # 备份完整 Wi-Fi 配置（含密码，注意保管）
node miwifi-roam.cjs set 1 1 -75 -85             # 2.4GHz 开启，弱信号 -75 / 踢除 -85
node miwifi-roam.cjs restore miwifi-wifi-backup-xxx.json
```

---

## 已知边界（很重要）

1. **只支持 2.4GHz（`wifiIndex=1`）和 5GHz（`wifiIndex=2`）。**
   `wifiIndex=3`（5G-Game / `wl0`）**会返回 `{"code":0}` 但值不变** —— 固件压根没给它做表单。
   而在多数小米 Mesh 里，**子节点跟随的正是 5G-Game** —— 也就是说，**覆盖全屋的那条射频恰好是调不了的那条**。
2. **每次写入会让该频段重启约 30 秒**（固件自己的提示：「设置成功正在重启，需要30秒请等待」）。
   请挑没人在用网的时候做。
3. **两个阈值的分工尚未完全确认。** 从取值范围推断：`weakthreshold`（-95~-65）更像是"弱信号判定"，
   `kickthreshold`（-100~-70）更像是"踢下线"。**这一条是推断，不是实测结论** —— 请自己观察再定值。
4. 社区常用的经验值是 **-75**（[恩山的固件剔除脚本](https://www.right.com.cn/forum/thread-8290654-1-1.html)用的就是它，
   [这份漫游排查指南](https://bbs.csdn.net/weixin_30983353/article/details/100435144)推荐 -70 ~ -75）。
5. 改完**不等于**就变好。阈值设得太激进，会让设备（尤其是扫地机、摄像头这类低速 2.4G 设备）**反复掉线重连**。

---

## 免责声明

这是对**你自己家里的设备**做未公开接口的写操作。写错可能需要恢复出厂设置。
请**先备份**、**一次只改一个频段**、**改完立刻读回验证**。
作者只在自己的一台路由器上验证过，不保证适用于你的型号。MIT License，不提供任何担保。
