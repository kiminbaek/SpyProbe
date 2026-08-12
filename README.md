# SpyProbe

**通用逆向探测 / 抓包工作台**（LSPosed / libxposed 模块）

SpyProbe 是一个运行在目标 App 进程内的全面探测工具，专为**逆向分析、反编译辅助、安全研究**设计。在 LSPosed 中勾选作用域后，即可对目标 App 进行：

## 核心能力

### 网络抓包
- ✅ **SSL 证书锁定绕过（全量覆盖）**：网络配置 pinning（NetworkSecurityTrustManager）、Conscrypt 底层校验（TrustManagerImpl）、OkHttp 主机名校验、WebView SSL 错误自动放行、Cronet pinning、老版 okhttp / xutils / httpclient / Platform
- ✅ **BoringSSL 底层校验绕过（Native）**：`SSL_CTX_set_custom_verify` / `set_verify` / `SSL_set_verify` / `cert_verify_callback` / `get_verify_result` 五接口全部放行，任何自定义证书校验一律通过
- ✅ **SSL KeyLog 抓取**：记录每次 TLS 握手的 `CLIENT_RANDOM` + master secret，配合 Wireshark 直接还原 HTTPS 明文
- ✅ **OkHttp（同步/异步）/ HttpURLConnection 请求响应记录** + DNS 解析 + Socket 连接 + QUIC/HTTP3（万能 connect 连接点）
- ✅ **TLS 明文抓包**：ConscryptEngine wrap/unwrap，HTTPS 明文头直接可见
- ✅ **Native 层抓包**：xhook PLT/GOT hook——libc 五函数（send/recv/read/write/connect）+ 4 个 SSL 库（libssl/conscrypt/ttboringssl/libflutter）TLS 解密明文 + HTTP/2 帧解析，专治 Flutter/Unity 纯 native 网络栈（Java hook 盲区）
- ✅ **URL 构造捕捉**：hook URL 构造 / `Uri.parse` / `URI.create` / `HttpUrl.parse`，运行期拼的所有地址一目了然（找接口/CDN 域名）
- ✅ **WebView 调试**：自动开启 WebContentsDebugging，Chrome DevTools 可调试 H5 页面
- ✅ **pcap 导出（v1.39+）**：native 层 TLS 明文写入标准 pcap 文件，Wireshark 直接打开看 HTTPS 明文（含视频 TS / 流媒体内容）；导出范围可选「全部（当前+历史归档）/ 仅当前会话」，支持一键清空
- ✅ **请求重放（v1.40）**：OkHttp 请求缓存（环形 50 条），一键重放历史请求，GET/无 body 请求 100% 可靠
- ✅ **混淆 OkHttp 自动定位（v1.40）**：`OkHttpClient.newCall` 入口 hook + 返回类型特征动态 hook + DexKit 类名兜底，全混淆 App 也能抓
- ✅ **JSON/Hex 双视图（v1.39）**：日志详情支持 JSON 格式化 / Hex 切换，加密数据直接看字节

### 加密与证书
- ✅ **加密算法记录**：hook `Cipher.getInstance/init/doFinal`，记录算法、密钥、IV、明文/密文（按实例跟踪完整上下文）
- ✅ **密钥材料追踪**：SecretKeySpec / DESKeySpec / Mac（HMAC）/ SecureRandom 种子记录
- ✅ **双向认证证书导出（mTLS）**：记录目标 App 使用 KeyStore 客户端证书的 alias、算法、主题、有效期、SHA-256 指纹（不导出私钥）
- ✅ **SSL pinning 定位（v1.39）**：7 类证书固定触发点全标记（network_security_config pin-set / okhttp CertificatePinner / Conscrypt / X509TrustManagerExtensions / WebView…），一看日志就知道 App 用的哪种锁定
- ✅ **native SSL 调用栈（v1.39）**：SSL_read/write 回调自动记录调用栈，定位 native 层 TLS 使用点

### 函数与逻辑
- ✅ **函数探测**：反射枚举类方法/字段（含**静态字段当前值**、**native 方法标记**），动态 hook/unhook 任意方法，打印参数/返回值/调用栈/实例字段快照
- ✅ **返回值劫持**：对已 hook 方法下发强制返回值（`true`/`false`/数字/文本/`null`），不执行原方法——去检测、去付费的万能钥匙
- ✅ **通用 Hook 规则引擎 7 模式**：记录参数 / 记录返回 / 记录两者（纯观测）+ 返回值（isVip()→true）/ 参数值（vipLevel→3）/ 拦截执行（绕过支付校验）/ 静态变量（UserInfo.IS_VIP=true）——规则按类名.方法名配置并持久化
- ✅ **DexKit 反编译**：一键导出全部 dex（jadx 打开）+ 字符串反查引用方法 + **类名模糊搜索自动生成 hook 清单**（一键复制到手动 Hook 规则）

### 应用行为
- ✅ **App 自身日志拦截**：`Log.d/i/e/w/v` 全量截获，多数 App 上线未删日志，直接泄露逻辑
- ✅ **SQLite 记录**：hook `SQLiteDatabase` 增删改查，拼可读 SQL
- ✅ **类加载记录**：hook `ClassLoader.loadClass`，关键字过滤定位核心逻辑类
- ✅ **SharedPreferences key 记录**：看 App 本地存了什么状态
- ✅ **Activity/Intent 流程**：生命周期 + 跳转目标，理清页面流
- ✅ **JSON/Gson 序列化**：直接看接口数据结构
- ✅ **环境检测探测**：记录 App 检测行为（root 路径/命令/属性/vpn/传感器/防截屏/剪贴板/设备指纹），反编译知道要绕过什么

### 反检测
- ✅ **反检测 hook 集**：隐藏 root（File.exists/Runtime.exec/SystemProperties）与 Xposed（loadClass/StackTrace/DexPathList/Modifier），与 EnvProbe 探测互为镜像
- ✅ **反检测增强**：File.listFiles / canRead / canExecute 过滤 root 特征文件、`Debug.isDebuggerConnected` 返回 false、magisk / KernelSU / SuperSU 检测路径全集过滤
- ✅ **隐藏应用列表（v1.44）**：hook `getInstalledPackages` / `getInstalledApplications` / `queryIntentActivities`，对 spyprobe / LSPosed / Magisk 等返回"未安装"（系统包永不隐藏）

### 工程健壮性
- ✅ **Hook 失败隔离**：所有探测 hook 统一包裹，单个 hook 异常不拖垮目标进程，失败留痕
- ✅ **惰性 Hook**：关闭的探测项目标进程零 hook，按配置按需加载
- ✅ **日志架构（自 1.32 起）**：日志/配置全部存 SpyProbe（`files/spyprobe_logs/` + `spyprobe_cfg.json`），目标进程日志实时推回主进程落盘，历史日志本地读取，免 root、免目标 App 在线
- ✅ **历史日志按会话记录**：目标进程每次启动 = 独立会话文件，卡片式浏览 + 勾选批量分享
- ✅ **日志容量可配置**：环形缓冲上限 100-20000 条可调（默认 4096）
- ✅ **内置更新系统**：GitHub API 多镜像回退 + SHA-256/versionCode 校验 + root 静默安装（回退系统安装器）
- ✅ **Token 鉴权**：目标进程日志推送带 48 位随机 token，主进程校验，防止其他 App 伪造推送
- ✅ **9901 控制面鉴权（v1.47）**：目标进程 hook/劫持/导出接口同样带 token 校验，本机任意 App 无法篡改目标进程探测状态
- ✅ **会话条数元数据（v1.47）**：写线程维护 sessions.json，历史页免全量扫描，大日志/多会话打开秒开

## 架构

```
SpyProbe 主进程（控制台 App，数据面）
├─ SpyHomeServer   —— 本地 HTTP server（127.0.0.1:9900）
│    ├─ 接收目标进程日志推送（token 鉴权）
│    ├─ 下发权威配置（spyprobe_cfg.json）
│    └─ /api/status /api/logs /api/classfind 查询路由
├─ LogPersister    —— 日志落盘 files/spyprobe_logs/（按会话）
├─ HomeLogReader   —— 历史会话读取（本地，免 root）
└─ Compose UI      —— 抓包 / 探测 / Hook / 日志 / 设置

目标 App 进程内（XposedModule，控制面）
├─ NetProbe        —— SSL 绕过（Java 12 点 + BoringSSL 5 接口）/ OkHttp / HttpURLConnection / DNS / Socket / WebView / TLS明文 / connect / Cronet
├─ NativeProbe     —— native 层抓包：xhook libc/SSL/HTTP2 + KeyLog + JNI 桥接 LogStore
├─ KeystoreProbe   —— mTLS 客户端证书 dump（v1.38）
├─ UrlProbe        —— URL/Uri/URI/HttpUrl 构造捕捉
├─ CryptoProbe     —— Cipher 算法/密钥/IV 记录 + SecretKeySpec/DESKeySpec/Mac/SecureRandom
├─ LogCatProbe     —— App 自身 Log 拦截
├─ MethodProbe     —— 函数枚举 / 动态 hook / 返回值劫持
├─ SQLiteProbe     —— SQLite 增删改查记录
├─ ClassLoadProbe  —— 类加载记录
├─ PrefsProbe      —— SharedPreferences key 记录
├─ ActivityProbe   —— Activity 生命周期 + Intent
├─ JsonProbe       —— JSONObject/Gson 序列化
├─ DexKitProbe     —— DexKit 导出 dex + 字符串反查 + 类名搜索
├─ EnvProbe        —— 环境检测探测：root/vpn/传感器/防截屏/设备指纹
├─ AntiDetectProbe —— 反检测 hook 集
├─ StackUtil       —— 调用栈工具
├─ HookSafe        —— hook 统一失败隔离
└─ LogStore        —— 环形缓冲日志 + 批量推送主进程
```

> **v1.32 架构修正**：日志/配置不再写入目标 App 目录，全部归 SpyProbe；目标进程只做探测与推送，历史日志由主进程本地读取。

## 使用

1. 安装最新版 `SpyProbe-v1.47.0.apk`（Release 页面下载）
2. 在 LSPosed 中勾选目标 App 作用域
3. 重启目标 App
4. 打开 SpyProbe 控制台，自动连接主进程服务
5. 按需开启探测开关（设置页），操作已 Hook 列表设置劫持

## 本地 HTTP 路由

### 主进程 SpyHomeServer（127.0.0.1:9900）

| 路由 | 方法 | 说明 |
|:-----|:-----|:-----|
| `/api/ping` | GET | 心跳 + 运行状态 |
| `/api/config` | GET/POST | 读写全部探测开关（权威配置） |
| `/api/status` | GET | 运行时长 / 日志条数（v1.38） |
| `/api/logs?since=N` | GET | 增量拉日志（v1.38） |
| `/api/export` | GET | 导出全量日志（v1.41 主进程通道） |
| `/api/classfind?name=` | GET | DexKit 类名模糊搜索 → 方法清单（v1.38） |
| `/api/token` | GET | 主进程 token 自举（v1.44.1，目标进程拉取鉴权用） |
| `/api/push_logs` | POST | 目标进程日志推送（需 X-Spy-Token 鉴权） |
| `/api/pcap_chunk` | POST | 目标进程 pcap 明文推送（需 X-Spy-Token 鉴权，v1.41） |

### 目标进程 SpyServer（127.0.0.1:9901，多进程自动偏移）

| 路由 | 方法 | 说明 |
|:-----|:-----|:-----|
| `/api/ping` | GET | 心跳 + 包名 + 实际端口 + 日志数 + 类数 + App 版本 |
| `/api/logs?since=N` | GET | 增量拉日志 |
| `/api/logs/all` | GET | 全量日志（v1.41 目标进程兜底） |
| `/api/export` | GET | 导出目标进程内存日志（v1.41 兜底） |
| `/api/debuglog` | GET | 目标进程调试日志（v1.30.2） |
| `/api/history/days` | GET | 历史日志日期列表（v1.33 目标进程兜底） |
| `/api/history?day=&max=` | GET | 读某天历史（v1.33 兜底） |
| `/api/history/clear?day=` | POST | 清空历史（day 空=全清） |
| `/api/scan` | POST | 枚举类方法/字段 |
| `/api/hook` | POST | 动态 hook 方法 |
| `/api/unhook` | POST | 卸载 hook |
| `/api/hooks` | GET | 当前 hook 列表 |
| `/api/hijack` | POST | 设置/取消返回值劫持 |
| `/api/hijacks` | GET | 当前劫持规则 |
| `/api/dexdump` | GET | 导出全部 dex |
| `/api/stringfind` | POST | 字符串反查引用方法 |
| `/api/classfind?name=` | GET | DexKit 类名模糊搜索 → 方法清单（v1.38） |
| `/api/dexclose` | POST | 释放 DexKit |
| `/api/config` | GET | 目标进程配置（v1.36） |
| `/api/classes` | GET | 类加载记录（v1.36） |
| `/api/flush_pcap` | POST | 立即 flush 目标进程 pcap 活跃会话（v1.41） |
| `/api/replay` | POST | 请求重放（v1.40，index 参数指定历史请求） |
| `/api/clear` | POST | 清空目标进程日志 |

## 版本历史

| 版本 | 说明 |
|:-----|:-----|
| **v1.47** | 修复 8 P1 + 22 P2：9901 控制面 token 鉴权 / 日志推送失败指数退避 / 会话条数元数据 sessions.json / native hook 只试一次防闪退 / 大 DATA 帧分段回调 / networkSecurityConfig 收紧 127.0.0.1 / FileProvider 单文件 / 目标端口防自推 |
| **v1.46** | 根治播放视频闪退 + pcap 0 数据（SSL_get_fd 解析方向错误，native resolve 只试一次）+ pcap 记录头字节序修复 + 2MB chunk 截断修复（MAX_BODY 1MB→4MB）+ 导出范围选择（全部/仅当前会话）+ 清空 pcap 按钮 |
| **v1.45** | pcap 链路修复：IPv4-mapped IPv6 全拒根治 + SSL_get_fd 延迟解析（dladdr/dlopen/ELF 符号表直读三连）+ 诊断日志 |
| **v1.44** | **隐藏应用列表**（HMA 思路）：hook getInstalledPackages/getInstalledApplications/queryIntentActivities 过滤 spyprobe/LSPosed/Magisk + push 401 根治闭环（token 自举+续期+失败重试不丢） |
| **v1.43** | UI 优化：抓包页整页可滚动 / 批量开关（全开/全关/恢复默认）/ Root 文案降级 / 新版本弹窗（完整更新日志 + 下载/忽略） |
| **v1.42** | 修复 15 项：addHook NPE / OkHttpReplay buffer / PcapWriter flush / pcap 流式合并 / TCP 校验和 / shareUri mimeType / 大块分段映射 |
| **v1.41** | **日志架构大修正**：实时日志/分享改走自己家 9900（目标 App 不在线也能看已推回日志）+ pcap 独立于 nativeCapture + 5s 周期 flush + 推送失败留痕 |
| **v1.40** | **OkHttp 混淆自动定位**（newCall 入口 + 特征动态 hook + DexKit 兜底）+ **请求重放**（环形 50 条，一键重放）+ 响应体重建（peekBody 不消费原流） |
| **v1.39** | **pcap 导出**（Wireshark 直接看 HTTPS 明文）+ **JSON/Hex 双视图** + native SSL 调用栈 + SSL pinning 定位 |
| **v1.38** | SSL 绕过增强：补齐 12 个证书校验绕过点（网络配置 pinning/Conscrypt/OkHttp 主机名/WebView/Cronet/xutils/httpclient/Platform）+ BoringSSL 五接口 verify 绕过 + SSL KeyLog（Wireshark 可还原明文）+ mTLS 客户端证书 dump（指纹不导出私钥）+ 加密追踪扩展（SecretKeySpec/DESKeySpec/Mac/SecureRandom）+ 反检测扩充（listFiles/isDebuggerConnected/ROOT_FILES 全集）+ WebView 调试开关 + DexKit 类名搜索 + 状态/日志查询路由 |
| **v1.37** | 内置更新系统（GitHub 多镜像 + SHA-256 校验 + root 静默安装）/ Hook 失败隔离（HookSafe 统一包裹）/ 惰性 Hook（按配置按需加载）/ R8 入口发布前自动校验 / 日志推送 token 鉴权 |
| **v1.36** | 修复 16 项：历史会话分组根治字典序陷阱 / 连接恢复 / Root 模式"本地优先"降级文案 / 代码清理与序列化收敛 |
| **v1.35** | 日志架构优化：推送改纯 Socket 根治递归爆炸 / 单行化 / URL 去重 / native hex 收敛 / 请求关联 ID / 分享格式优化 |
| **v1.34** | **shadowhook → xhook 换库**：根治 OnePlus Android 16 PAC 崩溃（inline hook 改写指令破坏 PAC 配对 → 32 tombstone 空指针；xhook 只改 GOT 表项，PAC 免疫） |
| **v1.33** | 历史日志按会话记录（目标进程每次启动 = 新会话文件）+ 卡片式浏览 + 勾选批量分享 |
| **v1.32** | **架构修正：日志/配置全部搬回 SpyProbe 自己家**——新增主进程数据面 SpyHomeServer :9900，目标进程日志实时推回，历史日志本地读取（免 root 免目标在线） |
| v1.31 | 工作模式（Root/普通）/ 修复 native 开关语义 / 配置持久化修复 |
| v1.30 | 日志导出 txt 分享 / 全链路调试日志埋点 / 修复 NetworkOnMainThreadException |
| v1.29 | 调试日志不落盘修复 |
| v1.28 | 修复 11 P1 + 8 P2 |
| v1.26 | 导出失败 P0 ×3 修复 |
| v1.25 | 修复 20 项 |
| v1.10-1.24 | Native 层抓包（shadowhook libc/SSL/HTTP2）/ DexKit 导出 + 字符串反查 / 环境检测探测 / TLS 明文 / 万能连接点 / 通用 Hook 规则引擎 7 模式 / 反检测 hook 集 / 返回值劫持 / SQLite 记录 / URL/Crypto/Log/Activity/JSON 探测 / Compose UI 重构 / Hook 失败隔离 |
| v1.0-1.9 | 初版 + 多轮审查增强（DNS/Socket/类加载/字段快照/端口自动发现） |

## 版权声明

**本软件受「SpyProbe 自定义许可证」保护（详见 [LICENSE](LICENSE)）。**

- ⛔ **不可商用**：禁止任何形式的商业用途（销售、出租、用于商业产品/服务、以盈利为目的的托管分发等）。
- ⚠️ **二次开发必须注明原作者版权**：衍生作品须在显著位置注明"基于 SpyProbe 二次开发，原作者 kiminbaek"，且衍生作品同样适用本许可证。

**免责声明**：本软件仅供安全研究与逆向分析学习使用，请勿用于任何非法用途；因非法使用产生的一切责任由使用者自行承担。
