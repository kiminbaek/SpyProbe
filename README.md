# SpyProbe

**通用逆向探测 / 抓包工作台**（LSPosed / libxposed 模块）

SpyProbe 是一个运行在目标 App 进程内的全面探测工具，专为**逆向分析、反编译辅助、安全研究**设计。在 LSPosed 中勾选作用域后，即可对目标 App 进行：

- ✅ **全量网络抓包**：SSL 证书锁定绕过 + OkHttp（同步/异步）/ HttpURLConnection 请求响应记录 + DNS 解析 + Socket 连接
- ✅ **URL 构造捕捉**：hook URL 构造 / `Uri.parse` / `URI.create` / `HttpUrl.parse`，运行期拼的所有地址一目了然（找接口/CDN 域名）
- ✅ **App 自身日志拦截**：`Log.d/i/e/w/v` 全量截获，多数 App 上线未删日志，直接泄露逻辑
- ✅ **加密算法记录**：hook `Cipher.getInstance/init/doFinal`，记录算法、密钥、IV、明文/密文
- ✅ **函数探测**：反射枚举类方法/字段（含**静态字段当前值**、**native 方法标记**），动态 hook/unhook 任意方法，打印参数/返回值/调用栈/实例字段快照
- ✅ **返回值劫持**：对已 hook 方法下发强制返回值（`true`/`false`/数字/文本/`null`），不执行原方法——去检测、去付费的万能钥匙
- ✅ **SQLite 记录**：hook `SQLiteDatabase` 增删改查，拼可读 SQL（`INSERT/UPDATE/DELETE/SELECT`）
- ✅ **类加载记录**：hook `ClassLoader.loadClass`，关键字过滤定位核心逻辑类
- ✅ **SharedPreferences key 记录**：看 App 本地存了什么状态
- ✅ **Activity/Intent 流程**：生命周期 + 跳转目标，理清页面流
- ✅ **JSON/Gson 序列化**：直接看接口数据结构
- ✅ **WebView.loadUrl 记录**

## 架构

```
目标 App 进程内（XposedModule）
├─ NetProbe      —— SSL 绕过 / OkHttp / HttpURLConnection / DNS / Socket / WebView
├─ UrlProbe      —— URL/Uri/URI/HttpUrl 构造捕捉（v1.5）
├─ CryptoProbe   —— Cipher 算法/密钥/IV 记录（v1.5）
├─ LogCatProbe   —— App 自身 Log 拦截（v1.5）
├─ MethodProbe   —— 函数枚举 / 动态 hook / 返回值劫持
├─ SQLiteProbe   —— SQLite 增删改查记录（v1.4）
├─ ClassLoadProbe—— 类加载记录
├─ PrefsProbe    —— SharedPreferences key 记录
├─ ActivityProbe —— Activity 生命周期 + Intent（v1.5）
├─ JsonProbe     —— JSONObject/Gson 序列化（v1.5）
├─ LogStore      —— 环形缓冲日志（4096 条）
└─ SpyServer     —— 本地 HTTP server（127.0.0.1:9901-9910，多进程自动偏移）

控制台 App（MainActivity）
└─ 通过 HTTP 拉日志 / 下发配置 / 探测函数 / 管理 hook / 设置劫持 / 导出
```

## 使用

1. 安装 `SpyProbe-v1.5.apk`
2. 在 LSPosed 中勾选目标 App 作用域
3. 重启目标 App
4. 打开 SpyProbe 控制台，自动发现端口（9901-9910）并连接
5. 按需开启探测开关（设置对话框），操作已 Hook 列表设置劫持

## 本地 HTTP 路由

| 路由 | 方法 | 说明 |
|:-----|:-----|:-----|
| `/api/ping` | GET | 心跳 + 包名 + 实际端口 + 日志数 + 类数 + App 版本 |
| `/api/logs?since=N` | GET | 增量拉日志 |
| `/api/logs/all` `/api/export` | GET | 全量日志 |
| `/api/config` | GET/POST | 读写全部探测开关 |
| `/api/classes?filter=` | GET | 类加载列表 |
| `/api/scan` | POST | 枚举类方法/字段 |
| `/api/hook` | POST | 动态 hook 方法 |
| `/api/unhook` | POST | 卸载 hook |
| `/api/hooks` | GET | 当前 hook 列表 |
| `/api/hijack` | POST | 设置/取消返回值劫持 |
| `/api/hijacks` | GET | 当前劫持规则 |
| `/api/clear` | POST | 清空日志 |

## 版本历史

| 版本 | 说明 |
|:-----|:-----|
| v1.5 | 全面审核 + 反编译难点增强：URL 捕捉 / Crypto / Log 拦截 / Activity / JSON 5 大新 Probe + isNative 标记 |
| v1.4 | 增强模式：返回值劫持 + SQLite 记录 |
| v1.3 | 第三轮审核：重复 hook 防重、多进程端口自动发现 |
| v1.2 | 二轮审核：DNS/Socket 抓包、类加载记录、字段值快照 |
| v1.1 | 首轮全面审查优化 |
| v1.0 | 初版 |

## 版权声明

**本软件受「SpyProbe 自定义许可证」保护（详见 [LICENSE](LICENSE)）。**

- ⛔ **不可商用**：禁止任何形式的商业用途（销售、出租、用于商业产品/服务、以盈利为目的的托管分发等）。
- ⚠️ **二次开发必须注明原作者版权**：衍生作品须在显著位置注明"基于 SpyProbe 二次开发，原作者 kiminbaek"，且衍生作品同样适用本许可证。

**免责声明**：本软件仅供安全研究与逆向分析学习使用，请勿用于任何非法用途；因非法使用产生的一切责任由使用者自行承担。
