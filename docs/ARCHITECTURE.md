# ClaudeGuard 架构

依赖从 React 界面经类型化 Tauri IPC 到 guard-service；guard-core 只包含类型、纯规则、启动意图和监测状态机，guard-platform 承载系统副作用。

- `guard-core`：稳定 RuleId、Profile、策略版本、Report、单次启动意图与时效、通知证据、恢复状态和处理指引。显示文案不控制授权。
- `guard-platform`：受限 CommandRunner、Mac 代理/进程/路由只读采集、静态验签、固定 Cloudflare 探测、被动网络与生命周期事件、受限启动适配。Windows 返回 Unsupported。
- `guard-service`：完整检查顺序、配置冻结、Controller、锁和代际、独立时效维护、进度快照、共享告警 sink。
- `desktop`：持久化设置、人工确认、同用户单实例、通知/托盘/窗口、UI。前端不持有启动票据，导入报告不能授权。

## 权限与失败语义

新安装空配置不能执行检查或启动。坏配置不能静默回退。完整检查无论成功与否都必须具有可信配置；演示和仅观察进程由后端禁止真实启动，不因前端参数或配置修改解除。

只有明确手动操作才能建立一次性启动意图。完整报告与实际出口采样均须新鲜，最后提交时再次检查代际、时限、进程与应用身份；后台恢复、报告或 UI 不能生成意图。

检查器只接受固定系统可执行白名单，无通用 shell、URL、下载器或规则执行接口。配置中的代理程序路径只用于身份比对，不作为检测命令运行。客户端静态签名校验保留官方 team ID 与 Desktop bundle ID；这些是身份约束，不是个人偏好。

## 监测

本地与出口采样分开节流。独立心跳负责过期判定，不等待阻塞网络；迟到采样以代际丢弃。路径/休眠事件撤销旧许可。异常保持采样并去重，连续本地观测和两次实际出口采样跨度至少 30 秒后可确认观察恢复，仍需完整复检才能授权新启动。

## 验收

核心、服务和平台使用注入 Clock、Platform、CommandRunner、ApplicationRegistry 与 NotificationSink。默认离线/回环，无账号和真实客户端。界面使用 jsdom/Testing Library；原生 GUI 验收只能使用 demo 或用户授权的 observe-only。

能在 Windows 编译共享逻辑，不代表完成 Windows 系统代理、Authenticode、通知、路径事件、终端或 WSL 适配。未实现/未知能力必须保持不通过。
