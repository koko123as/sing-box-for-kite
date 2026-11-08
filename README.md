# KiteBox (sing-box-for-kite)

Experimental Android client for sing-box, the universal proxy platform,
with the Xray and mihomo cores built in. Package `io.kitebox.app`; it
installs beside the upstream app (`io.nekohasekai.sfa`).

This fork (https://github.com/koko123as/sing-box-for-kite) adds the Xray and
mihomo cores and user routing rules. It is based on
[SagerNet/sing-box-for-android](https://github.com/SagerNet/sing-box-for-android);
issues are disabled on this fork, please report app issues upstream.

## Documentation

sing-box: https://sing-box.sagernet.org/

## 多内核与路由规则（中文说明）

### 三个内核

`libbox.aar` 同时编入 sing-box（`CORE_VERSION`）、Xray（`XRAY_VERSION`，经 libXray 转换分享链接）和
mihomo（`MIHOMO_VERSION`，按 ClashMetaForAndroid 的方式以 `cmfa` 标签嵌入），版本固定在
[version.properties](version.properties)。同一时间只运行一个内核，每个配置都直接在自己的内核上运行，不做内核之间的转换或套娃。

- **添加/编辑配置时选择内核**：自动（按内容识别：sing-box JSON、Xray JSON、Clash/mihomo YAML）、sing-box、Xray、mihomo。
  分享链接（vmess/vless/trojan/ss/hysteria2/tuic/…）或 Base64 节点列表会在保存时转换为所选内核的完整配置；
  订阅按配置的内核发送 User-Agent（mihomo 为 `clash.meta`，Xray 为 `v2rayN/<版本>`）。
- **客户端功能**：分组/切换节点、URL 测速、连接列表、流量、日志、Clash 模式等界面经 libbox 的同一个 gRPC 接口读取当前内核，三种内核通用。
- **默认日志等级**：配置未设置时，sing-box 以 `warn`、Xray 以 `warning`、mihomo 以 `warning` 运行；日志页默认显示 warn 及以上。
- **地理数据**：Xray 的 `geoip:`/`geosite:` 与 mihomo 的 GEOIP/GEOSITE 共用 `<工作目录>/cores/mihomo` 下的文件；
  mihomo 会自行下载缺失文件，Xray 配置用到时在启动前自动下载，也可在「设置 → 路由规则 → 更新地理数据」手动更新。

### 订阅、导入与内核开关

- **订阅返回多个配置的 JSON 数组**：创建和更新订阅时每个配置拆成独立的配置（名称为「订阅名 - remarks」），更新时按 remarks（无则按序号）对应回原配置，订阅新增的配置会自动添加。错误信息会写明是哪个内核报的错（如 `mihomo: ...`）。
- **导入文件 / QRS / 二维码**时可选择内核（默认自动识别）。
- **设置 → 内核**：sing-box、mihomo、Xray 各占一行，显示版本并可单独关闭（至少保留一个）；关闭的内核不会出现在内核选择里，其配置也不会启动。

### 发布与更新

检查更新只读取本仓库的 GitHub Releases（不再需要版本元数据文件，也不提供 F-Droid 来源）。推送与 `version.properties`
中 `VERSION_NAME` 一致的标签 `v<VERSION_NAME>` 会触发 `.github/workflows/release.yml`，构建 arm64-v8a 的
`KiteBox-<版本>-arm64-v8a.apk` 并发布。要让每次发布的 APK 签名一致（可覆盖安装），请在仓库 Secrets 中设置
`LOCAL_PROPERTIES`（base64 编码的 `KEYSTORE_PASS=`/`ALIAS_NAME=`/`ALIAS_PASS=`）以及可选的 `RELEASE_KEYSTORE_BASE64`
（自己的 keystore，base64）；未设置时以临时 debug 密钥签名。

### 路由规则

「设置 → 路由规则」参照 v2rayNG 的路由设置：可添加、编辑、删除、排序、启用/停用规则。每条规则包含备注、域名
（无前缀为该域名及子域名，支持 `full:`、`domain:`、`keyword:`、`regexp:`、`geosite:`）、IP/CIDR（支持 `geoip:`）、
应用（从已安装应用中选择）、可选端口与网络，目标为当前配置中的节点/策略组、直连或阻止。

- 匹配语义（三个内核一致）：（任一域名 或 任一 IP）且（任一应用）且 端口 且 网络。
- 启动和重载时按当前内核翻译，并放在配置自带规则之前：sing-box 写入 `route.rules`（位于开头的 sniff/hijack-dns 等动作之后，
  `geosite:`/`geoip:` 使用 SagerNet 远程规则集）；Xray 写入 `routing.rules`（域名与 IP 拆为两条，目标可为 outbound 或 balancer）；
  mihomo 写入 `rules`（多条件时使用 AND/OR 逻辑规则，应用使用 `PROCESS-NAME`）。
- 目标节点/策略组不在当前配置中的规则会被跳过，并在日志中记一条警告，不会导致启动失败。
- 规则修改后，服务运行时会提示重载。

### 已知限制

- Xray 与 mihomo 只支持 VPN 模式（使用 VpnService 的 TUN），没有纯代理模式。
- 应用规则只在 VPN 模式下生效：sing-box 用自身的 `package_name`；Xray 与 mihomo 通过系统的连接归属查询
  （`ConnectivityManager.getConnectionOwnerUid`，与 sing-box 相同的平台接口）取得包名。Xray 的规则含应用时，
  TUN 入站的嗅探改为 `routeOnly`（嗅探出的域名只用于路由，转发仍用原 IP）。共享 UID 的应用按第一个包名匹配。
- sing-box 的 `geosite:`/`geoip:` 规则集在启动时联网下载（无缓存时下载失败可能使 sing-box 启动失败）。
- mihomo 规则中的名称不能包含逗号或括号；这样的目标会被跳过并记警告。
- libbox 只编译 arm64-v8a；Android 5（otherLegacy）版本不再构建。
- 以上功能尚未在真机上验证。

## License

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
```

Under the license, that forks of the app are not allowed to be listed on F-Droid or other app stores
under the original name.
