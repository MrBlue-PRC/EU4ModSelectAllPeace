# EU4 SelectAllPeace — 一键全选省份（和谈界面快捷工具）

One-click "select all provinces" shortcut for the Europa Universalis IV peace deal interface.

在和谈界面**一键全选对方全部省份**：按一下热键 `T`（或点击条约列表里的
"吞并全部省份(全选)"），即可把当前页签（索取/给予）里所有能通过规则校验的
省份条目自动逐个加入——与手动逐个点击**完全等价**。

## 原理 / How it works

**快捷操作而非作弊。** 所有选中都走游戏原生"加入条款"管线
（CanAdd 校验 → Add → 刷新）：战争分数、外交点、侵略扩张、阶级领土变化
与手动逐个点选完全一致，联机同样安全。

本仓库分两部分：

| 部分 | 位置 | 说明 |
|---|---|---|
| 工坊 Mod | `SelectAllPeace/` | 零费用空效果的快捷条约 + 双字节中文本地化，Steam 创意工坊订阅 |
| 插件 DLL | `plugin/` | 热键与自动化逻辑（MIT 源码，成品见 `plugin/release/`） |

Mod 部分单独使用无副作用（条款可见、零费用、零效果）；
全选功能需要 DLL 插件，依赖 [EU4dll](https://github.com/matanki-saito/EU4dll)（multibyte patch）加载器生态。

## 安装 / Install

1. **Mod**：Steam 创意工坊订阅本 Mod（或把 `SelectAllPeace/` 文件夹与
   `SelectAllPeace.mod` 一起放入 `Documents/Paradox Interactive/Europa Universalis IV/mod/`，
   启动器勾选）。
2. **插件**：解压 `plugin/release/selectall_v1.7.zip`，把 `selectall.dll`
   放入游戏目录的 `plugins/` 文件夹。
   - 前置：游戏目录需有 [EU4dll](https://github.com/matanki-saito/EU4dll) 的
     `version.dll` 加载器（玩中文/日文 Mod 的玩家通常已装好）。
   - 没有 `plugins/` 目录就新建一个。
3. 开一局游戏验证：和谈界面按 `T`。

## 使用 / Usage

- 和谈界面按 **`T`**：全选当前页签所有可加入的省份条目（索取/给予页签自动识别）
- 点击条约 **"吞并全部省份(全选)"**：与按 T 等价
- 手动取消勾选任意省份后，快捷条约会自动反选（避免"空条款"残留）

## 兼容性 / Compatibility

- eu4.exe **1.37.0 / 1.37.5**（Steam 64 位版），特征码运行时定位、无硬编码偏移
- 与 EU4dll 双字节补丁及其他 `plugins/` 内插件共存
- 联机：仅调用游戏原生函数、不改游戏数据，理论无 desync，但进程修改风险自负
- 铁人成就：属第三方进程修改，合规性自负

## 构建 / Build

```bat
cd plugin
build.bat        :: 需 VS2022（vcvars64），产物 selectall.dll
```

## 维护 / Maintenance

游戏版本更新后的适配流程、逆向结论与对象布局、故障排查见
[docs/交接文档.md](docs/交接文档.md)；
`tools/scan_patterns.py` 可对新版 eu4.exe 一键验证特征码/布局/IAT。

## 免责 / Disclaimer

本项目为非官方工具，与 Paradox Interactive 无关。二进制内存补丁属 EULA 灰色地带，
按 MIT 协议开源，使用风险自负。

## 致谢 / Credits

- [EU4dll](https://github.com/matanki-saito/EU4dll)（MIT）—— 加载器与双字节方案上游
- MakeQinGreatAgain / USSR mod —— 双字节本地化转码器 `mqga_convert.py`
- Ghidra / capstone —— 逆向工具链

## License

[MIT](LICENSE) © 2026 MrBlue-PRC
