# GitHub 成熟项目对照（2026-08-25）

开始编码前已检索 GitHub。结论是：没有找到可验证的、面向 CLIP STUDIO PAINT 的成熟专用 MCP。对本项目的通用控制目标，当前可验证路线是受限可见 Windows 界面、快捷键/Auto Actions 与文件交换；这不是对所有第三方或未来集成方式的排他断言。

| 项目 | 功能/技术栈 | 活跃情况 | 许可证 | 值得借鉴 | 本项目判断 |
|---|---|---|---|---|---|
| [CursorTouch/Windows-MCP](https://github.com/CursorTouch/Windows-MCP) | 通用 Windows MCP；Python、FastMCP、UIA、截图、输入 | v0.8.5；2026-08 仍更新 | MIT | 截图优先、等待、输入工具注解 | Beta、权限过宽、遥测且要求 Python >=3.14；不整包安装 |
| [microsoft/UFO](https://github.com/microsoft/UFO) | UIA+视觉桌面智能体；Python | 2026-08 仍更新 | MIT | 失败恢复和状态机 | 与 Codex 代理层重叠，部署过重 |
| [microsoft/AutoGenesis](https://github.com/microsoft/AutoGenesis) | Windows MCP 自动化测试；Python/pywinauto | 2026-08 仍更新，无正式 release | MIT | session、验证与 BDD 测试 | 更适合测试生成，不是日常 CSP 控制器 |
| [saitolume/clipstudio.js](https://github.com/saitolume/clipstudio.js) | `.clip` 缩略图/图层元数据只读；TypeScript/SQL.js | 2025-07 更新 | MIT | 可选离线只读检查思路 | 未公开格式易漂移，不能控制或写回；本项目不采用 |
| [dobrokot/clip_to_psd](https://github.com/dobrokot/clip_to_psd) | `.clip` 转 PSD/PNG；Python | 2024-07 更新 | MIT | 文件交换思路 | 格式覆盖不完整；本项目不解析 `.clip` |
| [mika-f/nekodraw](https://github.com/mika-f/nekodraw) | CSP EX 滤镜插件；C++/官方滤镜 SDK | 2023-10 更新 | MIT + CELSYS SDK 条款 | CSP 滤镜插件骨架 | 不是通用编辑 API，且 EX/SDK 许可边界不同，不采用 |

[CELSYS 官方公开 SDK](https://www.clipstudio.net/ja/sdk/)只面向 EX 图像滤镜插件，不提供文档、图层、菜单、时间线或无头自动化 API。[Auto Actions](https://help.clip-studio.com/en-us/manual_en/720_preferences/Auto_Actions.htm)、快捷键和 Quick Access 是受支持的应用内能力，文件格式交换也是公开工作流；它们不是官方外部通用自动化 API，而是本项目选择的可验证控制边界。

本项目仅复用架构思想，不复制上述仓库代码。
