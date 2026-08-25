# Auto Actions 接入

CSP 的 `.laf` 是专有动作数据。本 MCP 不解析或修改它。
CELSYS 官方说明 Auto Actions 适用于 PRO/EX，不支持 DEBUT；已跟踪的
`config/auto_actions.json` 是空模板，本机登记写入被 Git 忽略的
`config/auto_actions.local.json`。

1. 在 CSP 的 Auto Action 面板创建并人工验证动作。
2. 在 CSP 的快捷键设置中绑定 `Ctrl+Alt+F1..F12` 或 `Ctrl+Alt+Shift+F1..F12`；其他组合会被 production 校验拒绝。
3. 关闭正在运行的 MCP，把 `config/auto_actions.json` 复制为
   `config/auto_actions.local.json`，再把动作加入本机文件顶层的 `actions` 数组。完整文件结构示例：

```json
{
  "schema_version": 1,
  "profile_id": "csp-5.1.2-zh-CN-dpi120-v1",
  "actions": [
    {
      "id": "layer.merge_visible_copy",
      "title": "合并可见图层副本",
      "description": "用户已在 CSP 内验证、且不包含打开/保存/导出的文档动作",
      "effect": "document",
      "risk": "modify",
      "keys": ["CTRL", "ALT", "F9"],
      "requires_confirmation": true,
      "attested_no_file_io": true,
      "enabled": true
    }
  ]
}
```

4. 重启 Codex，调用 `csp_list_auto_actions` 核对登记结果。
5. 先调用 `csp_preflight(operation="input", identifier="csp_run_auto_action", parameters_json='{"action_id":"..."}')`；用户批准后重新调用 `csp_capture`，最后把新 captureId 与单次 confirmToken 一起交给参数完全一致的 `csp_run_auto_action`。旧版 `operation="auto_action"` 仍作为兼容别名，但所有 Auto Action 都必须经过同一令牌流程。

动作名称、快捷键、副作用和前置状态都由用户负责验证；MCP 只执行白名单组合键并比较前后截图。

生产配置拒绝所有 `effect: "filesystem"` 的 Auto Action，并要求显式填写
`"attested_no_file_io": true`。原因不是 CSP 做不到保存，而是 MCP 无法检查专有
`.laf` 内部是否写入了白名单之外的路径。打开、保存和导出应使用本 MCP 的路径校验与
原生文件对话框工具。声明是管理员承诺，不是服务端对 `.laf` 内容的证明。
