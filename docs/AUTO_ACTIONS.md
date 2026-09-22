# Auto Actions setup

CSP stores Auto Actions as proprietary *.laf* data, which this MCP neither parses nor modifies. CELSYS documents Auto Actions for PRO and EX; DEBUT does not have them. The tracked *config/auto_actions.json* is an empty template; local registrations go in *config/auto_actions.local.json*, which Git ignores.

1. Create the action in CSP's *Auto Action* palette and check by hand that it does what you expect.
2. In CSP's shortcut settings, bind it to *Ctrl+Alt+F1* through *F12* or *Ctrl+Alt+Shift+F1* through *F12*. Production validation refuses any other combination.
3. Stop the running MCP, copy *config/auto_actions.json* to *config/auto_actions.local.json*, and add the action to the top-level `actions` array of the local file. A complete example:

```json
{
  "schema_version": 1,
  "profile_ids": ["csp-1.11.10-dpi96-v1"],
  "actions": [
    {
      "id": "layer.merge_visible_copy",
      "title": "Merge visible layers into a copy",
      "description": "A document action verified in CSP by the user; it does not open, save, or export anything",
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

4. Restart Codex and call `csp_list_auto_actions` to check the registration.
5. Call `csp_preflight(operation="input", identifier="csp_run_auto_action", parameters_json='{"action_id":"..."}')`. Once the user approves it, call `csp_capture` again, then pass the new captureId and the single-use confirmToken to `csp_run_auto_action` with exactly the same parameters. The older `operation="auto_action"` form still works as an alias, but every Auto Action goes through the same token flow.

The user is responsible for verifying each action's name, shortcut, side effects, and preconditions. The MCP only sends allowlisted key combinations and compares captures before and after.

Production configuration refuses every Auto Action with `effect: "filesystem"` and requires an explicit `"attested_no_file_io": true`. CSP can save from an Auto Action; the reason for the rule is that the MCP cannot inspect a proprietary *.laf* file to see whether it writes outside the allowlisted paths. Open, save, and export through this MCP's path validation and native file-dialog tools instead. The attestation is the administrator's promise, not something the server proves from the *.laf* contents.
