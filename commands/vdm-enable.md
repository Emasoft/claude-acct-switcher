---
description: Re-arm vdm after a `/vdm-disable` — start the dashboard, restore hook behaviour
allowed-tools: Bash(vdm enable)
---

Removes the kill-switch marker and restarts the dashboard. Hooks resume
their normal behaviour automatically (the marker check at the top of
each hook now falls through to the curl call). New shells re-export
`ANTHROPIC_BASE_URL` via the rc-block.

Already-open shells need a manual `export ANTHROPIC_BASE_URL=http://localhost:3334`
or a new terminal to pick up the proxy again.

!`vdm enable`
