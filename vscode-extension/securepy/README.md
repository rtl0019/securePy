# SecurePy

SecurePy is a VS Code extension for running the SecurePy Python security scanner directly inside the editor.

## Features

- Scan the current Python file
- Scan the current workspace
- Show findings in the Problems panel
- Highlight issues directly in the editor
- Optional scan on save
- Output raw SecurePy results in the SecurePy output channel

## Commands

- **SecurePy: Scan Current File**
- **SecurePy: Scan Workspace**
- **SecurePy: Clear Diagnostics**

## Requirements

This extension requires the SecurePy CLI to be installed and accessible on your machine.

You can point the extension to the CLI using the `securepy.executablePath` setting.

Example:

```json
{
  "securepy.executablePath": "/absolute/path/to/securepy"
}