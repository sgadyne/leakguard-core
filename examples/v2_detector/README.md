# LeakGuard v2 detector example

This independently installable package shows a small synthetic firm rule. It
reports a location and a stable rule ID; it never returns the matched text.

Install alongside LeakGuard Core from this directory with `python -m pip
install .`. Then explicitly select the component in the external LeakGuard
configuration:

```json
{
  "plugins": [
    {
      "module": "example_detector.plugin",
      "component": "example-firm-marker",
      "options": {}
    }
  ]
}
```

The manifest declares `example-firm-marker` as a detector and the static rule ID
`example-firm-marker`. The example marker is synthetic and has no credential
meaning. Python extensions run as trusted code with the scanner account's
permissions; the worker contract is not a security sandbox.
