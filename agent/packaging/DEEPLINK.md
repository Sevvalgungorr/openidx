# `openidx://` deep-link registration

The Add-a-device wizard shows a QR / link of the form:

```
openidx://enroll?code=<enrollment-code>&server=<https://server>
```

When the OS opens it, the agent is invoked as `openidx-agent "openidx://enroll?..."`.
`main.go` detects the `openidx://` argument and rewrites it into
`enroll --code <code> --server <server>`. Each platform must register the agent
as the handler for the `openidx` URL scheme:

## Linux
Shipped automatically by the `.deb`/`.rpm` (see `nfpm.yaml`): the package installs
`openidx.desktop` (with `MimeType=x-scheme-handler/openidx;`) and its
`postinstall.sh` runs `xdg-mime default` + `update-desktop-database`.

## Windows (MSI / WiX)
Add a URL-protocol registry key under `HKCR\openidx` in `packaging/wix/OpenIDX.wxs`:

```xml
<Component Id="UrlSchemeOpenidx" Guid="*">
  <RegistryKey Root="HKCR" Key="openidx">
    <RegistryValue Type="string" Value="URL:OpenIDX Protocol" />
    <RegistryValue Name="URL Protocol" Type="string" Value="" />
    <RegistryKey Key="shell\open\command">
      <RegistryValue Type="string" Value="&quot;[INSTALLFOLDER]openidx-agent.exe&quot; &quot;%1&quot;" />
    </RegistryKey>
  </RegistryKey>
</Component>
```
Reference the component from the product feature. (Built in CI on the Windows runner.)

## macOS (.pkg app bundle)
Add to the app bundle's `Info.plist`:

```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLName</key><string>org.openidx.agent</string>
    <key>CFBundleURLSchemes</key><array><string>openidx</string></array>
  </dict>
</array>
```
(Built in CI on the macOS runner with `pkgbuild`.)

## Manual fallback
Every platform keeps a manual path: `openidx-agent enroll --code <code> --server <url>`,
and the wizard shows a **Copy code** button. Deep-link registration is a
convenience, never a requirement.
