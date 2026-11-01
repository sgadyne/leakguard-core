# Password Buddy: three-key identity

Three horizontal keys step left from top to bottom. Mint, warm gold and ivory on
deep teal form the application tile; their colors carry no scan-status meaning.
The menu-bar mark uses a separate optically adjusted monochrome drawing with
larger holes and shorter teeth. It is not a scaled color tile.

## Assets and integration

- `app-icon.svg`: editable desktop/Dock master.
- `mark.svg`: transparent single-color mark (`currentColor`).
- `mark-color.svg`: transparent color mark for light surfaces.
- `menu-bar.svg`: 24 x 22 monochrome source.
- `preview.svg` / `preview.png`: design contact sheet, not a product screenshot.
- `../../apps/desktop/assets/icon.png`: 1024 px raster.
- `../../apps/desktop/assets/icon.icns`: complete Mac icon family.
- `../../apps/desktop/assets/icon.ico`: PNG-compressed 16/24/32/48/64/128/256 family.
- `trayTemplate.png` and `trayTemplate@2x.png` in desktop assets: native 24 x 22
  / 48 x 44 template representations; macOS supplies light/dark appearance.
- `../../apps/buddy-ui/src/BrandMark.tsx`: generated inline SVG beside the app name;
  decorative, with the adjacent text supplying the accessible name.

The desktop packaging script passes the appropriate ICNS/ICO/PNG file to
Electron Packager. The native tray loads the template without resizing away its
scale representations. PNG/ICO export does not imply Windows/Linux qualification.

Penpot was not available through this session's connected tools or plugin
directory. Import the SVG masters into Penpot to edit them. No external fonts or
linked raster images are required for the marks. Text in the preview is illustrative.

## Regenerate

```sh
cd tools/brand
npm ci --ignore-scripts --no-audit --no-fund
npm run build
```

Geometry is centralized in `tools/brand/build.mjs`; edit there and regenerate so
the React and native exports stay aligned. Rendering uses pinned
`@resvg/resvg-js@2.6.2` only as development tooling. macOS `iconutil` produces ICNS;
on other systems that existing export is retained and must be regenerated on a Mac
before a Mac release. `manifest.json` records generated asset SHA-256 values.

Useful platform references: [Electron nativeImage](https://www.electronjs.org/docs/latest/api/native-image)
and [Electron Packager icon option](https://electron.github.io/packager/main/interfaces/Options.html#icon).

These are next-revision assets. They do not alter the published November 1 pilot
or the user's installed app/profile. Native Finder/menu-bar appearance still needs
an exact next-build smoke check before publishing that revision.
