# Password Buddy desktop shell

Requires Node 22.12 or later. Install and build from this directory:

```sh
ELECTRON_SKIP_BINARY_DOWNLOAD=1 npm ci --ignore-scripts
npm run typecheck
npm test
npm run build
```

The package entry is `dist/main.cjs`; sandboxed preload is `dist/preload.cjs`.
Both are bundled CommonJS with Electron as the only external module. The renderer
comes from Buddy's authenticated loopback HTTP origin, never a file or dev server.

Run an unpackaged shell only against a staged resource tree matching
`docs/design/desktop-v0/architecture.md`:

```sh
BUDDY_DESKTOP_RESOURCES=/absolute/staged/resources/buddy npm start -- --buddy-data-dir /absolute/isolated/test-profile
```

Install Electron's binary for that developer run (`npm rebuild electron`, or run
`node node_modules/electron/install.js`) if it was skipped. Release assembly owns
the bundled standalone Python, offline installer and manifest. There is no system
Python, checkout, existing LeakGuard service or global virtualenv fallback.

The default profile is the OS app-data directory / Password Buddy. The entire
profile can be selected by an explicit absolute `--buddy-data-dir PATH`; symlinked
profile roots are refused. This workspace is independent from legacy LeakGuard.
Single instance is per selected profile, and Buddy also holds a nonblocking OS
ownership lock while stores are locked. A second owner is never attached or killed.

Closing hides to the native tray and locks credentials while scans remain
independent. Hide, suspend, supported OS-lock events and five minutes OS idle clear
sensitive renderer state and request credential lock. Lock is acknowledged only
after the backend confirms it. Copy uses Electron 45's asynchronous clipboard API
and conditionally clears the copied value after 30 seconds. Quit quiesces APIs and
waits for the owned backend's safe close; failed worker stop retains ownership and
offers Retry. No timer kills the backend.

Native Mac/Windows login and OS-lock event behavior still require native acceptance.
Linux advertises idle/suspend handling and no session-lock/login capability.
