export {};
declare global {
  interface Window { buddyDesktop?: BuddyDesktop }
  interface BuddyDesktop {
    getInfo(): Promise<DesktopInfo>;
    bootstrapSession(): Promise<{ token: string }>;
    chooseDirectory(): Promise<{ canceled: boolean; path?: string }>;
    saveEncryptedBackup(input: { filename: string; base64: string }): Promise<{ canceled: boolean; saved: boolean }>;
    copySecret(input: { text: string }): Promise<{ copied: boolean }>;
    getPreferences(): Promise<DesktopPreferences>;
    setPreferences(patch: Partial<DesktopPreferences>): Promise<DesktopPreferences>;
    onEvent(callback: (event: DesktopEvent) => void): () => void;
  }
  interface DesktopPreferences { theme: "system" | "light" | "dark"; startAtLogin: boolean }
  interface DesktopInfo { protocolVersion: 1; appVersion: string; platform: "darwin" | "win32" | "linux"; packaged: boolean; profileKind: "desktop"; capabilities: { directoryPicker: boolean; encryptedBackupSave: boolean; nativeClipboard: boolean; startAtLogin: boolean; sessionLockEvents: boolean } }
  type DesktopEvent = { type: "navigate"; page: "overview" | "sources" | "findings" | "vault" | "plugins" | "settings" } | { type: "clear-sensitive"; reason: string } | { type: "vault-locked" } | { type: "backend-state"; state: "ready" | "unavailable" | "stopping"; code?: string };
}