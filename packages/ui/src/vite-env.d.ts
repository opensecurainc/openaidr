/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_MOCK?: string;
  readonly VITE_MOCK_TENANT?: string;
  readonly VITE_MOCK_USER?: string;
  readonly VITE_CONSOLE_ORIGIN?: string;
}
