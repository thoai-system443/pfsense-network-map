/**
 * The backend address is written into config.js when the container starts, so
 * pointing the SPA at a different backend never requires a rebuild. Reading it
 * from import.meta.env would bake it into the bundle and break that.
 */
declare global {
  interface Window {
    __CONFIG__?: { API_URL?: string };
  }
}

const configured = window.__CONFIG__?.API_URL ?? "http://localhost:8010";

export const apiUrl = configured.replace(/\/+$/, "");
