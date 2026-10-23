import { initializeApp, getApps } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
let projectId = "threatops-local";
try {
  const cfgPath = path.resolve(__dirname, "../../firebase-applet-config.json");
  const parsed = JSON.parse(fs.readFileSync(cfgPath, "utf-8"));
  if (parsed?.projectId) projectId = parsed.projectId;
} catch {
  // Fallback projectId for local environments
}

if (!getApps().length) {
  initializeApp({ projectId });
}

export const adminAuth = getAuth();
