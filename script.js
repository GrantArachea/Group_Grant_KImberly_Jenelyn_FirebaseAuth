"use strict";

/* ============================================================
  FirebaseAuth — REST Auth (Token-Based)
  Clean UI: main = login/signup. Everything else in Account modal.

  FEATURES KEPT:
  - Sign Up (accounts:signUp)
  - Sign In (accounts:signInWithPassword)
  - Sign Out (local)
  - Lookup Profile (accounts:lookup)
  - Update Profile (accounts:update)
  - Send Password Reset (accounts:sendOobCode)
  - Refresh ID Token (securetoken /token)

  FEATURES KEPT (from your “max points” version):
  - Send Verify Email (accounts:sendOobCode requestType=VERIFY_EMAIL)
  - Change Password (accounts:update password)
  - Delete Account (accounts:delete)
  - Auto-refresh token near expiry (before protected calls)
  - Activity log
  - Copy token buttons

  ============================================================
  DETAILED FUNCTION COMMENTS (WHAT/WHY/EDGE CASES)
  ------------------------------------------------------------
  This file is organized into sections:
  1) CONFIG/DOM/STATE
  2) UI helpers (loading, error, mode, status, session display, log)
  3) Storage (localStorage for session + log)
  4) Validation (input checks + auth requirement checks)
  5) API core (fetch wrappers with uniform error handling)
  6) Endpoint wrappers (Firebase REST endpoints)
  7) Results UI (cards in the modal)
  8) Auto token refresh (keeps calls working near expiry)
  9) Actions (event handlers for UI buttons)
  10) Copy/Clear
  11) Events and Init
============================================================ */

/* ===================== CONFIG ===================== */
/**
 * API_KEY
 * - Reads from window.FIREBASE_API_KEY (typically set in config.js).
 * - Trim is important: avoids invisible spaces/newlines breaking requests.
 * - SECURITY: config.js should not be committed if it contains secrets.
 */
const API_KEY = (window.FIREBASE_API_KEY || "").trim();

/**
 * Firebase REST base URLs:
 * - Identity Toolkit API: sign up/in, lookup, update, sendOobCode, delete.
 * - Secure Token API: refresh tokens (exchange refresh_token -> new id_token).
 */
const ID_TOOLKIT_BASE = "https://identitytoolkit.googleapis.com/v1";
const SECURE_TOKEN_BASE = "https://securetoken.googleapis.com/v1";

/**
 * localStorage keys:
 * - SESSION_KEY stores current auth session snapshot.
 * - LOG_KEY stores recent activity items (for UI auditing/debugging).
 */
const SESSION_KEY = "firebaseauth.session.v3";
const LOG_KEY = "firebaseauth.log.v2";

/**
 * Auto refresh threshold:
 * - If time left on ID token is <= 2 minutes, refresh before protected calls.
 * - Reduces “token expired” errors during demos.
 */
const AUTO_REFRESH_THRESHOLD_MS = 2 * 60 * 1000; // 2 minutes

/* ===================== DOM ===================== */
// Tabs / main auth
const tabSignIn = document.getElementById("tabSignIn");
const tabSignUp = document.getElementById("tabSignUp");
const btnSubmit = document.getElementById("btnSubmit");
const btnForgot = document.getElementById("btnForgot");

const elEmail = document.getElementById("email");
const elPassword = document.getElementById("password");
const elErrorBox = document.getElementById("errorBox");

const elLoader = document.getElementById("loader");
const elLoaderText = document.getElementById("loaderText");

// Topbar
const elStatusDot = document.getElementById("statusDot");
const elStatusText = document.getElementById("statusText");
const btnOpenAccount = document.getElementById("btnOpenAccount");
const btnSignOutTop = document.getElementById("btnSignOutTop");

// Side session + log
const elSessionKv = document.getElementById("sessionKv");
const elLogList = document.getElementById("logList");
const btnCopyIdToken = document.getElementById("btnCopyIdToken");
const btnCopyRefreshToken = document.getElementById("btnCopyRefreshToken");

// Modal
const modal = document.getElementById("accountModal");
const backdrop = document.getElementById("modalBackdrop");
const btnCloseModal = document.getElementById("btnCloseModal");

// Modal fields/actions
const elDisplayName = document.getElementById("displayName");
const elPhotoUrl = document.getElementById("photoUrl");
const elNewPassword = document.getElementById("newPassword");

const btnLookup = document.getElementById("btnLookup");
const btnUpdate = document.getElementById("btnUpdate");
const btnVerifyEmail = document.getElementById("btnVerifyEmail");

const btnResetPw = document.getElementById("btnResetPw");
const btnRefresh = document.getElementById("btnRefresh");
const btnChangePw = document.getElementById("btnChangePw");
const btnDelete = document.getElementById("btnDelete");

const btnClearResults = document.getElementById("btnClearResults");
const btnClearLog = document.getElementById("btnClearLog");

const elResults = document.getElementById("results");
const elEmpty = document.getElementById("emptyState");

/* ===================== STATE ===================== */
/**
 * mode
 * - "signin" or "signup" controls the main form behavior and button text.
 */
let mode = "signin"; // signin | signup

/**
 * session
 * - Holds the current authenticated user's tokens + metadata.
 * - Loaded from localStorage at startup to persist across refresh.
 *
 * Expected shape (not all fields always present):
 * {
 *   idToken, refreshToken, email, localId, displayName,
 *   expiresIn, tokenIssuedAt, emailVerified
 * }
 */
let session = loadSession();

/**
 * logItems
 * - Recent events, stored in localStorage, capped at 20.
 */
let logItems = loadLog();

/**
 * tickTimer
 * - setInterval handle for updating session countdown (“time left”).
 */
let tickTimer = null;

/* ===================== UI ===================== */
/**
 * setLoading(isLoading, text)
 * WHAT:
 * - Shows/hides loader overlay and disables interactive buttons while busy.
 * WHY:
 * - Prevents double submits and conflicting actions while a network call is in-flight.
 * EDGE CASES:
 * - Any null DOM references are skipped safely (if (b) ...).
 */
function setLoading(isLoading, text = "Loading…") {
  elLoader.style.display = isLoading ? "flex" : "none";
  elLoaderText.textContent = text;

  const lock = !!isLoading;
  const buttons = [
    tabSignIn, tabSignUp, btnSubmit, btnForgot,
    btnOpenAccount, btnSignOutTop,
    btnLookup, btnUpdate, btnVerifyEmail,
    btnResetPw, btnRefresh, btnChangePw, btnDelete,
    btnCopyIdToken, btnCopyRefreshToken,
    btnClearResults, btnClearLog,
    btnCloseModal
  ];
  buttons.forEach(b => { if (b) b.disabled = lock; });
}

/**
 * showError(message)
 * WHAT:
 * - Displays a single error banner on the main UI.
 * WHY:
 * - Centralizes error presentation so every handler can call it consistently.
 * NOTE:
 * - Passing "" hides the error box.
 */
function showError(message) {
  elErrorBox.style.display = message ? "block" : "none";
  elErrorBox.textContent = message || "";
}

/**
 * setMode(nextMode)
 * WHAT:
 * - Switches between Sign In and Sign Up tab.
 * - Updates aria-selected for accessibility and updates submit button label.
 * WHY:
 * - Keeps the main UI minimal with one form supporting two flows.
 */
function setMode(nextMode) {
  mode = nextMode;
  const isSignIn = mode === "signin";

  tabSignIn.classList.toggle("isActive", isSignIn);
  tabSignUp.classList.toggle("isActive", !isSignIn);

  tabSignIn.setAttribute("aria-selected", String(isSignIn));
  tabSignUp.setAttribute("aria-selected", String(!isSignIn));

  btnSubmit.textContent = isSignIn ? "Sign in" : "Create account";
}

/**
 * renderStatus()
 * WHAT:
 * - Updates topbar status text/dot and enables/disables buttons based on auth.
 * WHY:
 * - Prevents users from triggering protected actions when signed out.
 * - Keeps UI state consistent with session state.
 * DETAIL:
 * - Copy refresh token enabled if refresh token exists even if idToken missing,
 *   but in this code, signedIn is based on idToken.
 */
function renderStatus() {
  const signedIn = !!(session && session.idToken);
  elStatusText.textContent = signedIn ? `Signed in: ${session.email || "user"}` : "Signed out";

  elStatusDot.style.background = signedIn ? "var(--green)" : "var(--red)";
  elStatusDot.style.boxShadow = signedIn
    ? "0 0 0 4px rgba(34,197,94,0.12)"
    : "0 0 0 4px rgba(251,113,133,0.10)";

  btnOpenAccount.disabled = !signedIn;
  btnSignOutTop.disabled = !signedIn;

  btnCopyIdToken.disabled = !signedIn;
  btnCopyRefreshToken.disabled = !(session && session.refreshToken);

  // modal buttons require auth
  const modalBtns = [btnLookup, btnUpdate, btnVerifyEmail, btnRefresh, btnChangePw, btnDelete];
  modalBtns.forEach(b => b.disabled = !signedIn);
}

/**
 * truncateMiddle(str, head, tail)
 * WHAT:
 * - Truncates long tokens for display: shows start + end with ellipsis.
 * WHY:
 * - Tokens are long; showing full token clutters UI and can leak secrets on screen.
 * SECURITY:
 * - This is display-only; copies still copy full token from session.
 */
function truncateMiddle(str, head = 18, tail = 10) {
  if (!str) return "";
  if (str.length <= head + tail + 3) return str;
  return `${str.slice(0, head)}…${str.slice(-tail)}`;
}

/**
 * secondsToMs(secStr)
 * WHAT:
 * - Converts Firebase expiresIn strings (seconds) to ms.
 * WHY:
 * - All Date.now() calculations are in ms.
 * EDGE CASE:
 * - Non-numeric -> 0, prevents NaN propagation.
 */
function secondsToMs(secStr) {
  const n = Number(secStr);
  return Number.isFinite(n) ? n * 1000 : 0;
}

/**
 * getExpiresAtMs(sess)
 * WHAT:
 * - Computes the absolute expiry time (ms since epoch) using:
 *   tokenIssuedAt + expiresIn(seconds->ms)
 * WHY:
 * - Used for countdown and refresh logic.
 * NOTE:
 * - tokenIssuedAt is set locally when receiving token/refresh response.
 */
function getExpiresAtMs(sess) {
  if (!sess?.tokenIssuedAt || !sess?.expiresIn) return 0;
  return sess.tokenIssuedAt + secondsToMs(sess.expiresIn);
}

/**
 * getRemainingMs(sess)
 * WHAT:
 * - Returns ms remaining until expiry (0..).
 * WHY:
 * - Central countdown used by renderSession and ensureFreshIdToken.
 */
function getRemainingMs(sess) {
  const exp = getExpiresAtMs(sess);
  if (!exp) return 0;
  return Math.max(0, exp - Date.now());
}

/**
 * formatRemaining(ms)
 * WHAT:
 * - Formats remaining ms into mm:ss.
 * WHY:
 * - Simple human-readable countdown.
 */
function formatRemaining(ms) {
  const s = Math.floor(ms / 1000);
  const mm = String(Math.floor(s / 60)).padStart(2, "0");
  const ss = String(s % 60).padStart(2, "0");
  return `${mm}:${ss}`;
}

/**
 * setKvRow(k, v)
 * WHAT:
 * - Appends two divs (key/value) to the session KV container.
 * WHY:
 * - Keeps renderSession readable by reusing a small helper.
 */
function setKvRow(k, v) {
  const dk = document.createElement("div");
  dk.className = "k";
  dk.textContent = k;

  const dv = document.createElement("div");
  dv.className = "v";
  dv.textContent = v == null ? "" : String(v);

  elSessionKv.appendChild(dk);
  elSessionKv.appendChild(dv);
}

/**
 * renderSession()
 * WHAT:
 * - Populates the sidebar session panel with current session data.
 * WHY:
 * - Helps users debug and demonstrates token-based session state for grading.
 * SECURITY:
 * - Displays truncated tokens; full tokens still exist in localStorage/session.
 */
function renderSession() {
  elSessionKv.innerHTML = "";

  if (!session || !session.idToken) {
    setKvRow("status", "signed out");
    setKvRow("api key", API_KEY && API_KEY !== "YOUR_API_KEY_HERE" ? "configured" : "missing");
    setKvRow("note", "Sign in to view tokens and user info.");
    return;
  }

  const remaining = getRemainingMs(session);
  const expAt = getExpiresAtMs(session);

  setKvRow("email", session.email || "");
  setKvRow("localId", session.localId || "");
  setKvRow("displayName", session.displayName || "");
  setKvRow("emailVerified", session.emailVerified != null ? String(session.emailVerified) : "unknown");
  setKvRow("expiresAt", expAt ? new Date(expAt).toLocaleString() : "unknown");
  setKvRow("time left", remaining ? formatRemaining(remaining) : "unknown");
  setKvRow("idToken", truncateMiddle(session.idToken || ""));
  setKvRow("refreshToken", truncateMiddle(session.refreshToken || ""));
}

/**
 * logEvent(message)
 * WHAT:
 * - Adds a timestamped log item to localStorage and re-renders.
 * WHY:
 * - Provides an “activity log” feature for demos and debugging API calls.
 * DESIGN:
 * - Unshift places newest first; slice caps list length at 20.
 */
function logEvent(message) {
  const item = { t: Date.now(), msg: message };
  logItems.unshift(item);
  logItems = logItems.slice(0, 20);
  localStorage.setItem(LOG_KEY, JSON.stringify(logItems));
  renderLog();
}

/**
 * renderLog()
 * WHAT:
 * - Renders activity log list; shows a placeholder when empty.
 * WHY:
 * - Visual feedback for actions (POST path, OK/ERROR, copies, clears).
 */
function renderLog() {
  elLogList.innerHTML = "";
  if (!logItems.length) {
    const li = document.createElement("li");
    li.textContent = "No activity yet.";
    elLogList.appendChild(li);
    return;
  }
  for (const it of logItems) {
    const li = document.createElement("li");
    const time = new Date(it.t).toLocaleTimeString();
    li.textContent = `[${time}] ${it.msg}`;
    elLogList.appendChild(li);
  }
}

/**
 * openModal()
 * WHAT:
 * - Opens account modal and shows backdrop.
 * WHY:
 * - Keeps main UI clean while still exposing advanced account actions.
 * NOTE:
 * - Uses <dialog>.showModal() which blocks focus behind it.
 */
function openModal() {
  backdrop.style.display = "block";
  backdrop.setAttribute("aria-hidden", "false");
  modal.showModal();
}

/**
 * closeModal()
 * WHAT:
 * - Closes <dialog> and hides backdrop.
 * WHY:
 * - Restores main UI interaction.
 */
function closeModal() {
  modal.close();
  backdrop.style.display = "none";
  backdrop.setAttribute("aria-hidden", "true");
}

/* ===================== STORAGE ===================== */
/**
 * saveSession(next)
 * WHAT:
 * - Writes session to memory and localStorage (or clears it).
 * - Triggers UI updates (status + session sidebar).
 * WHY:
 * - Single source of truth; prevents forgetting to re-render after changes.
 */
function saveSession(next) {
  session = next || null;
  if (!session) localStorage.removeItem(SESSION_KEY);
  else localStorage.setItem(SESSION_KEY, JSON.stringify(session));

  renderStatus();
  renderSession();
}

/**
 * loadSession()
 * WHAT:
 * - Reads session JSON from localStorage.
 * WHY:
 * - Persists login across reload.
 * EDGE CASE:
 * - Invalid JSON returns null safely.
 */
function loadSession() {
  try {
    const raw = localStorage.getItem(SESSION_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

/**
 * loadLog()
 * WHAT:
 * - Loads activity log array from localStorage.
 * WHY:
 * - Maintains an action history across reloads.
 */
function loadLog() {
  try {
    const raw = localStorage.getItem(LOG_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

/* ===================== VALIDATION ===================== */
/**
 * ensureApiKeyOrThrow()
 * WHAT:
 * - Hard fails before any API call if API_KEY missing.
 * WHY:
 * - Saves time: avoids confusing 400/403 errors from Firebase.
 */
function ensureApiKeyOrThrow() {
  if (!API_KEY || API_KEY === "YOUR_API_KEY_HERE") {
    throw new Error("Missing API key. Create config.js and set window.FIREBASE_API_KEY. Do NOT commit config.js.");
  }
}

/**
 * trimVal(el)
 * WHAT:
 * - Returns element.value trimmed.
 * WHY:
 * - Normalizes inputs and avoids whitespace auth failures.
 */
function trimVal(el) { return (el.value || "").trim(); }

/**
 * isValidEmail(email)
 * WHAT:
 * - Simple email format validation.
 * WHY:
 * - Prevents unnecessary API calls and provides user-friendly errors.
 */
function isValidEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }

/**
 * hasInvalidCharsBasic(str)
 * WHAT:
 * - Rejects ASCII control chars (0x00-0x1F and 0x7F).
 * WHY:
 * - Protects against weird copy/paste artifacts and invisible characters.
 */
function hasInvalidCharsBasic(str) { return /[\u0000-\u001F\u007F]/.test(str); }

/**
 * getEmailPasswordOrThrow()
 * WHAT:
 * - Reads email/password from main form, validates, returns them.
 * WHY:
 * - Centralizes sign-in/up validation.
 * DETAILS:
 * - Password length >= 6 matches Firebase minimum requirement by default.
 * SIDE EFFECT:
 * - Writes trimmed values back to inputs to keep UI consistent.
 */
function getEmailPasswordOrThrow() {
  const email = trimVal(elEmail);
  const password = trimVal(elPassword);

  if (!email || !password) throw new Error("Invalid input: Email and Password are required.");
  if (!isValidEmail(email)) throw new Error("Invalid input: Enter a valid email address.");
  if (password.length < 6) throw new Error("Invalid input: Password must be at least 6 characters.");
  if (hasInvalidCharsBasic(email) || hasInvalidCharsBasic(password)) {
    throw new Error("Invalid input: Detected invalid control characters.");
  }

  elEmail.value = email;
  elPassword.value = password;
  return { email, password };
}

/**
 * getProfileFieldsOrThrow()
 * WHAT:
 * - Reads displayName and photoUrl from modal fields; validates format.
 * WHY:
 * - Prevents malformed data being sent to /accounts:update.
 * VALIDATION RULES:
 * - Control chars rejected.
 * - photoUrl must start with http:// or https:// if provided.
 * SIDE EFFECT:
 * - Writes trimmed values back to inputs.
 */
function getProfileFieldsOrThrow() {
  const displayName = trimVal(elDisplayName);
  const photoUrl = trimVal(elPhotoUrl);

  if (displayName && hasInvalidCharsBasic(displayName)) throw new Error("Invalid input: Display name has invalid characters.");
  if (photoUrl && hasInvalidCharsBasic(photoUrl)) throw new Error("Invalid input: Photo URL has invalid characters.");
  if (photoUrl && !/^https?:\/\/.+/i.test(photoUrl)) throw new Error("Invalid input: Photo URL must start with http:// or https://");

  elDisplayName.value = displayName;
  elPhotoUrl.value = photoUrl;
  return { displayName, photoUrl };
}

/**
 * getNewPasswordOrThrow()
 * WHAT:
 * - Reads and validates new password for Change Password flow.
 * WHY:
 * - Avoids sending invalid password updates.
 */
function getNewPasswordOrThrow() {
  const np = trimVal(elNewPassword);
  if (!np) throw new Error("Invalid input: New Password is required.");
  if (np.length < 6) throw new Error("Invalid input: New Password must be at least 6 characters.");
  if (hasInvalidCharsBasic(np)) throw new Error("Invalid input: Detected invalid control characters.");
  elNewPassword.value = np;
  return np;
}

/**
 * requireSessionOrThrow()
 * WHAT:
 * - Ensures user is signed in before protected actions.
 * WHY:
 * - Provides a clear message instead of failing with API errors.
 * NOTE:
 * - Message uses your rubric-friendly “No results found” pattern.
 */
function requireSessionOrThrow() {
  if (!session || !session.idToken) throw new Error("No results found: You are signed out. Sign in first.");
}

/* ===================== API CORE ===================== */
/**
 * apiJsonPost(baseUrl, path, bodyObj)
 * WHAT:
 * - Generic helper for Firebase JSON POST endpoints using ?key=API_KEY.
 * WHY:
 * - DRY: all endpoints share identical fetch + parse + error mapping logic.
 * ERROR HANDLING:
 * - Attempts res.json(); if it fails, uses {}.
 * - If !res.ok, uses data.error.message when available, else HTTP_status fallback.
 * - Throws Error augmented with status/code/raw for debugging.
 * LOGGING:
 * - Writes "POST path", then "OK path" or "ERROR path: code".
 */
async function apiJsonPost(baseUrl, path, bodyObj) {
  ensureApiKeyOrThrow();

  const url = `${baseUrl}${path}?key=${encodeURIComponent(API_KEY)}`;
  logEvent(`POST ${path}`);
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(bodyObj || {})
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    const code = data?.error?.message || `HTTP_${res.status}`;
    logEvent(`ERROR ${path}: ${code}`);
    const err = new Error(`API error (${res.status}): ${code}`);
    err.status = res.status;
    err.code = code;
    err.raw = data;
    throw err;
  }

  logEvent(`OK ${path}`);
  return data;
}

/**
 * apiFormPost(baseUrl, path, formObj)
 * WHAT:
 * - Generic helper for x-www-form-urlencoded POST (Secure Token refresh).
 * WHY:
 * - securetoken.googleapis.com expects form-encoded parameters.
 * DETAIL:
 * - Uses URLSearchParams for correct encoding.
 */
async function apiFormPost(baseUrl, path, formObj) {
  ensureApiKeyOrThrow();

  const url = `${baseUrl}${path}?key=${encodeURIComponent(API_KEY)}`;
  const formBody = new URLSearchParams();
  Object.entries(formObj || {}).forEach(([k, v]) => formBody.append(k, String(v)));

  logEvent(`POST ${path}`);
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: formBody.toString()
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    const code = data?.error?.message || `HTTP_${res.status}`;
    logEvent(`ERROR ${path}: ${code}`);
    const err = new Error(`API error (${res.status}): ${code}`);
    err.status = res.status;
    err.code = code;
    err.raw = data;
    throw err;
  }

  logEvent(`OK ${path}`);
  return data;
}

/* ===================== ENDPOINT WRAPPERS ===================== */
/**
 * These wrappers keep the rest of the code readable:
 * - They encode exactly which Firebase endpoint is used and with what payload.
 * - If you change versions or endpoints later, you update in one place.
 */
function signUp(email, password) {
  return apiJsonPost(ID_TOOLKIT_BASE, "/accounts:signUp", { email, password, returnSecureToken: true });
}
function signIn(email, password) {
  return apiJsonPost(ID_TOOLKIT_BASE, "/accounts:signInWithPassword", { email, password, returnSecureToken: true });
}
function lookupProfile(idToken) {
  return apiJsonPost(ID_TOOLKIT_BASE, "/accounts:lookup", { idToken });
}
function updateProfile(idToken, displayName, photoUrl) {
  const body = { idToken, returnSecureToken: true };
  if (displayName) body.displayName = displayName;
  if (photoUrl) body.photoUrl = photoUrl;
  return apiJsonPost(ID_TOOLKIT_BASE, "/accounts:update", body);
}
function sendOobCode(body) {
  return apiJsonPost(ID_TOOLKIT_BASE, "/accounts:sendOobCode", body);
}
function refreshIdToken(refreshToken) {
  return apiFormPost(SECURE_TOKEN_BASE, "/token", { grant_type: "refresh_token", refresh_token: refreshToken });
}
function changePassword(idToken, newPassword) {
  return apiJsonPost(ID_TOOLKIT_BASE, "/accounts:update", { idToken, password: newPassword, returnSecureToken: true });
}
function deleteAccount(idToken) {
  return apiJsonPost(ID_TOOLKIT_BASE, "/accounts:delete", { idToken });
}

/* ===================== RESULTS UI (MODAL) ===================== */
/**
 * makeResultCard(title, rowsObj, badges)
 * WHAT:
 * - Produces a consistent “card” element with a title, key/value grid, and badges.
 * WHY:
 * - Easy to show responses from multiple endpoints without cluttering main UI.
 * SECURITY:
 * - Tokens displayed should be truncated by caller (this function prints strings).
 */
function makeResultCard(title, rowsObj, badges = []) {
  const card = document.createElement("div");
  card.className = "resultCard";

  const h = document.createElement("div");
  h.className = "resultCard__title";
  h.textContent = title;

  const kv = document.createElement("div");
  kv.className = "kv2";
  for (const [k, v] of Object.entries(rowsObj)) {
    const dk = document.createElement("div");
    dk.className = "k";
    dk.textContent = k;

    const dv = document.createElement("div");
    dv.className = "v";
    dv.textContent = v == null ? "" : String(v);

    kv.appendChild(dk);
    kv.appendChild(dv);
  }

  card.appendChild(h);
  card.appendChild(kv);

  if (badges.length) {
    const row = document.createElement("div");
    row.className = "badges";
    badges.forEach(b => {
      const pill = document.createElement("span");
      pill.className = "badge";
      pill.textContent = b;
      row.appendChild(pill);
    });
    card.appendChild(row);
  }

  return card;
}

/**
 * pushResult(card)
 * WHAT:
 * - Adds a result card to the top of the results list (most recent first).
 * WHY:
 * - Keeps latest API result visible without scrolling.
 */
function pushResult(card) {
  elEmpty.style.display = "none";
  elResults.prepend(card);
}

/**
 * clearResults()
 * WHAT:
 * - Clears all result cards and shows the empty state.
 * WHY:
 * - Provides a clean slate for demos and avoids confusion.
 */
function clearResults() {
  elResults.innerHTML = "";
  elEmpty.style.display = "block";
}

/* ===================== AUTO TOKEN REFRESH ===================== */
/**
 * ensureFreshIdToken()
 * WHAT:
 * - If current idToken is near expiration, refresh it using refresh_token.
 * WHY:
 * - Firebase ID tokens expire (typically ~1 hour). Refreshing prevents failures.
 * HOW:
 * - Checks getRemainingMs(session) and compares to AUTO_REFRESH_THRESHOLD_MS.
 * - Calls securetoken /token, then updates session with new id_token and timing.
 * RESULT UI:
 * - Pushes a card showing truncated new tokens and expires_in.
 * EDGE CASES:
 * - If remaining is 0 (unknown), function returns and does nothing.
 * - If refreshToken missing, throws a clear auth error.
 */
async function ensureFreshIdToken() {
  requireSessionOrThrow();

  const remaining = getRemainingMs(session);
  if (!remaining) return;

  if (remaining <= AUTO_REFRESH_THRESHOLD_MS) {
    if (!session.refreshToken) throw new Error("Authentication error: Missing refresh token.");

    const resp = await refreshIdToken(session.refreshToken);

    saveSession({
      ...session,
      idToken: resp.id_token || session.idToken,
      refreshToken: resp.refresh_token || session.refreshToken,
      expiresIn: resp.expires_in || session.expiresIn,
      tokenIssuedAt: Date.now()
    });

    pushResult(makeResultCard("Auto Refresh (securetoken /token)", {
      user_id: resp.user_id || "",
      id_token: truncateMiddle(resp.id_token || ""),
      refresh_token: truncateMiddle(resp.refresh_token || ""),
      expires_in: resp.expires_in || "",
      token_type: resp.token_type || ""
    }, ["Displayed: tokens truncated, expires_in"]));
  }
}

/* ===================== ACTIONS ===================== */
/**
 * handleSubmit()
 * WHAT:
 * - Main sign in / sign up action for the primary form.
 * WHY:
 * - Demonstrates OAuth-like token-based auth via Firebase REST API.
 * FLOW:
 * - Validate inputs -> call signIn/signUp -> saveSession -> show modal card.
 * SESSION RULES:
 * - emailVerified is set to null initially; updated by Lookup Profile later.
 * UI:
 * - Keeps results in the modal to avoid cluttering main page.
 */
async function handleSubmit() {
  showError("");
  setLoading(true, mode === "signin" ? "Signing in…" : "Creating account…");
  try {
    const { email, password } = getEmailPasswordOrThrow();
    const resp = mode === "signin"
      ? await signIn(email, password)
      : await signUp(email, password);

    saveSession({
      idToken: resp.idToken,
      refreshToken: resp.refreshToken,
      email: resp.email,
      localId: resp.localId,
      displayName: resp.displayName || "",
      expiresIn: resp.expiresIn,
      tokenIssuedAt: Date.now(),
      emailVerified: null
    });

    renderStatus();
    renderSession();

    pushResult(makeResultCard(
      mode === "signin" ? "Sign In (accounts:signInWithPassword)" : "Sign Up (accounts:signUp)",
      {
        email: resp.email || "",
        localId: resp.localId || "",
        displayName: resp.displayName || "",
        idToken: truncateMiddle(resp.idToken || ""),
        refreshToken: truncateMiddle(resp.refreshToken || ""),
        expiresIn: resp.expiresIn || ""
      },
      ["Displayed: email, localId, tokens truncated, expiresIn"]
    ));
  } catch (e) {
    showError(e.message || "Failed API request.");
  } finally {
    setLoading(false);
  }
}

/**
 * handleForgotPassword()
 * WHAT:
 * - Sends PASSWORD_RESET email via accounts:sendOobCode.
 * WHY:
 * - Required “password reset” feature; also good for rubric/auth completeness.
 * NOTE:
 * - Uses email from main input; does not require signed-in session.
 * UI:
 * - Adds results card then opens modal for visibility.
 */
async function handleForgotPassword() {
  showError("");
  setLoading(true, "Requesting password reset…");
  try {
    const email = trimVal(elEmail);
    if (!email) throw new Error("Invalid input: Email is required.");
    if (!isValidEmail(email)) throw new Error("Invalid input: Enter a valid email.");
    if (hasInvalidCharsBasic(email)) throw new Error("Invalid input: Invalid characters detected.");
    elEmail.value = email;

    const resp = await sendOobCode({ requestType: "PASSWORD_RESET", email });

    pushResult(makeResultCard("Password Reset Email (accounts:sendOobCode)", {
      email: resp.email || email,
      message: "Password reset email requested."
    }, ["Displayed: email"]));

    openModal();
  } catch (e) {
    showError(e.message || "Failed API request.");
  } finally {
    setLoading(false);
  }
}

/**
 * handleSignOut()
 * WHAT:
 * - Local sign out (clears stored session).
 * WHY:
 * - In token-based demos, “sign out” is typically client-side cleanup.
 * NOTE:
 * - Firebase does not require server-side sign-out for JWT-style tokens.
 */
function handleSignOut() {
  showError("");
  saveSession(null);
  renderStatus();
  renderSession();
  logEvent("Signed out (local session cleared).");
}

/**
 * handleLookup()
 * WHAT:
 * - Calls accounts:lookup with current idToken to fetch user profile state.
 * WHY:
 * - Updates emailVerified, displayName, photoUrl, localId, etc.
 * TOKEN SAFETY:
 * - Calls ensureFreshIdToken() first to avoid expired-token errors.
 * SESSION UPDATE:
 * - Merges retrieved values into session so UI is accurate after lookup.
 */
async function handleLookup() {
  showError("");
  setLoading(true, "Looking up profile…");
  try {
    await ensureFreshIdToken();

    const resp = await lookupProfile(session.idToken);
    const user = resp?.users?.[0] || {};

    saveSession({
      ...session,
      email: user.email || session.email,
      localId: user.localId || session.localId,
      displayName: user.displayName || session.displayName,
      emailVerified: user.emailVerified != null ? !!user.emailVerified : session.emailVerified
    });

    pushResult(makeResultCard("Profile Lookup (accounts:lookup)", {
      email: user.email || "",
      localId: user.localId || "",
      displayName: user.displayName || "",
      photoUrl: user.photoUrl || "",
      emailVerified: user.emailVerified != null ? String(user.emailVerified) : ""
    }, ["Displayed: email, localId, displayName, photoUrl, emailVerified"]));
  } catch (e) {
    showError(e.message || "Failed API request.");
  } finally {
    setLoading(false);
  }
}

/**
 * handleUpdate()
 * WHAT:
 * - Updates displayName/photoUrl via accounts:update.
 * WHY:
 * - Demonstrates authenticated profile update.
 * TOKEN SAFETY:
 * - ensureFreshIdToken() to avoid expiry issues.
 * VALIDATION:
 * - Requires at least one of displayName/photoUrl.
 * SESSION UPDATE:
 * - Firebase may return a new idToken/refreshToken; code updates session if so.
 */
async function handleUpdate() {
  showError("");
  setLoading(true, "Updating profile…");
  try {
    await ensureFreshIdToken();
    const { displayName, photoUrl } = getProfileFieldsOrThrow();
    if (!displayName && !photoUrl) throw new Error("Invalid input: Provide Display Name or Photo URL.");

    const resp = await updateProfile(session.idToken, displayName, photoUrl);

    saveSession({
      ...session,
      idToken: resp.idToken || session.idToken,
      refreshToken: resp.refreshToken || session.refreshToken,
      email: resp.email || session.email,
      localId: resp.localId || session.localId,
      displayName: resp.displayName || displayName || session.displayName || "",
      expiresIn: resp.expiresIn || session.expiresIn,
      tokenIssuedAt: resp.idToken ? Date.now() : session.tokenIssuedAt
    });

    pushResult(makeResultCard("Update Profile (accounts:update)", {
      email: resp.email || session.email || "",
      localId: resp.localId || session.localId || "",
      displayName: resp.displayName || displayName || "",
      photoUrl: photoUrl || "",
      idToken: truncateMiddle(resp.idToken || session.idToken || ""),
      refreshToken: truncateMiddle(resp.refreshToken || session.refreshToken || ""),
      expiresIn: resp.expiresIn || session.expiresIn || ""
    }, ["Displayed: updated profile + tokens truncated"]));
  } catch (e) {
    showError(e.message || "Failed API request.");
  } finally {
    setLoading(false);
  }
}

/**
 * handleVerifyEmail()
 * WHAT:
 * - Sends a verification email using accounts:sendOobCode with requestType=VERIFY_EMAIL.
 * WHY:
 * - Common auth feature and part of your “max points” list.
 * NOTE:
 * - After user clicks the link, you typically call Lookup Profile to see emailVerified=true.
 */
async function handleVerifyEmail() {
  showError("");
  setLoading(true, "Sending verify email…");
  try {
    await ensureFreshIdToken();
    const resp = await sendOobCode({ requestType: "VERIFY_EMAIL", idToken: session.idToken });

    pushResult(makeResultCard("Verify Email (accounts:sendOobCode)", {
      email: resp.email || session.email || "",
      message: "Verify email requested. Click link in inbox, then run Lookup Profile."
    }, ["Displayed: email"]));
  } catch (e) {
    showError(e.message || "Failed API request.");
  } finally {
    setLoading(false);
  }
}

/**
 * handleRefresh()
 * WHAT:
 * - Manual token refresh button: calls securetoken /token and updates session.
 * WHY:
 * - Demonstrates refresh-token flow (grant_type=refresh_token).
 * EDGE CASE:
 * - If refreshToken is missing, shows “No results found”.
 */
async function handleRefresh() {
  showError("");
  setLoading(true, "Refreshing token…");
  try {
    if (!session?.refreshToken) throw new Error("No results found: Missing refresh token.");

    const resp = await refreshIdToken(session.refreshToken);

    saveSession({
      ...session,
      idToken: resp.id_token || session.idToken,
      refreshToken: resp.refresh_token || session.refreshToken,
      expiresIn: resp.expires_in || session.expiresIn,
      tokenIssuedAt: Date.now()
    });

    pushResult(makeResultCard("Token Refresh (securetoken /token)", {
      user_id: resp.user_id || "",
      id_token: truncateMiddle(resp.id_token || ""),
      refresh_token: truncateMiddle(resp.refresh_token || ""),
      expires_in: resp.expires_in || "",
      token_type: resp.token_type || ""
    }, ["Displayed: tokens truncated, expires_in"]));
  } catch (e) {
    showError(e.message || "Failed API request.");
  } finally {
    setLoading(false);
  }
}

/**
 * handleChangePw()
 * WHAT:
 * - Changes password using accounts:update with password field.
 * WHY:
 * - Required “Change Password” feature.
 * TOKEN SAFETY:
 * - ensureFreshIdToken() to reduce expired token failures.
 * SESSION UPDATE:
 * - Firebase often issues a new token set after password change; code stores it.
 */
async function handleChangePw() {
  showError("");
  setLoading(true, "Changing password…");
  try {
    await ensureFreshIdToken();
    const np = getNewPasswordOrThrow();

    const resp = await changePassword(session.idToken, np);

    saveSession({
      ...session,
      idToken: resp.idToken || session.idToken,
      refreshToken: resp.refreshToken || session.refreshToken,
      email: resp.email || session.email,
      localId: resp.localId || session.localId,
      expiresIn: resp.expiresIn || session.expiresIn,
      tokenIssuedAt: Date.now()
    });

    pushResult(makeResultCard("Change Password (accounts:update)", {
      email: resp.email || session.email || "",
      localId: resp.localId || session.localId || "",
      idToken: truncateMiddle(resp.idToken || session.idToken || ""),
      refreshToken: truncateMiddle(resp.refreshToken || session.refreshToken || ""),
      expiresIn: resp.expiresIn || session.expiresIn || "",
      message: "Password updated successfully."
    }, ["Displayed: email + tokens truncated"]));

    elNewPassword.value = "";
  } catch (e) {
    showError(e.message || "Failed API request.");
  } finally {
    setLoading(false);
  }
}

/**
 * handleDelete()
 * WHAT:
 * - Deletes the current account permanently via accounts:delete.
 * WHY:
 * - Required “Delete Account” feature; good for demonstrating destructive action handling.
 * SAFETY:
 * - confirm() prompt to prevent accidental deletion.
 * FLOW:
 * - If cancelled: logs and returns early (loader cleared in finally).
 * - If confirmed: ensureFreshIdToken() -> deleteAccount() -> clear session.
 */
async function handleDelete() {
  showError("");
  setLoading(true, "Deleting account…");
  try {
    requireSessionOrThrow();
    const ok = confirm("Delete this account permanently? This cannot be undone.");
    if (!ok) {
      logEvent("Delete cancelled.");
      return;
    }

    await ensureFreshIdToken();
    await deleteAccount(session.idToken);

    pushResult(makeResultCard("Delete Account (accounts:delete)", {
      message: "Account deleted successfully."
    }, ["Displayed: message"]));

    saveSession(null);
    closeModal();
    logEvent("Account deleted.");
  } catch (e) {
    showError(e.message || "Failed API request.");
  } finally {
    setLoading(false);
  }
}

/* ===================== COPY ===================== */
/**
 * copyText(text)
 * WHAT:
 * - Uses Clipboard API to copy text to clipboard.
 * WHY:
 * - Supports your “copy token buttons” feature for demos/testing.
 * EDGE CASE:
 * - Throws if text empty so UI can show a clear error.
 */
async function copyText(text) {
  if (!text) throw new Error("No results found: Nothing to copy.");
  await navigator.clipboard.writeText(text);
}

/**
 * handleCopyId()
 * WHAT:
 * - Copies current session.idToken.
 * WHY:
 * - Makes it easy to test authenticated requests elsewhere (e.g., Postman).
 */
async function handleCopyId() {
  showError("");
  try {
    requireSessionOrThrow();
    await copyText(session.idToken);
    logEvent("Copied ID token.");
  } catch (e) {
    showError(e.message || "Copy failed.");
  }
}

/**
 * handleCopyRefresh()
 * WHAT:
 * - Copies current session.refreshToken.
 * WHY:
 * - Useful for demonstrating refresh flow / debugging session persistence.
 */
async function handleCopyRefresh() {
  showError("");
  try {
    if (!session?.refreshToken) throw new Error("No results found: Missing refresh token.");
    await copyText(session.refreshToken);
    logEvent("Copied refresh token.");
  } catch (e) {
    showError(e.message || "Copy failed.");
  }
}

/* ===================== CLEAR ===================== */
/**
 * handleClearResults()
 * WHAT:
 * - Clears modal results and logs the action.
 */
function handleClearResults() {
  clearResults();
  logEvent("Results cleared.");
}

/**
 * handleClearLog()
 * WHAT:
 * - Clears stored log then re-renders.
 * IMPORTANT DETAIL:
 * - After clearing, it calls logEvent("Log cleared.") which re-adds one item.
 *   This is intentional in your current logic (it proves the clear happened).
 */
function handleClearLog() {
  logItems = [];
  localStorage.removeItem(LOG_KEY);
  renderLog();
  logEvent("Log cleared.");
}

/* ===================== EVENTS ===================== */
/**
 * Event binding section
 * WHAT:
 * - Wires UI controls to handlers.
 * WHY:
 * - Keeps all event hookups in one place for maintainability.
 */
tabSignIn.addEventListener("click", () => setMode("signin"));
tabSignUp.addEventListener("click", () => setMode("signup"));

btnSubmit.addEventListener("click", handleSubmit);
btnForgot.addEventListener("click", handleForgotPassword);

btnOpenAccount.addEventListener("click", () => openModal());
btnCloseModal.addEventListener("click", () => closeModal());
backdrop.addEventListener("click", () => closeModal());

/**
 * <dialog> cancel event fires on ESC key.
 * preventDefault() stops browser from auto-closing without our cleanup.
 */
modal.addEventListener("cancel", (e) => { e.preventDefault(); closeModal(); });

btnSignOutTop.addEventListener("click", handleSignOut);

btnLookup.addEventListener("click", handleLookup);
btnUpdate.addEventListener("click", handleUpdate);
btnVerifyEmail.addEventListener("click", handleVerifyEmail);

btnResetPw.addEventListener("click", handleForgotPassword); // same flow
btnRefresh.addEventListener("click", handleRefresh);
btnChangePw.addEventListener("click", handleChangePw);
btnDelete.addEventListener("click", handleDelete);

btnCopyIdToken.addEventListener("click", handleCopyId);
btnCopyRefreshToken.addEventListener("click", handleCopyRefresh);

btnClearResults.addEventListener("click", handleClearResults);
btnClearLog.addEventListener("click", handleClearLog);

/* ===================== INIT ===================== */
/**
 * init() IIFE
 * WHAT:
 * - Sets initial mode, renders log, pre-fills email, and starts countdown tick.
 * WHY:
 * - Guarantees UI is consistent after reload.
 * DETAILS:
 * - If API key missing: shows setup message and logs it.
 * - Starts a 1-second interval to update session countdown display.
 * NOTE:
 * - This does not auto-refresh on a timer; it auto-refreshes only before protected calls
 *   (ensureFreshIdToken) or via manual Refresh button. That is a safe and simple pattern.
 */
(function init() {
  setMode("signin");
  renderLog();

  if (session?.email) elEmail.value = session.email;

  // Session tick for countdown
  if (tickTimer) clearInterval(tickTimer);
  tickTimer = setInterval(() => renderSession(), 1000);

  if (!API_KEY || API_KEY === "YOUR_API_KEY_HERE") {
    showError("Setup required: Create config.js and set window.FIREBASE_API_KEY. Do NOT commit config.js.");
    logEvent("API key missing.");
  } else {
    logEvent("App ready.");
  }

  renderStatus();
  renderSession();
})();
