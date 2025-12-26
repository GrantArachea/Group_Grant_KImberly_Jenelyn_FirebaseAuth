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
============================================================ */

/* ===================== CONFIG ===================== */
const API_KEY = (window.FIREBASE_API_KEY || "").trim();
const ID_TOOLKIT_BASE = "https://identitytoolkit.googleapis.com/v1";
const SECURE_TOKEN_BASE = "https://securetoken.googleapis.com/v1";

const SESSION_KEY = "firebaseauth.session.v3";
const LOG_KEY = "firebaseauth.log.v2";
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
let mode = "signin"; // signin | signup
let session = loadSession(); // {idToken, refreshToken, email, localId, displayName, expiresIn, tokenIssuedAt, emailVerified}
let logItems = loadLog();
let tickTimer = null;

/* ===================== UI ===================== */
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

function showError(message) {
  elErrorBox.style.display = message ? "block" : "none";
  elErrorBox.textContent = message || "";
}

function setMode(nextMode) {
  mode = nextMode;
  const isSignIn = mode === "signin";

  tabSignIn.classList.toggle("isActive", isSignIn);
  tabSignUp.classList.toggle("isActive", !isSignIn);

  tabSignIn.setAttribute("aria-selected", String(isSignIn));
  tabSignUp.setAttribute("aria-selected", String(!isSignIn));

  btnSubmit.textContent = isSignIn ? "Sign in" : "Create account";
}

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

function truncateMiddle(str, head = 18, tail = 10) {
  if (!str) return "";
  if (str.length <= head + tail + 3) return str;
  return `${str.slice(0, head)}…${str.slice(-tail)}`;
}

function secondsToMs(secStr) {
  const n = Number(secStr);
  return Number.isFinite(n) ? n * 1000 : 0;
}

function getExpiresAtMs(sess) {
  if (!sess?.tokenIssuedAt || !sess?.expiresIn) return 0;
  return sess.tokenIssuedAt + secondsToMs(sess.expiresIn);
}

function getRemainingMs(sess) {
  const exp = getExpiresAtMs(sess);
  if (!exp) return 0;
  return Math.max(0, exp - Date.now());
}

function formatRemaining(ms) {
  const s = Math.floor(ms / 1000);
  const mm = String(Math.floor(s / 60)).padStart(2, "0");
  const ss = String(s % 60).padStart(2, "0");
  return `${mm}:${ss}`;
}

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

function logEvent(message) {
  const item = { t: Date.now(), msg: message };
  logItems.unshift(item);
  logItems = logItems.slice(0, 20);
  localStorage.setItem(LOG_KEY, JSON.stringify(logItems));
  renderLog();
}

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

function openModal() {
  backdrop.style.display = "block";
  backdrop.setAttribute("aria-hidden", "false");
  modal.showModal();
}

function closeModal() {
  modal.close();
  backdrop.style.display = "none";
  backdrop.setAttribute("aria-hidden", "true");
}

/* ===================== STORAGE ===================== */
function saveSession(next) {
  session = next || null;
  if (!session) localStorage.removeItem(SESSION_KEY);
  else localStorage.setItem(SESSION_KEY, JSON.stringify(session));

  renderStatus();
  renderSession();
}

function loadSession() {
  try {
    const raw = localStorage.getItem(SESSION_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function loadLog() {
  try {
    const raw = localStorage.getItem(LOG_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

/* ===================== VALIDATION ===================== */
function ensureApiKeyOrThrow() {
  if (!API_KEY || API_KEY === "YOUR_API_KEY_HERE") {
    throw new Error("Missing API key. Create config.js and set window.FIREBASE_API_KEY. Do NOT commit config.js.");
  }
}

function trimVal(el) { return (el.value || "").trim(); }

function isValidEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }

function hasInvalidCharsBasic(str) { return /[\u0000-\u001F\u007F]/.test(str); }

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

function getNewPasswordOrThrow() {
  const np = trimVal(elNewPassword);
  if (!np) throw new Error("Invalid input: New Password is required.");
  if (np.length < 6) throw new Error("Invalid input: New Password must be at least 6 characters.");
  if (hasInvalidCharsBasic(np)) throw new Error("Invalid input: Detected invalid control characters.");
  elNewPassword.value = np;
  return np;
}

function requireSessionOrThrow() {
  if (!session || !session.idToken) throw new Error("No results found: You are signed out. Sign in first.");
}

/* ===================== API CORE ===================== */
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

function pushResult(card) {
  elEmpty.style.display = "none";
  elResults.prepend(card);
}

function clearResults() {
  elResults.innerHTML = "";
  elEmpty.style.display = "block";
}

/* ===================== AUTO TOKEN REFRESH ===================== */
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

    // minimal results card goes to modal only (clean main UI)
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

    // Put this in results modal
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

function handleSignOut() {
  showError("");
  saveSession(null);
  renderStatus();
  renderSession();
  logEvent("Signed out (local session cleared).");
}

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
async function copyText(text) {
  if (!text) throw new Error("No results found: Nothing to copy.");
  await navigator.clipboard.writeText(text);
}

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
function handleClearResults() {
  clearResults();
  logEvent("Results cleared.");
}

function handleClearLog() {
  logItems = [];
  localStorage.removeItem(LOG_KEY);
  renderLog();
  logEvent("Log cleared.");
}

/* ===================== EVENTS ===================== */
tabSignIn.addEventListener("click", () => setMode("signin"));
tabSignUp.addEventListener("click", () => setMode("signup"));

btnSubmit.addEventListener("click", handleSubmit);
btnForgot.addEventListener("click", handleForgotPassword);

btnOpenAccount.addEventListener("click", () => openModal());
btnCloseModal.addEventListener("click", () => closeModal());
backdrop.addEventListener("click", () => closeModal());
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
