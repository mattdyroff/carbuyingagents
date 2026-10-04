const form = document.getElementById("search-form");
const statusEl = document.getElementById("status");
const resultsEl = document.getElementById("results");
const goBtn = document.getElementById("go");
const accountBtn = document.getElementById("account-btn");
const signoutBtn = document.getElementById("signout-btn");
const accountLabel = document.getElementById("account-label");
const authModal = document.getElementById("auth-modal");
const authForms = document.getElementById("auth-forms");
const checkEmail = document.getElementById("check-email");
const signupForm = document.getElementById("signup-form");
const loginForm = document.getElementById("login-form");
const signupError = document.getElementById("signup-error");
const loginError = document.getElementById("login-error");
const pendingEmail = document.getElementById("pending-email");
const confirmLink = document.getElementById("confirm-link");

let currentUser = null;

function money(n) {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 0,
  }).format(n);
}

function miles(n) {
  if (n == null || n === "") return "Mileage not listed";
  return `${new Intl.NumberFormat("en-US").format(n)} miles`;
}

function setStatus(text, kind) {
  statusEl.textContent = text;
  statusEl.className = "status" + (kind ? ` ${kind}` : "");
}

function renderListings(listings) {
  resultsEl.innerHTML = "";
  if (!listings.length) {
    resultsEl.innerHTML = `<div class="empty">No dealer listings in that range. Try a wider budget or a different ZIP.</div>`;
    return;
  }
  for (const car of listings) {
    const el = document.createElement("article");
    el.className = "listing";
    const title = document.createElement("h2");
    title.textContent = car.name;
    const price = document.createElement("p");
    price.className = "price";
    price.textContent = money(car.price);
    const meta = document.createElement("p");
    meta.className = "meta";
    const dealer = car.dealer || "Dealer";
    const city = car.city || car.location || "";
    meta.textContent = `${miles(car.mileage)} · ${dealer}${city ? ` · ${city}` : ""}`;
    const link = document.createElement("a");
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.href = car.url;
    link.textContent = "View listing";
    el.append(title, price, meta);
    const lines = [];
    if (car.payment) lines.push(car.payment);
    if (car.recalls) lines.push(car.recalls);
    if (car.crash_rating) lines.push(car.crash_rating);
    if (car.mpg) lines.push(car.mpg);
    if (Array.isArray(car.notes)) {
      for (const note of car.notes) {
        if (note) lines.push(note);
      }
    }
    for (const text of lines) {
      const detail = document.createElement("p");
      detail.className = "detail";
      detail.textContent = text;
      el.appendChild(detail);
    }
    el.append(link);
    resultsEl.appendChild(el);
  }
}

function setAuthError(el, message) {
  if (!message) {
    el.hidden = true;
    el.textContent = "";
    return;
  }
  el.hidden = false;
  el.textContent = message;
}

function updateAccountUI() {
  if (currentUser) {
    accountLabel.hidden = false;
    accountLabel.textContent = currentUser.name;
    accountBtn.hidden = true;
    signoutBtn.hidden = false;
  } else {
    accountLabel.hidden = true;
    accountLabel.textContent = "";
    accountBtn.hidden = false;
    signoutBtn.hidden = true;
  }
}

function showAuthModal(tab = "signup") {
  authModal.hidden = false;
  authForms.hidden = false;
  checkEmail.hidden = true;
  setAuthError(signupError, "");
  setAuthError(loginError, "");
  switchAuthTab(tab);
  document.body.style.overflow = "hidden";
}

function hideAuthModal() {
  authModal.hidden = true;
  document.body.style.overflow = "";
}

function showCheckEmail(email, confirmUrl) {
  authForms.hidden = true;
  checkEmail.hidden = false;
  pendingEmail.textContent = email;
  confirmLink.href = confirmUrl;
  confirmLink.textContent = confirmUrl.startsWith("http")
    ? confirmUrl
    : `${window.location.origin}${confirmUrl}`;
  authModal.hidden = false;
  document.body.style.overflow = "hidden";
}

function switchAuthTab(tab) {
  const tabs = document.querySelectorAll("[data-auth-tab]");
  tabs.forEach((btn) => {
    const active = btn.dataset.authTab === tab;
    btn.classList.toggle("is-active", active);
    btn.setAttribute("aria-selected", active ? "true" : "false");
  });
  signupForm.hidden = tab !== "signup";
  loginForm.hidden = tab !== "login";
}

async function refreshMe() {
  try {
    const res = await fetch("/api/me");
    const data = await res.json();
    currentUser = data.user || null;
  } catch {
    currentUser = null;
  }
  updateAccountUI();
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(form);
  const minRaw = String(fd.get("min") || "").trim();
  const maxRaw = String(fd.get("budget") || "").trim();
  const params = new URLSearchParams({
    budget: maxRaw,
    zip: String(fd.get("zip") || ""),
    body: String(fd.get("body") || ""),
  });
  if (minRaw !== "") {
    const minN = Number(minRaw);
    const maxN = Number(maxRaw);
    if (!Number.isInteger(minN) || minN < 0) {
      setStatus("Enter a min budget in whole dollars.", "error");
      resultsEl.innerHTML = "";
      return;
    }
    if (Number.isInteger(maxN) && minN > maxN) {
      setStatus("Min budget can't be higher than max budget.", "error");
      resultsEl.innerHTML = "";
      return;
    }
    params.set("min", String(minN));
  }

  goBtn.disabled = true;
  setStatus("Searching dealer lots…");
  resultsEl.innerHTML = "";

  try {
    const res = await fetch(`/api/search?${params.toString()}`);
    const data = await res.json();
    if (!data.ok) {
      setStatus(data.error || "Search failed.", "error");
      renderListings([]);
      return;
    }
    const n = data.listings.length;
    setStatus(data.note || `Found ${n} dealer listing${n === 1 ? "" : "s"}.`, "ok");
    renderListings(data.listings);
  } catch (err) {
    setStatus(`Search failed: ${err.message}`, "error");
  } finally {
    goBtn.disabled = false;
  }
});

accountBtn.addEventListener("click", () => showAuthModal("signup"));
signoutBtn.addEventListener("click", async () => {
  await fetch("/api/logout", { method: "POST" });
  currentUser = null;
  updateAccountUI();
});

document.querySelectorAll("[data-close-auth]").forEach((el) => {
  el.addEventListener("click", hideAuthModal);
});

document.querySelectorAll("[data-auth-tab]").forEach((btn) => {
  btn.addEventListener("click", () => {
    setAuthError(signupError, "");
    setAuthError(loginError, "");
    switchAuthTab(btn.dataset.authTab);
  });
});

signupForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  setAuthError(signupError, "");
  const fd = new FormData(signupForm);
  const payload = {
    name: String(fd.get("name") || "").trim(),
    email: String(fd.get("email") || "").trim(),
    password: String(fd.get("password") || ""),
  };
  try {
    const res = await fetch("/api/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!data.ok) {
      setAuthError(signupError, data.error || "Could not create account.");
      return;
    }
    signupForm.reset();
    showCheckEmail(data.email, data.confirm_url);
  } catch (err) {
    setAuthError(signupError, err.message || "Could not create account.");
  }
});

loginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  setAuthError(loginError, "");
  const fd = new FormData(loginForm);
  const payload = {
    email: String(fd.get("email") || "").trim(),
    password: String(fd.get("password") || ""),
  };
  try {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (data.needs_confirmation) {
      showCheckEmail(data.email, data.confirm_url);
      return;
    }
    if (!data.ok) {
      setAuthError(loginError, data.error || "Could not sign in.");
      return;
    }
    currentUser = data.user;
    updateAccountUI();
    hideAuthModal();
    loginForm.reset();
  } catch (err) {
    setAuthError(loginError, err.message || "Could not sign in.");
  }
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !authModal.hidden) hideAuthModal();
});

refreshMe();
