const title = document.getElementById("confirm-title");
const body = document.getElementById("confirm-body");
const actions = document.getElementById("confirm-actions");

async function run() {
  const params = new URLSearchParams(window.location.search);
  const token = params.get("token") || "";
  if (!token) {
    title.textContent = "Missing confirmation link";
    body.textContent = "This page needs a valid token from your signup.";
    actions.hidden = false;
    return;
  }

  try {
    const res = await fetch(`/api/confirm?token=${encodeURIComponent(token)}`);
    const data = await res.json();
    if (!data.ok) {
      title.textContent = "Could not confirm";
      body.textContent = data.error || "This confirmation link is invalid.";
      actions.hidden = false;
      return;
    }
    if (data.already_confirmed) {
      title.textContent = "Email already confirmed";
      body.textContent = `You’re signed in as ${data.user.name}.`;
    } else {
      title.textContent = "Email confirmed";
      body.textContent = `Welcome, ${data.user.name}. Your account is active.`;
    }
    actions.hidden = false;
  } catch (err) {
    title.textContent = "Confirmation failed";
    body.textContent = err.message || "Something went wrong.";
    actions.hidden = false;
  }
}

run();
