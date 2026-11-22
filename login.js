const form = document.getElementById("loginForm");
const passwordInput = document.getElementById("password");
const submitButton = document.getElementById("submitLogin");
const result = document.getElementById("loginResult");

function showMessage(message, isError) {
  result.textContent = message;
  result.classList.toggle("error", Boolean(isError));
  result.classList.remove("hidden");
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!passwordInput.value) {
    showMessage("Enter the dashboard password.", true);
    return;
  }

  submitButton.disabled = true;
  result.classList.add("hidden");

  try {
    const response = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: passwordInput.value })
    });
    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      passwordInput.value = "";
      showMessage(data.error || "Sign-in failed.", true);
      return;
    }

    passwordInput.value = "";
    window.location.href = "/";
  } catch {
    showMessage("Could not reach the PhishWatch server.", true);
  } finally {
    submitButton.disabled = false;
  }
});

passwordInput.focus();
