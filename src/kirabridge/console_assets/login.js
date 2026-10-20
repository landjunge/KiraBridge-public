"use strict";
const login = document.getElementById("login");
try {
  localStorage.setItem("kirabridge.session", login.dataset.session);
  window.location.replace("/");
} catch (_) {
  login.textContent = "Bitte erlaube lokale Browserdaten für 127.0.0.1 und öffne KiraBridge erneut über den Schreibtisch.";
}
