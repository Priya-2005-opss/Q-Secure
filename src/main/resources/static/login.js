
async function secureFetch(url, options = {}) {
    const method = (options.method || "GET").toUpperCase();
    const headers = new Headers(options.headers || {});

    if (!["GET", "HEAD", "OPTIONS", "TRACE"].includes(method)) {
        const tokenResponse = await fetch("/api/auth/csrf", {
            method: "GET",
            credentials: "same-origin",
            cache: "no-store"
        });

        if (!tokenResponse.ok) {
            throw new Error("Unable to obtain CSRF security token.");
        }

        const csrfData = await tokenResponse.json();
        headers.set("X-CSRF-TOKEN", csrfData.token);
    }

    return fetch(url, {
        ...options,
        headers,
        credentials: "same-origin"
    });
}

const loginTab = document.getElementById("loginTab");
const registerTab = document.getElementById("registerTab");
const loginForm = document.getElementById("loginForm");
const registerForm = document.getElementById("registerForm");
const message = document.getElementById("message");

loginTab.addEventListener("click", () => {
    loginForm.classList.remove("hidden");
    registerForm.classList.add("hidden");
    loginTab.classList.add("active");
    registerTab.classList.remove("active");
    message.textContent = "";
});

registerTab.addEventListener("click", () => {
    registerForm.classList.remove("hidden");
    loginForm.classList.add("hidden");
    registerTab.classList.add("active");
    loginTab.classList.remove("active");
    message.textContent = "";
});

registerForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const data = {
        fullName: document.getElementById("fullName").value.trim(),
        email: document.getElementById("registerEmail").value.trim(),
        password: document.getElementById("registerPassword").value
    };

    try {
        const response = await secureFetch("/api/auth/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data)
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.message || result.error || "Registration failed");
        }

        message.textContent = "Registration successful! Please login.";
        message.style.color = "#36df9b";
        registerForm.reset();
        loginTab.click();
        document.getElementById("loginEmail").value = data.email;

    } catch (error) {
        message.textContent = error.message;
        message.style.color = "#ff7373";
    }
});

loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const data = {
        email: document.getElementById("loginEmail").value.trim(),
        password: document.getElementById("loginPassword").value
    };

    try {
        const response = await secureFetch("/api/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data)
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.message || result.error || "Login failed");
        }

        window.location.href = "/index.html";

    } catch (error) {
        message.textContent = error.message;
        message.style.color = "#ff7373";
    }
});
