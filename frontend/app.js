let currentUser = null;

document.addEventListener("DOMContentLoaded", async () => {
    document.getElementById("loginButton").addEventListener("click", login);
    document.getElementById("logoutButton").addEventListener("click", logout);
    document.getElementById("refreshButton").addEventListener("click", loadTasks);
    document.getElementById("getTaskButton").addEventListener("click", manualGetTask);
    document.getElementById("deleteTaskButton").addEventListener("click", manualDeleteTask);
    document.getElementById("searchButton").addEventListener("click", searchTasks);
    document.getElementById("deleteUserButton").addEventListener("click", deleteUser);

    await loadCurrentUser();
    loadMessageFromUrl();
});


async function loadCurrentUser() {
    const response = await fetch("/api/me");

    if (!response.ok) {
        showLogin();
        return;
    }

    const data = await response.json();
    currentUser = data.user;

    showDashboard();
    await loadTasks();
}


async function login() {
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;

    const response = await fetch("/api/login", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({username, password})
    });

    const data = await response.json();

    if (!response.ok) {
        document.getElementById("loginMessage").textContent = data.error;
        return;
    }

    currentUser = data.user;
    showDashboard();
    await loadTasks();
}


async function logout() {
    await fetch("/api/logout", {method: "POST"});
    currentUser = null;
    showLogin();
}


function showLogin() {
    document.getElementById("loginPanel").classList.remove("hidden");
    document.getElementById("dashboard").classList.add("hidden");
    document.getElementById("userArea").classList.add("hidden");
}


function showDashboard() {
    document.getElementById("loginPanel").classList.add("hidden");
    document.getElementById("dashboard").classList.remove("hidden");
    document.getElementById("userArea").classList.remove("hidden");

    document.getElementById("userName").textContent =
        currentUser.username;

    document.getElementById("userRole").textContent =
        currentUser.role;
}


async function loadTasks() {
    const response = await fetch("/api/tasks");
    const tasks = await response.json();

    const table = document.getElementById("taskTable");
    table.innerHTML = "";

    tasks.forEach(task => {
        const row = document.createElement("tr");

        row.innerHTML = `
            <td>${task.id}</td>
            <td>${task.owner_id}</td>
            <td>${escapeHtml(task.title)}</td>
            <td>
                <button class="secondary-button"
                    onclick="selectTask(${task.id})">
                    Select
                </button>
            </td>
        `;

        table.appendChild(row);
    });
}


function selectTask(taskId) {
    document.getElementById("testTaskId").value = taskId;
}


async function manualGetTask() {
    const taskId = document.getElementById("testTaskId").value;

    const response = await fetch(`/api/tasks/${taskId}`);
    const body = await response.text();

    document.getElementById("testOutput").textContent =
        `GET /api/tasks/${taskId}\n\nHTTP ${response.status}\n\n${body}`;
}


async function manualDeleteTask() {
    const taskId = document.getElementById("testTaskId").value;

    const response = await fetch(`/api/tasks/${taskId}`, {
        method: "DELETE"
    });

    const body = await response.text();

    document.getElementById("testOutput").textContent =
        `DELETE /api/tasks/${taskId}\n\nHTTP ${response.status}\n\n${body}`;

    await loadTasks();
}


async function searchTasks() {
    const searchTerm = document.getElementById("searchTerm").value;

    const response = await fetch(
        `/api/tasks/search?q=${encodeURIComponent(searchTerm)}`
    );

    const body = await response.text();

    document.getElementById("searchOutput").textContent =
        `GET /api/tasks/search?q=${searchTerm}\n\n` +
        `HTTP ${response.status}\n\n${body}`;
}


async function deleteUser() {
    const userId = document.getElementById("deleteUserId").value;

    const response = await fetch(`/api/users/${userId}`, {
        method: "DELETE"
    });

    const body = await response.text();

    document.getElementById("userOutput").textContent =
        `DELETE /api/users/${userId}\n\nHTTP ${response.status}\n\n${body}`;
}


function loadMessageFromUrl() {
    const message =
        new URLSearchParams(window.location.search).get("message");

    if (!message) {
        return;
    }

    // DAST / Manual PT ISSUE: DOM XSS.
    //
    // CORRECT:
    // document.getElementById("loginMessage").textContent = message;

    document.getElementById("loginMessage").innerHTML =
        "Message: " + message;
}


function escapeHtml(value) {
    const div = document.createElement("div");
    div.textContent = value;
    return div.innerHTML;
}
