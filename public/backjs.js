var API = "/api";

function hideAll() {
    ["loginBox", "registerBox", "forgotBox"].forEach(function (id) {
        var el = document.getElementById(id);
        if (el) el.style.display = "none";
    });
}
function showRegister() { hideAll(); document.getElementById("registerBox").style.display = "block"; }
function showLogin()    { hideAll(); document.getElementById("loginBox").style.display    = "block"; }
function showForgot()   { hideAll(); document.getElementById("forgotBox").style.display   = "block"; }

function compressImage(dataURL, callback) {
    var img = new Image();
    img.onload = function () {
        var canvas = document.createElement("canvas");
        var MAX = 400, w = img.width, h = img.height;
        if (w > h) { if (w > MAX) { h = Math.round(h * MAX / w); w = MAX; } }
        else       { if (h > MAX) { w = Math.round(w * MAX / h); h = MAX; } }
        canvas.width = w; canvas.height = h;
        canvas.getContext("2d").drawImage(img, 0, 0, w, h);
        callback(canvas.toDataURL("image/jpeg", 0.7));
    };
    img.src = dataURL;
}

function previewPhoto(event) {
    var file = event.target.files[0];
    if (!file) return;
    if (!file.type.startsWith("image/")) {
        alert("Please select a valid image file!");
        event.target.value = "";
        return;
    }
    var reader = new FileReader();
    reader.onload = function (e) {
        compressImage(e.target.result, function (compressed) {
            sessionStorage.setItem("tempPhoto", compressed);
            document.getElementById("photoPreview").src = compressed;
            document.getElementById("photoPreviewContainer").style.display = "block";
            document.getElementById("uploadText").textContent = "✅ " + file.name;
        });
    };
    reader.readAsDataURL(file);
}

function register() {
    var payload = {
        username : document.getElementById("regUser").value.trim(),
        password : document.getElementById("regPass").value.trim(),
        email    : document.getElementById("regEmail").value.trim(),
        phone    : document.getElementById("regPhone").value.trim(),
        gender   : document.getElementById("reggender").value.trim(),
        dob      : document.getElementById("regdob").value.trim(),
        cast     : document.getElementById("regcast").value.trim(),
        salary   : document.getElementById("regsalary").value.trim(),
        fname    : document.getElementById("regfname").value.trim(),
        mname    : document.getElementById("regmname").value.trim(),
        bio      : document.getElementById("regbio").value.trim(),
        photo    : sessionStorage.getItem("tempPhoto") || ""
    };
    fetch(API + "/register", {
        method  : "POST",
        headers : { "Content-Type": "application/json" },
        body    : JSON.stringify(payload)
    })
    .then(function (res) { return res.json().then(function (d) { return { ok: res.ok, data: d }; }); })
    .then(function (r) {
        if (!r.ok) { alert(r.data.error); return; }
        sessionStorage.setItem("pendingEmail", payload.email);
        alert(r.data.message);
        document.getElementById("otpSection").style.display = "block";
        document.getElementById("otpInput").focus();
    })
    .catch(function () { alert("Network error. Is the server running?"); });
}

function verifyOTP() {
    var otp   = document.getElementById("otpInput").value.trim();
    var email = sessionStorage.getItem("pendingEmail");
    if (!email) { alert("Session expired. Please register again."); return; }
    fetch(API + "/verify-otp", {
        method  : "POST",
        headers : { "Content-Type": "application/json" },
        body    : JSON.stringify({ email: email, otp: otp })
    })
    .then(function (res) { return res.json().then(function (d) { return { ok: res.ok, data: d }; }); })
    .then(function (r) {
        if (!r.ok) { alert(r.data.error); return; }
        sessionStorage.removeItem("pendingEmail");
        sessionStorage.removeItem("tempPhoto");
        alert(r.data.message);
        showLogin();
    })
    .catch(function () { alert("Network error. Is the server running?"); });
}

function login() {
    var username = document.getElementById("logUser").value.trim();
    var password = document.getElementById("logPass").value.trim();
    if (!username || !password) { alert("Please enter both username and password!"); return; }
    fetch(API + "/login", {
        method  : "POST",
        headers : { "Content-Type": "application/json" },
        body    : JSON.stringify({ username: username, password: password })
    })
    .then(function (res) { return res.json().then(function (d) { return { ok: res.ok, data: d }; }); })
    .then(function (r) {
        if (!r.ok) { alert(r.data.error); return; }
        sessionStorage.setItem("loggedInUser", r.data.username);
        sessionStorage.setItem("isAdmin", r.data.isAdmin ? "true" : "false");
        // Redirect based on role
        if (r.data.isAdmin) {
            window.location.href = "admin.html";
        } else {
            window.location.href = "home.html";
        }
    })
    .catch(function () { alert("Network error. Is the server running?"); });
}

function sendResetOTP() {
    var username = document.getElementById("forgotUser").value.trim();
    var email    = document.getElementById("forgotEmail").value.trim();
    if (!username || !email) { alert("Please enter both username and email!"); return; }
    fetch(API + "/forgot-password", {
        method  : "POST",
        headers : { "Content-Type": "application/json" },
        body    : JSON.stringify({ username: username, email: email })
    })
    .then(function (res) { return res.json().then(function (d) { return { ok: res.ok, data: d }; }); })
    .then(function (r) {
        if (!r.ok) { alert(r.data.error); return; }
        sessionStorage.setItem("resetEmail", email);
        alert(r.data.message);
        document.getElementById("forgotOtpSection").style.display = "block";
    })
    .catch(function () { alert("Network error. Is the server running?"); });
}

function verifyResetOTP() {
    var otp         = document.getElementById("forgotOtpInput").value.trim();
    var newPassword = document.getElementById("newPass").value.trim();
    var email       = sessionStorage.getItem("resetEmail");
    if (!email)       { alert("Session expired. Please start again."); showForgot(); return; }
    if (!otp || !newPassword) { alert("Please fill in both OTP and new password!"); return; }
    fetch(API + "/reset-password", {
        method  : "POST",
        headers : { "Content-Type": "application/json" },
        body    : JSON.stringify({ email: email, otp: otp, newPassword: newPassword })
    })
    .then(function (res) { return res.json().then(function (d) { return { ok: res.ok, data: d }; }); })
    .then(function (r) {
        if (!r.ok) { alert(r.data.error); return; }
        sessionStorage.removeItem("resetEmail");
        alert(r.data.message);
        showLogin();
    })
    .catch(function () { alert("Network error. Is the server running?"); });
}

function logout() {
    sessionStorage.clear();
    window.location.href = "login.html";
}
