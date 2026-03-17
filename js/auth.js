let authToken = localStorage.getItem('sig_token') || null;
let currentUser = localStorage.getItem('sig_user') || null;
let authMode = 'login';

function openLoginModal() {
    const modal = document.getElementById('login-modal');
    if (modal) modal.style.display = 'flex';
}

function closeLoginModal() {
    const modal = document.getElementById('login-modal');
    if (modal) modal.style.display = 'none';
}

async function login(username, password) {
    try {
        const formData = new FormData();
        formData.append('username', username);
        formData.append('password', password);

        console.log('🚀 Intentando login para:', username);
        const response = await apiFetch('/api/v1/auth/login', {
            method: 'POST',
            body: formData
        });

        if (response.ok) {
            const data = await response.json();
            authToken = data.access_token;

            currentUser = (data.user && data.user.full_name) ? data.user.full_name : username;
            const role = (data.user && data.user.role) ? data.user.role : 'user';

            localStorage.setItem('sig_token', authToken);
            localStorage.setItem('sig_user', currentUser);
            localStorage.setItem('sig_username', data.user.username || username);
            localStorage.setItem('sig_role', role);

            console.log('✅ Login exitoso:', currentUser);
            closeLoginModal();

            updateAuthUI();
            showNotification(`¡Hola, ${currentUser}! Bienvenido al SIG.`, 'success');
            loadCustomPointsFromServer();
            // Refrescar panel de capas si existe la función
            if (window.ui && window.ui.loadLayers) window.ui.loadLayers();
        } else {
            const error = await response.json();
            showNotification(error.detail || 'Credenciales incorrectas', 'error');
        }
    } catch (e) {
        console.error('❌ Error en login:', e);
        showNotification('Error de conexión con el servidor', 'error');
    }
}

function logout() {
    authToken = null;
    currentUser = null;
    localStorage.removeItem('sig_token');
    localStorage.removeItem('sig_user');
    localStorage.removeItem('sig_username');
    localStorage.removeItem('sig_role');
    localStorage.removeItem('sig_picture');
    updateAuthUI();
    showNotification('Sesión cerrada', 'info');
}

function updateAuthUI() {
    try {
        const loginBtn = document.getElementById('login-btn');
        const loggedInView = document.getElementById('user-logged-in');

        if (authToken) {
            if (loginBtn) loginBtn.classList.add('hidden');
            if (loggedInView) {
                loggedInView.classList.remove('hidden');
                loggedInView.style.display = 'flex';

                const displayName = currentUser || localStorage.getItem('sig_user') || 'Usuario';
                const displaySpan = document.getElementById('username-display');
                if (displaySpan) displaySpan.textContent = displayName;
            }

            const adminBtn = document.getElementById('admin-panel-btn');
            const userRole = localStorage.getItem('sig_role');
            const userLogin = localStorage.getItem('sig_username');
            
            if (userLogin === 'admin' || userRole === 'admin') {
                if (adminBtn) adminBtn.classList.remove('hidden');
            } else {
                if (adminBtn) adminBtn.classList.add('hidden');
            }
        } else {
            if (loginBtn) loginBtn.classList.remove('hidden');
            if (loggedInView) {
                loggedInView.classList.add('hidden');
                loggedInView.style.display = 'none';
            }
            const adminBtn = document.getElementById('admin-panel-btn');
            if (adminBtn) adminBtn.classList.add('hidden');
        }
    } catch (err) {
        console.error('❌ Error en updateAuthUI:', err);
    }
}

async function register(username, password, full_name, email, university) {
    try {
        const response = await apiFetch('/api/v1/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, full_name, email, university })
        });

        if (response.ok) {
            showNotification('¡Cuenta creada! Ahora inicia sesión.', 'success');
            setAuthMode('login');
        } else {
            const error = await response.json();
            showNotification(error.detail || 'Error al registrar', 'error');
        }
    } catch (e) {
        showNotification('Error de conexión', 'error');
    }
}

async function handleGoogleLogin(response) {
    try {
        const res = await apiFetch('/api/v1/auth/google', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: response.credential })
        });
        if (res.ok) {
            const data = await res.json();
            authToken = data.access_token;
            currentUser = data.user.full_name;
            const picture = data.user.picture || null;

            localStorage.setItem('sig_token', authToken);
            localStorage.setItem('sig_user', currentUser);
            localStorage.setItem('sig_role', data.user.role || 'user');
            if (picture) localStorage.setItem('sig_picture', picture);

            updateAuthUI();
            closeLoginModal();
            showNotification(`¡Bienvenido, ${currentUser}! (Google)`, 'success');
            loadCustomPointsFromServer();
        } else {
            const errorData = await res.json();
            showNotification(errorData.detail || 'Error al validar cuenta de Google', 'error');
        }
    } catch (e) {
        showNotification('Error de conexión con Google', 'error');
    }
}

function initGoogleAuth() {
    if (typeof google !== 'undefined') {
        google.accounts.id.initialize({
            client_id: "481357191308-c06t135ahrb8nnk1vq6nfo0bcqn33cdl.apps.googleusercontent.com",
            callback: handleGoogleLogin,
            auto_select: false
        });
        const googleBtn = document.getElementById("google-btn");
        if (googleBtn) {
            google.accounts.id.renderButton(
                googleBtn,
                {
                    theme: "outline",
                    size: "large",
                    text: "signin_with",
                    shape: "rectangular",
                    locale: "es",
                    logo_alignment: "left",
                    width: "320"
                }
            );
        }
    }
}

function setAuthMode(mode) {
    authMode = mode;
    const title = document.getElementById('auth-title');
    const submitBtn = document.getElementById('auth-submit-btn');
    const tabLogin = document.getElementById('tab-login');
    const tabRegister = document.getElementById('tab-register');
    const regFields = document.getElementById('register-only-fields');

    if (mode === 'login') {
        if (title) title.textContent = 'Acceso Administrativo';
        if (submitBtn) submitBtn.textContent = 'INGRESAR AL SIG';
        if (tabLogin) tabLogin.className = 'flex-1 py-3 font-bold text-[#F6C453] border-b-2 border-[#F6C453] bg-white/5';
        if (tabRegister) tabRegister.className = 'flex-1 py-3 font-bold text-white/40 border-b-2 border-transparent';
        if (regFields) regFields.classList.add('hidden');
    } else {
        if (title) title.textContent = 'Crear Perfil SIG';
        if (submitBtn) submitBtn.textContent = 'COMPLETAR REGISTRO';
        if (tabLogin) tabLogin.className = 'flex-1 py-3 font-bold text-white/40 border-b-2 border-transparent';
        if (tabRegister) tabRegister.className = 'flex-1 py-3 font-bold text-[#F6C453] border-b-2 border-[#F6C453] bg-white/5';
        if (regFields) regFields.classList.remove('hidden');
    }
}

async function handleAuth(event) {
    if (event) {
        if (event.preventDefault) event.preventDefault();
        if (event.stopPropagation) event.stopPropagation();
    }

    const btn = document.getElementById('auth-submit-btn');
    const u = document.getElementById('auth-user');
    const p = document.getElementById('auth-pass');

    if (!u || !p) return console.error('Campos no encontrados');

    if (authMode === 'login') {
        if (btn) {
            btn.textContent = 'VALIDANDO...';
            btn.disabled = true;
        }

        try {
            await login(u.value, p.value);
        } catch (e) {
            console.error('Login Error:', e);
            showNotification('Error de sistema', 'error');
        } finally {
            if (btn) {
                btn.textContent = 'INGRESAR AL SIG';
                btn.disabled = false;
            }
        }
    } else {
        const fn = document.getElementById('reg-fullname').value;
        const em = document.getElementById('reg-email').value;
        const un = document.getElementById('reg-uni').value;
        await register(u.value, p.value, fn, em, un);
    }
}

async function changePassword(old_password, new_password) {
    try {
        const response = await apiFetch('/api/v1/auth/change-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ old_password, new_password })
        });

        if (response.ok) {
            showNotification('Contraseña actualizada con éxito', 'success');
            if (window.ui) window.ui.closePasswordModal();
            return true;
        } else {
            const error = await response.json();
            showNotification(error.detail || 'Error al cambiar contraseña', 'error');
            return false;
        }
    } catch (e) {
        showNotification('Error de conexión', 'error');
        return false;
    }
}

window.handleAuth = handleAuth;
window.changePassword = changePassword;
