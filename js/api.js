async function apiFetch(endpoint, options = {}) {
    const url = endpoint.startsWith('http') ? endpoint : `${API_BASE_URL}${endpoint}`;
    try {
        return await fetch(url, options);
    } catch (error) {
        if (error.message.includes('Failed to fetch')) {
            showNotification('El servidor despertando... espera un momento ⏳', 'info');
        }
        throw error;
    }
}

function getFullUrl(path) {
    if (!path) return '';
    if (path.startsWith('http')) return path;
    return `${API_BASE_URL}${path.startsWith('/') ? '' : '/'}${path}`;
}

async function fetchWithAuth(url, options = {}) {
    if (authToken) {
        options.headers = {
            ...options.headers,
            'Authorization': `Bearer ${authToken}`
        };
    }
    const response = await apiFetch(url, options);
    if (response.status === 401) {
        logout();
        openLoginModal();
        throw new Error('Sesión expirada');
    }
    return response;
}

// Funciones de Puntos Personalizados (API)
async function loadCustomPointsFromServer() {
    try {
        const response = await apiFetch('/api/v1/points');
        customPoints = await response.json();
        if (typeof filterCustomPoints === 'function') {
            filterCustomPoints();
        } else {
            renderCustomPoints();
        }
        updateSavedPointsList();
        updateCloudUI(true);
    } catch (error) {
        console.error('❌ Error cargando desde el servidor:', error);
        updateCloudUI(false);
    }
}

async function savePointToServer(pointData) {
    try {
        const response = await fetchWithAuth('/api/v1/points', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(pointData)
        });
        return response.ok;
    } catch (error) {
        console.error('❌ Error guardando en el servidor:', error);
        return false;
    }
}

async function deletePointFromServer(pointId) {
    try {
        const id = (typeof pointId === 'object') ? pointId.id : pointId;
        const response = await fetchWithAuth(`/api/v1/points/${id}`, {
            method: 'DELETE'
        });
        return response.ok;
    } catch (error) {
        console.error('❌ Error eliminando del servidor:', error);
        return false;
    }
}

async function likePoint(id, btn) {
    if (!authToken) { showNotification('Inicia sesión para dar Like ❤️', 'info'); return; }
    if (localStorage.getItem('liked_' + id)) { showNotification('Ya te gusta este punto.', 'info'); return; }

    try {
        const res = await fetchWithAuth(`/api/v1/points/${id}/like`, { method: 'POST' });
        if (res.ok) {
            const countSpan = btn.querySelector('.like-count');
            countSpan.textContent = parseInt(countSpan.textContent) + 1;
            btn.classList.add('liked');
            localStorage.setItem('liked_' + id, 'true');
            showNotification('¡Te gusta este punto!', 'success');
        }
    } catch (e) { console.error(e); }
}

async function loadComments(id) {
    const list = document.getElementById(`comments-list-${id}`);
    try {
        const res = await apiFetch(`/api/v1/points/${id}/comments`);
        const data = await res.json();
        if (data.length === 0) {
            list.innerHTML = '<p style="opacity:0.4; text-align:center; padding:10px;">Sin comentarios aún.</p>';
            return;
        }
        list.innerHTML = data.map(c => `
            <div class="comment-item" style="margin-bottom:6px; background:rgba(255,255,255,0.05); padding:6px; border-radius:5px;">
                <b style="color:#F6C453; font-size:9px;">${c.user_name}:</b>
                <span style="font-size:10px;">${c.content}</span>
                <div style="font-size:8px; opacity:0.4; margin-top:2px;">${new Date(c.timestamp).toLocaleString()}</div>
            </div>
        `).join('');
    } catch (e) { list.innerHTML = 'Error al cargar.'; }
}

async function sendComment(id) {
    if (!authToken) { showNotification('Inicia sesión para comentar 💬', 'info'); return; }
    const input = document.getElementById(`comment-input-${id}`);
    const content = input.value.trim();
    if (!content) return;

    try {
        const res = await fetchWithAuth(`/api/v1/points/${id}/comments`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content })
        });
        if (res.ok) {
            input.value = '';
            loadComments(id);
            showNotification('Comentario enviado.', 'success');
        }
    } catch (e) { showNotification('Error al enviar comentario.', 'error'); }
}

async function handleFileUpload(input) {
    if (!input.files || !input.files[0]) return;
    const status = document.getElementById('upload-status');
    status.textContent = 'Subiendo imagen...';
    status.style.color = '#F6C453';

    const formData = new FormData();
    formData.append('file', input.files[0]);

    try {
        const res = await fetchWithAuth('/api/v1/upload', {
            method: 'POST',
            body: formData
        });
        if (res.ok) {
            const data = await res.json();
            document.getElementById('point-image').value = data.url;
            status.textContent = '✅ Subida con éxito';
            status.style.color = '#10b981';
            showNotification('Imagen cargada correctamente.', 'success');
        } else {
            status.textContent = '❌ Error al subir';
            status.style.color = '#ef4444';
        }
    } catch (e) {
        status.textContent = '❌ Error de conexión';
        status.style.color = '#ef4444';
    }
}
async function fetchReverseGeocode(lat, lng) {
    const addrInput = document.getElementById('point-address');
    if (!addrInput) return;
    addrInput.value = "Obteniendo dirección...";
    try {
        const response = await fetch(`https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=${lat}&lon=${lng}`, {
            headers: { 'User-Agent': 'MapaInteractivaUV/1.0' }
        });
        const data = await response.json();
        addrInput.value = (data && data.display_name) ? data.display_name : "Dirección no encontrada";
    } catch (error) {
        addrInput.value = "";
    }
}

async function saveCustomPoint(event) {
    if (event) event.preventDefault();
    const pointData = {
        name: document.getElementById('point-name').value,
        category: document.getElementById('point-category').value,
        subcategory: document.getElementById('point-subcategory').value,
        description: document.getElementById('point-description').value,
        address: document.getElementById('point-address').value,
        lat: parseFloat(document.getElementById('point-lat').value),
        lng: parseFloat(document.getElementById('point-lng').value),
        image_url: document.getElementById('point-image').value
    };

    // Bug fix: detectar si estamos editando un punto existente → PUT en lugar de POST
    if (currentEditingPoint && currentEditingPoint.id) {
        try {
            const response = await fetchWithAuth(`/api/v1/points/${currentEditingPoint.id}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(pointData)
            });
            if (response && response.ok) {
                showNotification('Punto actualizado correctamente ✏️', 'success');
                await loadCustomPointsFromServer();
                closeMarkerPanel();
            } else {
                showNotification('Error al actualizar el punto.', 'error');
            }
        } catch (e) {
            console.error('Error PUT:', e);
            showNotification('Error de conexión al actualizar.', 'error');
        }
    } else {
        // Nuevo punto → POST
        const success = await savePointToServer(pointData);
        if (success) {
            showNotification('Punto guardado en el servidor 🚀', 'success');
            await loadCustomPointsFromServer();
            closeMarkerPanel();
        } else {
            showNotification('Error al guardar en el servidor.', 'error');
        }
    }
}

window.deleteCustomPoint = async function (pointId) {
    const point = customPoints.find(p => String(p.id) === String(pointId));
    if (!point) return;
    if (confirm(`¿Eliminar "${point.name}" de tu base de datos?`)) {
        const success = await deletePointFromServer(pointId);
        if (success) {
            showNotification('Punto eliminado del servidor', 'success');
            await loadCustomPointsFromServer();
            if (currentEditingPoint && String(currentEditingPoint.id) === String(pointId)) closeMarkerPanel();
        } else {
            showNotification('Error al eliminar del servidor', 'error');
        }
    }
};

// --- API DE CAPAS ESPECIALES ---
async function uploadLayerToServer(formData) {
    try {
        const response = await fetchWithAuth('/api/v1/layers/upload', {
            method: 'POST',
            body: formData
        });
        return await response.json();
    } catch (error) {
        console.error('❌ Error subiendo capa:', error);
        return { status: 'error' };
    }
}

async function fetchLayersFromServer() {
    try {
        const response = await apiFetch('/api/v1/layers');
        return await response.json();
    } catch (error) {
        console.error('❌ Error obteniendo capas:', error);
        return { layers: [] };
    }
}

window.saveCustomPoint = saveCustomPoint;
