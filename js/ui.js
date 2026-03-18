function spawnParticles() {
    const container = document.getElementById('particle-container');
    if (!container) return;
    for (let i = 0; i < 25; i++) {
        const p = document.createElement('div');
        p.className = 'particle';
        const size = Math.random() * 8 + 4;
        p.style.width = size + 'px';
        p.style.height = size + 'px';
        p.style.left = Math.random() * 100 + 'vw';
        p.style.animationDelay = Math.random() * 15 + 's';
        p.style.animationDuration = (Math.random() * 10 + 10) + 's';
        p.style.opacity = Math.random() * 0.5 + 0.2;
        container.appendChild(p);
    }
}

// Inicialización de objeto UI al inicio para evitar errores de referencia
window.ui = {
    openLayersModal: async function () {
        document.getElementById('modal-layers').classList.remove('hidden');
        if (typeof authToken !== 'undefined' && authToken) {
            const uploadSection = document.getElementById('layer-upload-section');
            if (uploadSection) uploadSection.classList.remove('hidden');
        }
        this.loadLayers();
    },

    openManualModal: function () {
        document.getElementById('modal-manual').classList.remove('hidden');
    },

    closeManualModal: function () {
        document.getElementById('modal-manual').classList.add('hidden');
    },

    openMetadataModal: function () {
        document.getElementById('modal-metadata').classList.remove('hidden');
    },

    closeMetadataModal: function () {
        document.getElementById('modal-metadata').classList.add('hidden');
    },

    closeLayersModal: function () {
        document.getElementById('modal-layers').classList.add('hidden');
    },

    openPasswordModal: function () {
        document.getElementById('modal-password').classList.remove('hidden');
    },

    closePasswordModal: function () {
        document.getElementById('modal-password').classList.add('hidden');
        const form = document.getElementById('form-change-password');
        if (form) form.reset();
    },

    // El resto de métodos se añaden abajo...
};
const ui = window.ui;
// currentChart se declara globalmente en config.js

function showNotification(message, type = 'info') {
    let container = document.getElementById('notification-toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'notification-toast-container';
        container.className = 'fixed bottom-5 right-5 z-[9999] flex flex-col gap-3 pointer-events-none';
        document.body.appendChild(container);
    }
    const toast = document.createElement('div');
    const colors = {
        success: 'from-[#00c853] to-[#b2ff59] border-[#b2ff59]',
        error: 'from-[#ff1744] to-[#f44336] border-[#ff1744]',
        info: 'from-[#1e3c72] to-[#2a5298] border-[#2a5298]'
    };
    toast.className = `p-4 rounded-2xl shadow-2xl border-l-4 bg-gradient-to-r ${colors[type] || colors.info} text-white font-bold text-sm min-w-[300px] flex items-center gap-3 animate-slide-in-right backdrop-blur-md bg-opacity-90 pointer-events-auto`;
    const icon = type === 'success' ? 'fa-check-circle' : (type === 'error' ? 'fa-exclamation-triangle' : 'fa-info-circle');
    toast.innerHTML = `<i class="fas ${icon} text-xl"></i> <span>${message}</span>`;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100px)';
        toast.style.transition = '0.5s';
        setTimeout(() => toast.remove(), 500);
    }, 4000);
}

function updateCloudUI(online) {
    const statusNode = document.querySelector('.status span');
    if (statusNode) {
        statusNode.textContent = online ? 'Servidor Python Online' : 'Servidor Offline';
    }
}

function abrirPanel(titulo, contenido, pointId = null) {
    document.getElementById('info-title').innerHTML = titulo;
    document.getElementById('info-content').innerHTML = contenido;
    document.getElementById('info-panel').classList.remove('hidden');
}

function setActiveBtn(id) {
    document.querySelectorAll('.map-control-btn').forEach(b => b.classList.remove('active'));
    const btn = document.getElementById(id);
    if (btn) btn.classList.add('active');
}

function actualizarLeyenda(tipo, data = null) {
    const node = document.getElementById('map-legend');
    if (!node) return;
    let content = "";
    let p = data;

    if (tipo === 'nacional') {
        content = `<b>Nacional</b><br><span class="legend-color-box" style="background:black"></span> Polígono Nacional`;
        if (!p && typeof poblacion !== 'undefined') p = poblacion.nacional;
    } else if (tipo === 'estatal') {
        content = `<b>Estatal</b><br><span class="legend-color-box" style="background:#006847"></span> Veracruz`;
        if (!p && typeof poblacion !== 'undefined') p = poblacion.veracruz;
    } else if (tipo === 'municipios') {
        content = `<b>Población Municipal</b><br>
            <div class="legend-item"><span class="legend-color-box" style="background:#bd0026"></span> +500,000</div>
            <div class="legend-item"><span class="legend-color-box" style="background:#f03b20"></span> 250,000 - 500,000</div>
            <div class="legend-item"><span class="legend-color-box" style="background:#fd8d3c"></span> 100,000 - 250,000</div>
            <div class="legend-item"><span class="legend-color-box" style="background:#feb24c"></span> 50,000 - 100,000</div>
            <div class="legend-item"><span class="legend-color-box" style="background:#fed976"></span> 25,000 - 50,000</div>
            <div class="legend-item"><span class="legend-color-box" style="background:#ffeda0"></span> 10,000 - 25,000</div>
            <div class="legend-item"><span class="legend-color-box" style="background:#ffffcc"></span> < 10,000</div>`;
    } else if (tipo === 'regiones_uv') {
        content = `<b>Regiones UV</b><br>`;
        const uvColors = {
            'Poza Rica-Tuxpan': '#F59E0B',
            'Xalapa': '#3B82F6',
            'Veracruz': '#EF4444',
            'Orizaba-Córdoba': '#10B981',
            'Coatzacoalcos-Minatitlán': '#8B5CF6'
        };
        Object.keys(uvColors).forEach(k => {
            content += `<div style="margin-top:6px"><span class="legend-color-box" style="background:${uvColors[k]}"></span> ${k}</div>`;
        });
    }

    if (p && p.POB1) {
        const nombre = p.NOMGEO || (tipo === 'estatal' ? 'Veracruz' : 'México');
        content += `
            <div style="margin-top: 10px; padding-top: 10px; border-top: 1px solid rgba(255,255,255,0.1); font-size: 10px; line-height: 1.4; opacity: 0.9;">
                <div style="color:#F6C453; font-weight:bold; margin-bottom:4px; text-transform:uppercase;">${nombre}</div>
                Población Total: <b style="color:#fff">${p.POB1.toLocaleString()}</b><br>
                Población Hombres: <b style="color:#3B82F6">${(p.POB84 || 0).toLocaleString()}</b><br>
                Población Mujeres: <b style="color:#F472B6">${(p.POB42 || 0).toLocaleString()}</b>
            </div>
        `;
    }
    node.innerHTML = content;
}

function toggleFacultades(regionName) {
    const safeId = regionName.replace(/\s+/g, '-');
    const list = document.getElementById('list-' + safeId);
    const btn = document.getElementById('btn-region-' + safeId);
    const isAbierto = list && list.classList.contains('open');
    document.querySelectorAll('.uv-facultades-list').forEach(l => l.classList.remove('open'));
    document.querySelectorAll('.uv-region-btn').forEach(b => b.classList.remove('active'));
    if (!isAbierto && list) {
        list.classList.add('open');
        if (btn) btn.classList.add('active');
    }
}

function mostrarDetalleFacultad(facultad) {
    abrirPanel("Facultad", `<h3 class="text-lg font-bold text-[#F6C453] mb-2">${facultad}</h3><p class="text-sm">Detalles por cargar.</p>`);
}

function toggleMarkerMode() {
    markerModeActive = !markerModeActive;
    const btn = document.getElementById('marker-mode-toggle');
    if (markerModeActive) {
        try { highlightLayer.clearLayers(); } catch (e) { }
        if (highlightLabel) { try { map.removeLayer(highlightLabel); } catch (e) { }; highlightLabel = null; }
        if (map.hasLayer(layers.municipios)) layers.municipios.setStyle({ fillOpacity: 0.05, weight: 0.5 });
        map.closePopup();
        btn.classList.add('active');
        btn.querySelector('span').textContent = 'Modo Activo - Haz clic en el mapa';
        map.getContainer().style.cursor = 'crosshair';
        map.on('click', onMapClickForMarker);
        showNotification('Modo marcado activo. Haz clic en el mapa para situar un punto.', 'info');
    } else {
        if (map.hasLayer(layers.municipios)) layers.municipios.setStyle({ fillOpacity: 0.18, weight: 1 });
        btn.classList.remove('active');
        btn.querySelector('span').textContent = 'Marcar Puntos Personalizados';
        map.getContainer().style.cursor = '';
        map.off('click', onMapClickForMarker);
        if (tempMarker) { map.removeLayer(tempMarker); tempMarker = null; }
    }
}

function openMarkerPanel(lat, lng, existingPoint = null) {
    const panel = document.getElementById('point-marker-panel');
    panel.classList.add('active');
    document.getElementById('point-lat').value = lat.toFixed(6);
    document.getElementById('point-lng').value = lng.toFixed(6);
    document.getElementById('coord-dms').textContent = `DMS: ${toDMS(lat, true)} | ${toDMS(lng, false)}`;
    document.getElementById('coord-utm').textContent = `UTM: ${toUTM(lat, lng)}`;

    if (existingPoint) {
        currentEditingPoint = existingPoint;
        document.getElementById('point-name').value = existingPoint.name;
        document.getElementById('point-category').value = existingPoint.category;
        updateSubcategories(existingPoint.subcategory || '');
        document.getElementById('point-description').value = existingPoint.description || '';
        document.getElementById('point-address').value = existingPoint.address || '';
        document.getElementById('point-image').value = existingPoint.image_url || '';
        document.getElementById('delete-button-container').style.display = 'block';
        panel.querySelector('h2').innerHTML = '<i class="fas fa-edit"></i> Editar Punto';
    } else {
        currentEditingPoint = null;
        document.getElementById('point-form').reset();
        document.getElementById('point-lat').value = lat.toFixed(6);
        document.getElementById('point-lng').value = lng.toFixed(6);
        document.getElementById('delete-button-container').style.display = 'none';
        panel.querySelector('h2').innerHTML = '<i class="fas fa-map-pin"></i> Punto Personalizado';
        fetchReverseGeocode(lat, lng);
    }
}

function closeMarkerPanel() {
    document.getElementById('point-marker-panel').classList.remove('active');
    document.getElementById('point-form').reset();
    currentEditingPoint = null;
    if (tempMarker) { map.removeLayer(tempMarker); tempMarker = null; }
}

function updateSubcategories(selectedSub = '') {
    const category = document.getElementById('point-category').value;
    const subDropdown = document.getElementById('point-subcategory');
    if (!subDropdown) return;
    subDropdown.innerHTML = '<option value="">Selecciona</option>';
    if (category && subcategoriesMap[category]) {
        subDropdown.disabled = false;
        subcategoriesMap[category].forEach(sub => {
            const option = document.createElement('option');
            option.value = sub.toLowerCase();
            option.textContent = sub;
            if (sub.toLowerCase() === selectedSub.toLowerCase()) option.selected = true;
            subDropdown.appendChild(option);
        });
    } else {
        subDropdown.disabled = true;
    }
}

function updateSavedPointsList() {
    const list = document.getElementById('saved-points-list');
    const count = document.getElementById('saved-points-count');
    if (count) count.textContent = customPoints.length;
    if (!list) return;
    if (customPoints.length === 0) {
        list.innerHTML = '<p class="text-center opacity-50">No hay puntos</p>';
        return;
    }
    list.innerHTML = customPoints.map(p => {
        const iconClass = categoryIcons[p.category] || 'fa-map-pin';
        const color = categoryColors[p.category] || '#CCC';
        const displayName = (typeof categoryNames !== 'undefined' && categoryNames[p.category]) ? categoryNames[p.category] : p.category;
        return `
        <div class="saved-point-item flex items-center gap-3" onclick="map.setView([${p.lat}, ${p.lng}], 16)">
            <div style="background: ${color}; width: 30px; height: 30px; border-radius: 50%; display: flex; align-items: center; justify-content: center; shrink-0">
                <i class="fas ${iconClass}" style="color: white; font-size: 14px;"></i>
            </div>
            <div>
                <h4>${p.name}</h4>
                <p>${displayName}</p>
            </div>
        </div>
        `;
    }).join('');
}

function setupCategoryFilters() {
    const container = document.getElementById('category-checkboxes');
    if (!container) return;
    container.innerHTML = `
        <div class="flex gap-2 mb-3">
            <button onclick="toggleAllCategories(true)" class="text-[10px] px-3 py-1 bg-white/10 border border-white/20 rounded hover:bg-white/20 transition-colors">Todos</button>
            <button onclick="toggleAllCategories(false)" class="text-[10px] px-3 py-1 bg-white/10 border border-white/20 rounded hover:bg-white/20 transition-colors">Ninguno</button>
        </div>
    `;
    Object.keys(categoryColors).forEach(cat => {
        const iconClass = categoryIcons[cat] || 'fa-map-pin';
        const color = categoryColors[cat];
        const displayName = categoryNames[cat] || cat;
        const div = document.createElement('div');
        div.className = 'flex items-center gap-2 mb-2 text-[12px] font-semibold text-white/90 hover:bg-white/5 p-1 rounded transition-colors';
        div.innerHTML = `
            <input type="checkbox" id="filter-${cat}" onchange="filterCustomPoints()" class="rounded border-white/30 bg-black/20 text-[#F6C453] focus:ring-[#F6C453] cursor-pointer">
            <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background-color: ${color}; flex-shrink: 0;" class="shadow-sm"></span>
            <div style="width: 16px; text-align: center; color: rgba(255,255,255,0.8);"><i class="fas ${iconClass}"></i></div>
            <label for="filter-${cat}" class="cursor-pointer flex-1 select-none">${displayName}</label>
        `;
        container.appendChild(div);
    });
}

function toggleAllCategories(checked) {
    Object.keys(categoryColors).forEach(cat => {
        const cb = document.getElementById(`filter-${cat}`);
        if (cb) cb.checked = checked;
    });
    filterCustomPoints();
}

function filterCustomPoints() {
    const query = document.getElementById('point-search-input').value.toLowerCase();
    const activeCategories = Object.keys(categoryColors).filter(cat => {
        const cb = document.getElementById(`filter-${cat}`);
        return cb ? cb.checked : true;
    });
    const filtered = customPoints.filter(p => p.name.toLowerCase().includes(query) && activeCategories.includes(p.category));
    renderCustomPoints(filtered);
}

function openAdminTable() {
    document.getElementById('admin-modal').classList.remove('hidden');
    fillAdminTable(customPoints);
}

function closeAdminTable() {
    document.getElementById('admin-modal').classList.add('hidden');
}

function fillAdminTable(data) {
    const tbody = document.getElementById('admin-table-body');
    if (!tbody) return;
    tbody.innerHTML = data.map(p => `
        <tr>
            <td class="p-4">${p.id}</td>
            <td class="p-4">${p.name}</td>
            <td class="p-4">${p.category}</td>
            <td class="p-4">${p.lat.toFixed(4)}, ${p.lng.toFixed(4)}</td>
            <td class="p-4"><button onclick="map.setView([${p.lat}, ${p.lng}], 16); closeAdminTable();">📍</button></td>
        </tr>
    `).join('');
}
function toDMS(dd, isLat) {
    const absDd = Math.abs(dd);
    const deg = Math.floor(absDd);
    const min = Math.floor((absDd - deg) * 60);
    const sec = ((absDd - deg - min / 60) * 3600).toFixed(2);
    let dir = isLat ? (dd >= 0 ? "N" : "S") : (dd >= 0 ? "E" : "W");
    return `${deg}° ${min}' ${sec}" ${dir}`;
}

function toUTM(lat, lon) {
    const zone = Math.floor((lon + 180) / 6) + 1;
    const letter = lat > 0 ? 'Q' : 'K';
    return `Zona ${zone}${letter} | Lat: ${lat.toFixed(4)}, Lon: ${lon.toFixed(4)}`;
}

function normalizar(txt) {
    if (!txt) return '';
    return txt.normalize('NFD').replace(/[\u0300-\u036f]/g, "").toLowerCase();
}

function getCategoryLabel(cat) {
    const labels = {
        'comercio': '🏪 Comercio',
        'oficina': '🏢 Oficina',
        'educacion': '🎓 Educación',
        'salud': '🏥 Salud',
        'recreacion': '🎯 Recreación',
        'transporte': '🚌 Transporte',
        'gobierno': '🏛️ Gobierno',
        'otro': '📍 Otro'
    };
    return labels[cat] || cat;
}

function focusOnPoint(id) {
    const p = customPoints.find(x => x.id === id);
    if (p) { map.setView([p.lat, p.lng], 16); }
}

function zoomToPoint(id) {
    const p = customPoints.find(p => p.id === id);
    if (p) {
        map.setView([p.lat, p.lng], 16);
        closeAdminTable();
        // Buscar el marcador en la capa y abrir su popup
        customPointsLayer.eachLayer(layer => {
            if (layer.getLatLng && layer.getLatLng().lat === p.lat && layer.getLatLng().lng === p.lng) {
                layer.openPopup();
            }
        });
    }
}

function filterAdminTable() {
    const query = document.getElementById('admin-search').value.toLowerCase();
    const filtered = customPoints.filter(p =>
        p.name.toLowerCase().includes(query) ||
        p.category.toLowerCase().includes(query) ||
        (p.description && p.description.toLowerCase().includes(query)) ||
        (p.address && p.address.toLowerCase().includes(query))
    );
    fillAdminTable(filtered);
}

function clearMunicipioFilter() {
    const input = document.getElementById('search-input');
    const clearBtn = document.getElementById('clear-search');
    if (input) input.value = '';
    if (clearBtn) clearBtn.style.display = 'none';
    try { highlightLayer.clearLayers(); } catch (e) { }
    if (highlightLabel) {
        try { map.removeLayer(highlightLabel); } catch (e) { }
        highlightLabel = null;
    }
    try { map.setView([19.17, -96.13], 7); } catch (e) { }
}

function mostrarInfoRegionUV(nombre) {
    const data = uvRegionsData[nombre];
    if (!data) return;
    abrirPanel("Región: " + nombre, `
        <p class="mb-2 text-sm">Sede de importantes facultades.</p>
        <p class="text-[11px] mb-2"><b>Campus Principal:</b> Varios</p>
        <p class="text-[10px] opacity-70">Selecciona una facultad del menú para más detalles.</p>
    `);
}

function editCustomPoint(pointId) {
    const point = customPoints.find(p => String(p.id) === String(pointId));
    if (point) openMarkerPanel(point.lat, point.lng, point);
}

async function toggleComments(id) {
    const section = document.getElementById(`comments-section-${id}`);
    if (!section) return;
    section.classList.toggle('hidden');
    if (!section.classList.contains('hidden')) {
        loadComments(id);
    }
}

function mostrarInfoMunicipio(cve, nombre) {
    if (typeof poblacion === 'undefined' || !poblacion.municipios) {
        console.warn("Datos de población no cargados aún.");
        return;
    }

    // Normalización para búsqueda robusta (sin acentos, mayúsculas, trim)
    const normalize = str => str.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toUpperCase().trim();
    const searchName = normalize(nombre);
    const p = poblacion.municipios.find(x => normalize(x.NOMGEO) === searchName);

    actualizarLeyenda('municipios', p);

    if (p) {
        // Mostrar el panel lateral y poner el título
        document.getElementById('info-title').innerHTML = `<i class="fas fa-chart-pie text-[#F6C453]"></i> ${nombre}`;
        document.getElementById('info-panel').classList.remove('hidden');

        const panel = document.getElementById('info-content');
        if (!panel) return;

        panel.innerHTML = `
            <div class="mb-4 animate-fade-in">
                <p class="text-[10px] uppercase tracking-widest text-[#F6C453] mb-1 font-bold opacity-80">Demografía Municipal</p>
                <h3 class="text-xl font-black mb-4 text-white">${nombre}</h3>
                
                <div class="bg-gradient-to-br from-white/10 to-white/5 rounded-2xl p-4 mb-5 border border-white/10 shadow-inner">
                    <p class="text-[10px] uppercase opacity-50 mb-1 font-bold">Población Total (Hab)</p>
                    <p class="text-3xl font-black text-white">${(p.POB1 || 0).toLocaleString()}</p>
                </div>

                <div class="relative h-64 w-full bg-black/20 rounded-2xl border border-white/5 p-2 mb-5">
                    <canvas id="poblacionChart"></canvas>
                </div>

                <div class="grid grid-cols-2 gap-3 text-[10px]">
                    <div class="bg-blue-500/10 p-3 rounded-xl border border-blue-500/20 text-center group hover:bg-blue-500/20 transition-all">
                        <p class="opacity-50 uppercase mb-1 font-bold">Hombres</p>
                        <p class="text-base font-black text-blue-300">${(p.POB84 || 0).toLocaleString()}</p>
                        <p class="text-[12px] font-bold text-blue-300 mt-1">${((p.POB84 / p.POB1) * 100).toFixed(1)}%</p>
                    </div>
                    <div class="bg-pink-500/10 p-3 rounded-xl border border-pink-500/20 text-center group hover:bg-pink-500/20 transition-all">
                        <p class="opacity-50 uppercase mb-1 font-bold">Mujeres</p>
                        <p class="text-base font-black text-pink-300">${(p.POB42 || 0).toLocaleString()}</p>
                        <p class="text-[12px] font-bold text-pink-300 mt-1">${((p.POB42 / p.POB1) * 100).toFixed(1)}%</p>
                    </div>
                </div>
            </div>
        `;

        if (currentChart) {
            currentChart.destroy();
            currentChart = null;
        }

        setTimeout(() => {
            const canvas = document.getElementById('poblacionChart');
            if (canvas) {
                currentChart = ui.renderMunicipioChart(canvas, p, false);
            }
        }, 100);
    } else {
        abrirPanel("Municipio: " + nombre, `
            <div class="p-4 bg-white/5 rounded-xl border border-white/10 italic opacity-70">
                Información demográfica detallada no disponible para esta entidad en el censo actual.
            </div>
        `);
    }
}

// Nueva función unificada para renderizar el gráfico tipo PASTEL/PIE
ui.renderMunicipioChart = function (ctx, data, isMini = false) {
    if (!ctx) return null;
    if (typeof Chart === 'undefined') {
        console.error("Chart.js no está cargado");
        return null;
    }

    try {
        const config = {
            type: 'pie',
            data: {
                labels: ['Hombres', 'Mujeres'],
                datasets: [{
                    data: [data.POB84 || 0, data.POB42 || 0],
                    backgroundColor: [
                        'rgba(59, 130, 246, 0.85)', // Blue
                        'rgba(244, 114, 182, 0.85)'  // Pink
                    ],
                    borderColor: '#1a2a6c',
                    borderWidth: 2,
                    hoverOffset: 12
                }]
            },
            options: {
                responsive: true,
                layout: { 
                    padding: isMini ? 10 : 2 
                },
                plugins: {
                    legend: {
                        position: 'bottom',
                        display: !isMini,
                        labels: {
                            color: '#fff',
                            padding: 10,
                            font: { size: 10, weight: 'bold' },
                            usePointStyle: true
                        }
                    },
                    tooltip: {
                        enabled: true,
                        backgroundColor: 'rgba(0,0,0,0.95)',
                        titleColor: '#F6C453',
                        bodyColor: '#fff',
                        padding: 8,
                        cornerRadius: 8,
                        displayColors: true,
                        borderColor: 'rgba(246, 196, 83, 0.5)',
                        borderWidth: 1,
                        caretSize: 6,
                        callbacks: {
                            label: function (context) {
                                const val = context.raw || 0;
                                const total = data.POB1 || (data.POB84 + data.POB42) || 1;
                                const perc = ((val / total) * 100).toFixed(1);
                                return ` ${context.label}: ${val.toLocaleString()} (${perc}%)`;
                            }
                        }
                    }
                }
            }
        };
        return new Chart(ctx, config);
    } catch (e) {
        console.error("Error creating chart:", e);
        return null;
    }
};

function setupSearchListeners() {
    const input = document.getElementById('search-input');
    const results = document.getElementById('search-results');
    if (!input || !results) return;

    input.addEventListener('input', () => {
        const q = normalizar(input.value.trim());
        if (q.length < 2) { results.classList.add('hidden'); results.innerHTML = ''; return; }
        const matches = municipiosIndex.filter(m => normalizar(m.nombre).includes(q)).slice(0, 30);
        if (matches.length === 0) {
            results.innerHTML = `<li class="p-2 text-gray-500">Sin resultados</li>`;
            results.classList.remove('hidden');
            return;
        }
        results.innerHTML = matches.map(m => `<li class="p-2 cursor-pointer hover:bg-white/10" data-cve="${m.cve}">${m.nombre}</li>`).join('');
        results.classList.remove('hidden');
    });

    results.addEventListener('click', e => {
        const cve = e.target.dataset.cve;
        if (!cve) return;
        const item = municipiosIndex.find(x => x.cve === cve);
        if (!item) return;

        try { highlightLayer.clearLayers(); } catch (e) { }
        if (highlightLabel) { try { map.removeLayer(highlightLabel); } catch (e) { }; highlightLabel = null; }

        let feature = municipalGeoJSON ? municipalGeoJSON.features.find(f => f.properties.CVEGEO === cve) : null;
        if (feature) {
            highlightLayer.addData(feature);
            
            // Etiqueta flotante solo para este municipio seleccionado
            highlightLayer.eachLayer(layer => {
                layer.bindTooltip(item.nombre, {
                    permanent: false,
                    direction: 'center',
                    className: 'custom-municipio-tooltip',
                    sticky: true
                });
            });

            applyGlowToLayer(highlightLayer);
            const bounds = L.geoJSON(feature).getBounds();
            try { map.flyToBounds(bounds, { padding: [40, 40], duration: 1.0 }); } catch (e) { map.fitBounds(bounds); }
            mostrarInfoMunicipio(item.cve, item.nombre);
        }
        input.value = item.nombre;
        results.classList.add('hidden');
        const clearBtn = document.getElementById('clear-search');
        if (clearBtn) clearBtn.style.display = 'block';
        if (!map.hasLayer(layers.municipios)) layers.municipios.addTo(map);
    });
}

// Métodos adicionales de UI
Object.assign(ui, {
    openLayersModal: async function () {
        document.getElementById('modal-layers').classList.remove('hidden');
        if (typeof authToken !== 'undefined' && authToken) {
            const uploadSection = document.getElementById('layer-upload-section');
            if (uploadSection) uploadSection.classList.remove('hidden');
        }
        this.loadLayers();
    },

    openManualModal: function () {
        document.getElementById('modal-manual').classList.remove('hidden');
    },

    closeManualModal: function () {
        document.getElementById('modal-manual').classList.add('hidden');
    },

    openMetadataModal: function () {
        document.getElementById('modal-metadata').classList.remove('hidden');
    },

    closeMetadataModal: function () {
        document.getElementById('modal-metadata').classList.add('hidden');
    },

    closeLayersModal: function () {
        document.getElementById('modal-layers').classList.add('hidden');
    },

    loadLayers: async function () {
        const list = document.getElementById('layers-list');
        if (!list) return;
        list.innerHTML = '<p class="text-center py-4 animate-pulse text-white/60 text-xs">Consultando S3...</p>';

        const data = await fetchLayersFromServer();
        if (!data.layers || data.layers.length === 0) {
            list.innerHTML = '<p class="text-center text-white/40 py-8 italic text-xs">No hay capas subidas aún.</p>';
            return;
        }

        list.innerHTML = data.layers.map(layer => {
            const icon = layer.file_type === 'shp' ? 'fa-file-zipper' : (layer.file_type === 'csv' ? 'fa-file-csv' : 'fa-file-code');
            const isActive = window.mapLayers && window.mapLayers[layer.id] ? 'bg-[#F6C453] text-[#1a2a6c]' : 'bg-white/10 text-white';
            const currentUsername = (localStorage.getItem('sig_username') || '').toLowerCase();
            const isAdmin = (localStorage.getItem('sig_role') || '').toLowerCase() === 'admin' || currentUsername === 'admin' || currentUsername === 'angel.arguello';
            const canDelete = (currentUsername === (layer.created_by || '').toLowerCase() || isAdmin);

            return `
                <div class="flex flex-col gap-2 p-4 rounded-2xl bg-white/5 border border-white/10 hover:bg-white/10 transition-all relative group">
                    <div class="flex items-center justify-between">
                        <div class="flex items-center gap-3">
                            <div class="w-10 h-10 rounded-full flex items-center justify-center bg-black/30">
                                <i class="fas ${icon} text-[#F6C453]"></i>
                            </div>
                            <div class="text-left">
                                <h4 class="font-bold text-sm text-white">${layer.name}</h4>
                                <p class="text-[10px] opacity-60 uppercase">${layer.file_type} • ${new Date(layer.created_at).toLocaleDateString()}</p>
                            </div>
                        </div>
                        <div class="flex items-center gap-2">
                            <button onclick="ui.toggleLayer('${layer.id}', '${layer.url}', '${layer.file_type}')" 
                                class="px-4 py-1.5 rounded-full text-[10px] font-bold transition-all ${isActive}">
                                ${window.mapLayers && window.mapLayers[layer.id] ? 'QUITAR' : 'VISUALIZAR'}
                            </button>
                            ${canDelete ? `
                                <button onclick="ui.deleteLayer('${layer.id}', '${layer.name}')" 
                                    class="w-8 h-8 rounded-full bg-red-500/20 text-red-500 hover:bg-red-500 hover:text-white transition-all flex items-center justify-center"
                                    title="Eliminar capa">
                                    <i class="fas fa-trash-can text-[10px]"></i>
                                </button>
                            ` : ''}
                        </div>
                    </div>
                    
                    ${window.mapLayers && window.mapLayers[layer.id] ? `
                        <div class="flex items-center gap-2 mt-1 px-1">
                            <i class="fas fa-eye-low-beam text-[10px] opacity-50 text-white"></i>
                            <input type="range" min="0" max="1" step="0.1" value="${window.mapLayers[layer.id].options ? (window.mapLayers[layer.id].options.fillOpacity || 0.4) : 0.4}" 
                                oninput="ui.updateLayerOpacity('${layer.id}', this.value)"
                                class="flex-1 h-1 bg-white/10 rounded-lg appearance-none cursor-pointer accent-[#F6C453]">
                            <i class="fas fa-eye text-[10px] opacity-50 text-white"></i>
                        </div>
                    ` : ''}
                </div>
            `;
        }).join('');
    },

    updateLayerOpacity: function (id, val) {
        if (window.mapLayers && window.mapLayers[id]) {
            const layer = window.mapLayers[id];
            val = parseFloat(val);
            if (layer.setStyle) {
                layer.setStyle({ fillOpacity: val, opacity: val });
            }
        }
    },

    handleLayerFileSelect: function (input) {
        const label = document.getElementById('layer-file-label');
        if (input.files && input.files[0] && label) {
            label.textContent = input.files[0].name;
            label.classList.add('text-[#F6C453]');
        }
    },

    toggleLayer: async function (id, url, type) {
        if (!window.mapLayers) window.mapLayers = {};

        if (window.mapLayers[id]) {
            map.removeLayer(window.mapLayers[id]);
            delete window.mapLayers[id];
            showNotification('Capa removida del mapa', 'info');
        } else {
            showNotification('Procesando capa... por favor espera', 'info');
            const layer = await loadAndShowLayer(id, url, type);
            if (layer) {
                window.mapLayers[id] = layer;
                showNotification('¡Capa visualizada con éxito!', 'success');
            } else {
                showNotification('No se pudo procesar esta capa.', 'error');
            }
        }
        this.loadLayers(); // Refrescar botones
    },

    deleteLayer: async function (id, name) {
        if (!confirm(`¿Estás seguro de que deseas eliminar la capa "${name}"? Esta acción no se puede deshacer.`)) {
            return;
        }

        try {
            const res = await fetchWithAuth(`/api/v1/layers/${id}`, {
                method: 'DELETE'
            });

            if (res.ok) {
                // Quitar del mapa si está activa
                if (window.mapLayers && window.mapLayers[id]) {
                    map.removeLayer(window.mapLayers[id]);
                    delete window.mapLayers[id];
                }
                showNotification('Capa eliminada con éxito', 'success');
                this.loadLayers();
            } else {
                const err = await res.json();
                showNotification(`Error: ${err.detail || 'No se pudo eliminar la capa'}`, 'error');
            }
        } catch (error) {
            console.error('Error deleting layer:', error);
            showNotification('Error de conexión al eliminar la capa', 'error');
        }
    },

});

// Listener para el formulario de subida
document.addEventListener('DOMContentLoaded', () => {
    setTimeout(() => {
        const form = document.getElementById('form-upload-layer');
        if (form) {
            form.onsubmit = async (e) => {
                e.preventDefault();
                const btn = form.querySelector('button[type="submit"]');
                const oldText = btn.innerHTML;
                btn.disabled = true;
                btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> SUBIENDO A AMAZON S3...';

                const formData = new FormData();
                formData.append('file', document.getElementById('layer-file').files[0]);
                formData.append('name', document.getElementById('layer-name').value);
                formData.append('description', document.getElementById('layer-desc').value);

                const res = await uploadLayerToServer(formData);
                if (res.status === 'success') {
                    showNotification('Capa guardada correctamente en la nube', 'success');
                    form.reset();
                    const fileLabel = document.getElementById('layer-file-label');
                    if (fileLabel) fileLabel.textContent = 'Seleccionar Archivo';
                    ui.loadLayers();
                } else {
                    showNotification('Error al subir el archivo.', 'error');
                }
                btn.disabled = false;
                btn.innerHTML = oldText;
            };
        }
        const passForm = document.getElementById('form-change-password');
        if (passForm) {
            passForm.onsubmit = async (e) => {
                e.preventDefault();
                const oldPass = document.getElementById('old-pass').value;
                const newPass = document.getElementById('new-pass').value;
                const confPass = document.getElementById('confirm-new-pass').value;

                if (newPass !== confPass) {
                    showNotification('Las nuevas contraseñas no coinciden', 'error');
                    return;
                }

                if (newPass.length < 6) {
                    showNotification('La nueva contraseña debe tener al menos 6 caracteres', 'warning');
                    return;
                }

                const btn = passForm.querySelector('button[type="submit"]');
                const originalText = btn.textContent;
                btn.disabled = true;
                btn.textContent = 'ACTUALIZANDO...';

                const success = await changePassword(oldPass, newPass);
                
                btn.disabled = false;
                btn.textContent = originalText;
                
                if (success) {
                    passForm.reset();
                }
            };
        }
    }, 1000);
});

// Exponer función demográfica en window.ui para que map.js pueda llamarla
ui.mostrarInfoMunicipio = mostrarInfoMunicipio;
window.ui = ui;
