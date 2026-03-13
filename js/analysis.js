const analysis = {
    heatmapLayer: null,
    bufferLayer: L.layerGroup(),
    measureLayer: L.layerGroup(),
    currentMeasure: null,
    activeTool: null,

    // Desactivar cualquier herramienta activa antes de iniciar otra
    deactivateTools: function () {
        map.off('click');
        map.off('dblclick');
        map.doubleClickZoom.enable();
        map.getContainer().style.cursor = '';
        window.pipMode = false;
        window.analysisMode = false;

        // Reset visual de botones
        document.querySelectorAll('.analysis-btn-active').forEach(b => b.classList.remove('analysis-btn-active'));
    },

    // --- MAPA DE CALOR ---
    toggleHeatmap: function () {
        if (this.heatmapLayer) {
            map.removeLayer(this.heatmapLayer);
            this.heatmapLayer = null;
            document.getElementById('btn-heatmap').classList.remove('bg-orange-500/40');
            showNotification('Mapa de calor desactivado', 'info');
            return;
        }

        const points = [];
        if (typeof customPoints !== 'undefined' && customPoints.length > 0) {
            customPoints.forEach(p => {
                points.push([p.lat, p.lng, 0.5]);
            });
        }

        if (points.length === 0) {
            showNotification('No hay puntos suficientes para generar calor.', 'warning');
            return;
        }

        this.heatmapLayer = L.heatLayer(points, {
            radius: 25,
            blur: 15,
            maxZoom: 17,
            gradient: { 0.4: 'blue', 0.65: 'lime', 1: 'red' }
        }).addTo(map);

        document.getElementById('btn-heatmap').classList.add('bg-orange-500/40');
        showNotification('Mapa de calor generado sobre puntos registrados', 'success');
    },

    // --- HERRAMIENTA BUFFER ---
    showBufferTool: function () {
        this.deactivateTools();
        window.analysisMode = true;
        const radius = prompt("Introduce el radio de influencia en METROS (ej. 500):", "500");
        if (!radius || isNaN(radius)) return;

        showNotification('Haz clic en el mapa para generar el área de influencia', 'info');
        map.getContainer().style.cursor = 'crosshair';

        map.once('click', (e) => {
            const center = [e.latlng.lng, e.latlng.lat];
            const point = turf.point(center);
            const buffered = turf.buffer(point, radius / 1000, { units: 'kilometers' });

            const layer = L.geoJSON(buffered, {
                style: {
                    color: '#3b82f6',
                    weight: 2,
                    fillOpacity: 0.2,
                    fillColor: '#3b82f6'
                }
            }).addTo(this.bufferLayer);

            this.bufferLayer.addTo(map);
            showNotification(`Buffer de ${radius}m generado`, 'success');
        });
    },

    // --- MEDICIÓN DE DISTANCIA ---
    startMeasure: function () {
        this.deactivateTools();
        window.analysisMode = true;
        showNotification('Haz clic en dos puntos para medir la distancia', 'info');
        map.getContainer().style.cursor = 'crosshair';
        let points = [];
        const onClick = (e) => {
            points.push(e.latlng);
            L.circleMarker(e.latlng, { radius: 4, color: '#F6C453' }).addTo(this.measureLayer);
            if (points.length === 2) {
                const line = L.polyline(points, { color: '#F6C453', dashArray: '5, 10' }).addTo(this.measureLayer);
                const dist = map.distance(points[0], points[1]);
                L.marker(line.getBounds().getCenter(), {
                    icon: L.divIcon({
                        className: 'measure-label',
                        html: `<div style="background: rgba(0,0,0,0.85); color: #F6C453; padding: 4px 8px; border-radius: 6px; border: 1px solid #F6C453; font-size: 11px; font-weight: 800; white-space: nowrap; box-shadow: 0 2px 6px rgba(0,0,0,0.4); display: inline-block;">
                                <i class="fas fa-ruler-combined" style="margin-right: 4px;"></i> ${dist > 1000 ? (dist / 1000).toFixed(2) + ' km' : dist.toFixed(1) + ' m'}
                               </div>`,
                        iconSize: null,
                        iconAnchor: [0, 0]
                    })
                }).addTo(this.measureLayer);
                this.measureLayer.addTo(map);
                map.off('click', onClick);
            }
        };
        map.on('click', onClick);
    },

    // --- MEDICIÓN DE ÁREA ---
    startMeasureArea: function () {
        this.deactivateTools();
        window.analysisMode = true;
        map.doubleClickZoom.disable(); // Evitar zoom al cerrar polígono
        showNotification('Dibuja un polígono (clics) y doble clic para cerrar y calcular área', 'info');
        map.getContainer().style.cursor = 'crosshair';
        let points = [];
        let polyLine = L.polyline([], { color: '#10b981' }).addTo(this.measureLayer);

        const onClick = (e) => {
            points.push([e.latlng.lng, e.latlng.lat]);
            L.circleMarker(e.latlng, { radius: 3, color: '#10b981' }).addTo(this.measureLayer);
            polyLine.addLatLng(e.latlng);
        };

        const onDoubleClick = () => {
            if (points.length < 3) return;
            points.push(points[0]); // Cerrar polígono para Turf
            const polygon = turf.polygon([points]);
            const area = turf.area(polygon);

            const center = L.polygon(points.map(p => [p[1], p[0]])).getBounds().getCenter();

            L.polygon(points.map(p => [p[1], p[0]]), {
                color: '#10b981',
                fillOpacity: 0.2
            }).addTo(this.measureLayer);

            L.marker(center, {
                icon: L.divIcon({
                    className: 'area-label',
                    html: `<div style="background: rgba(0,0,0,0.85); color: #10b981; padding: 4px 8px; border-radius: 6px; border: 1px solid #10b981; font-size: 11px; font-weight: 800; white-space: nowrap; box-shadow: 0 2px 6px rgba(0,0,0,0.4); display: inline-block;">
                            <i class="fas fa-vector-square" style="margin-right: 4px;"></i> ${area > 1000000 ? (area / 1000000).toFixed(2) + ' km²' : area.toFixed(1) + ' m²'}
                           </div>`,
                    iconSize: null,
                    iconAnchor: [0, 0]
                })
            }).addTo(this.measureLayer);

            this.measureLayer.addTo(map);
            map.off('click', onClick);
            map.off('dblclick', onDoubleClick);
        };

        map.on('click', onClick);
        map.on('dblclick', onDoubleClick);
    },

    // --- CRUCE DE DATOS: PUNTOS EN POLÍGONO ---
    startPointInPolygon: function () {
        this.deactivateTools();
        window.analysisMode = true;
        showNotification('ANÁLISIS ACTIVO: Haz clic en CUALQUIER municipio o polígono para contar puntos dentro', 'success');
        map.getContainer().style.cursor = 'help';

        // Esta función se activará globalmente al hacer clic en capas GeoJSON ya cargadas
        window.pipMode = true;
    },

    // --- ENRUTAMIENTO VIAL (Por calles) ---
    routingControl: null,
    startRouting: function () {
        this.deactivateTools();
        window.analysisMode = true;
        showNotification('Haz clic en dos puntos del mapa para trazar la ruta con tráfico', 'info');

        setTimeout(() => map.getContainer().style.cursor = 'crosshair', 100);

        let waypoints = [];
        const onClick = (e) => {
            waypoints.push(e.latlng);
            L.circleMarker(e.latlng, { radius: 5, color: '#F6C453', fillOpacity: 1 }).addTo(this.measureLayer);

            if (waypoints.length === 2) {
                if (this.routingControl) {
                    map.removeControl(this.routingControl);
                }

                this.routingControl = L.Routing.control({
                    waypoints: waypoints,
                    router: L.Routing.osrmv1({
                        serviceUrl: 'https://router.project-osrm.org/route/v1'
                    }),
                    routeWhileDragging: false,
                    addWaypoints: false,
                    draggableWaypoints: false,
                    show: true, // Mostrar panel de instrucciones
                    collapsible: true,
                    lineOptions: {
                        styles: [{ color: '#F6C453', opacity: 0.8, weight: 6 }]
                    },
                    formatter: new L.Routing.Formatter({
                        language: 'es',
                        units: 'metric'
                    }),
                    createMarker: function () { return null; }
                }).on('routesfound', function (e) {
                    const routes = e.routes;
                    const summary = routes[0].summary;
                    const dist = summary.totalDistance; // en metros
                    const baseTime = summary.totalTime; // en segundos

                    // --- LÓGICA DE SIMULACIÓN DE TRÁFICO ---
                    const now = new Date();
                    const hour = now.getHours();
                    let trafficMultiplier = 1.0;
                    let trafficStatus = "Fluido";
                    let trafficClass = "traffic-fluid";
                    let trafficIcon = "fa-check-circle";

                    // Horas pico: 7-9, 13-15, 18-20
                    if ((hour >= 7 && hour <= 9) || (hour >= 17 && hour <= 20)) {
                        trafficMultiplier = 1.8;
                        trafficStatus = "Tráfico Pesado (Hora Pico)";
                        trafficClass = "traffic-alert";
                        trafficIcon = "fa-exclamation-triangle";
                    } else if (hour >= 13 && hour <= 15) {
                        trafficMultiplier = 1.35;
                        trafficStatus = "Tráfico Moderado";
                        trafficClass = "traffic-alert";
                        trafficIcon = "fa-traffic-light";
                    }

                    const estimatedTime = (baseTime * trafficMultiplier) / 60; // minutos

                    // Actualizar la Tarjeta Minimalista
                    const card = document.getElementById('routing-minimal-card');
                    if (card) {
                        document.getElementById('routing-dist-val').textContent = `${(dist / 1000).toFixed(2)} km`;
                        document.getElementById('routing-time-val').textContent = `${Math.ceil(estimatedTime)} min`;
                        document.getElementById('routing-traffic-txt').textContent = trafficStatus.split(' ')[0]; // Solo la primera palabra

                        const dot = document.getElementById('routing-traffic-dot');
                        dot.className = 'traffic-dot ' + (trafficClass === 'traffic-alert' ? (trafficMultiplier > 1.5 ? 'dot-red' : 'dot-yellow') : 'dot-green');

                        card.classList.add('active');
                    }

                    showNotification(`Ruta estimada: ${Math.ceil(estimatedTime)} min`, 'success');
                }).on('routingerror', function (err) {
                    console.error("Routing error:", err);
                    showNotification('Error al calcular la ruta técnica.', 'error');
                }).addTo(map);

                this.measureLayer.addTo(map);
                map.off('click', onClick);
                map.getContainer().style.cursor = '';
            }
        };
        map.on('click', onClick);
    },

    // --- LIMPIEZA ---
    clearAnalysis: function () {
        if (this.heatmapLayer) {
            map.removeLayer(this.heatmapLayer);
            this.heatmapLayer = null;
            const btnHeatmap = document.getElementById('btn-heatmap');
            if (btnHeatmap) btnHeatmap.classList.remove('bg-orange-500/40');
        }

        if (this.routingControl) {
            map.removeControl(this.routingControl);
            this.routingControl = null;
        }

        // Ocultar tarjeta minimalista
        const card = document.getElementById('routing-minimal-card');
        if (card) card.classList.remove('active');

        this.bufferLayer.clearLayers();
        this.measureLayer.clearLayers();
        try { map.removeLayer(this.bufferLayer); } catch (e) { }
        try { map.removeLayer(this.measureLayer); } catch (e) { }

        // Bug fix #3: limpiar TODOS los modos para que los clics en el mapa vuelvan a funcionar
        window.pipMode = false;
        window.analysisMode = false;
        map.getContainer().style.cursor = '';
        map.off('click'); // elimina listeners de medición que puedan haber quedado
        if (this._measurePoints) this._measurePoints = [];

        showNotification('Análisis limpiados ✓', 'info');
    }
};

window.analysis = analysis;
