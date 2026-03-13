// Configuración para el despliegue híbrido (GitHub + Render)
const API_BASE_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:8000'
    : 'https://sig-web-uv.onrender.com';

// Variables globales para el sistema de puntos personalizados
let markerModeActive = false;
let customPointsLayer = null; // Se inicializará en map.js
let customPoints = [];
let currentEditingPoint = null;
let tempMarker = null;

let municipiosIndex = [];
let municipalGeoJSON = null;
let poblacion = {
    "nacional": {},
    "veracruz": {},
    "municipios": []
};


let currentChart = null;
let currentScale = 'nacional'; // Track current scale

// Colores por categoría
const categoryColors = {
    'comercio': '#f59e0b',
    'oficina': '#3b82f6',
    'educacion': '#8b5cf6',
    'salud': '#ef4444',
    'recreacion': '#10b981',
    'transporte': '#06b6d4',
    'gobierno': '#6366f1',
    'otro': '#64748b'
};

const subcategoriesMap = {
    'comercio': ['Supermercado', 'Tienda Local', 'Plaza Comercial', 'Restaurante', 'Mercado', 'Farmacia', 'Oxxo/7-Eleven', 'Otro'],
    'oficina': ['Administrativa', 'Corporativa', 'Servicios', 'Consultoría', 'Coworking', 'Otro'],
    'educacion': ['Preescolar', 'Primaria', 'Secundaria', 'Preparatoria', 'Universidad', 'Posgrado', 'Centro de Investigación', 'Biblioteca', 'Otro'],
    'salud': ['Hospital General', 'Clínica Especializada', 'Centro de Salud', 'Consultorio Privado', 'Laboratorio', 'Farmacia con Consultorio', 'Otro'],
    'recreacion': ['Parque', 'Cancha Deportiva', 'Gimnasio', 'Cine', 'Museo/Cultura', 'Centro Comunitario', 'Área Natural', 'Otro'],
    'transporte': ['Estación de Autobús', 'Terminal', 'Parada de Taxi', 'Gasolinera', 'Taller Mecánico', 'Estacionamiento', 'Otro'],
    'gobierno': ['Palacio Municipal', 'Delegación', 'Oficina Estatal', 'Oficina Federal', 'Centro de Atención', 'Seguridad/Policía', 'Otro'],
    'otro': ['Residencial', 'Terreno Baldío', 'Monumento', 'Religioso', 'Industrial', 'Infraestructura', 'Otro']
};

const categoryIcons = {
    'comercio': 'fa-store',
    'oficina': 'fa-building',
    'educacion': 'fa-graduation-cap',
    'salud': 'fa-hospital',
    'recreacion': 'fa-tree',
    'transporte': 'fa-bus',
    'gobierno': 'fa-landmark',
    'otro': 'fa-map-pin'
};

const categoryNames = {
    'comercio': 'Comercio',
    'oficina': 'Oficina',
    'educacion': 'Educación',
    'salud': 'Salud',
    'recreacion': 'Recreación',
    'transporte': 'Transporte',
    'gobierno': 'Gobierno',
    'otro': 'Otro'
};

const uvRegionsData = {
    "Poza Rica-Tuxpan": {
        color: "#F59E0B",
        municipios: ["Poza Rica de Hidalgo", "Tuxpan", "Ixhuatlán de Madero", "Espinal", "Papantla"],
        facultades: [
            "Facultad de Medicina",
            "Facultad de Ingeniería y Ciencias Químicas",
            "Facultad de Pedagogía",
            "Facultad de Trabajo Social",
            "Facultad de Arquitectura"
        ]
    },
    "Xalapa": {
        color: "#3B82F6",
        municipios: ["Xalapa", "Naolinco", "Perote", "Ixhuacán de los Reyes"],
        facultades: [
            "Facultad de Derecho",
            "Facultad de Economía",
            "Facultad de Estadística e Informática",
            "Facultad de Humanidades",
            "Facultad de Biología",
            "Facultad de Artes Plásticas",
            "Facultad de Música"
        ]
    },
    "Veracruz": {
        color: "#EF4444",
        municipios: ["Veracruz", "Boca del Río"],
        facultades: [
            "Facultad de Medicina",
            "Facultad de Administración",
            "Facultad de Ciencias de la Comunicación",
            "Facultad de Bioanálisis",
            "Facultad de Ingeniería"
        ]
    },
    "Orizaba-Córdoba": {
        color: "#10B981",
        municipios: ["Orizaba", "Córdoba", "Camerino Z. Mendoza", "Ciudad Mendoza", "Nogales", "Río Blanco", "Amatlán de los Reyes", "Tequila"],
        facultades: [
            "Facultad de Ciencias Químicas",
            "Facultad de Enfermería",
            "Facultad de Odontología",
            "Facultad de Arquitectura"
        ]
    },
    "Coatzacoalcos-Minatitlán": {
        color: "#8B5CF6",
        municipios: ["Coatzacoalcos", "Minatitlán", "Acayucan", "Agua Dulce", "Mecayapan", "Uxpanapa"],
        facultades: [
            "Facultad de Contaduría y Administración",
            "Facultad de Ingeniería",
            "Facultad de Ciencias Químicas",
            "Escuela de Enfermería"
        ]
    }
};
