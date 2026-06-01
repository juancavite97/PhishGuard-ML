import streamlit as st
import re
import joblib
import pandas as pd

# ==========================================================
# 1. CONFIGURACIÓN DE LA PÁGINA Y ESTILOS
# ==========================================================
st.set_page_config(
    page_title="PhishGuard-ML Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Estilización personalizada con CSS nativo de Streamlit para un acabado profesional
st.markdown("""
    <style>
    .main-title { font-size: 32px; font-weight: bold; color: #1E3A8A; margin-bottom: 5px; }
    .subtitle { font-size: 16px; color: #4B5563; margin-bottom: 25px; }
    .metric-box { padding: 15px; border-radius: 8px; background-color: #F3F4F6; margin-bottom: 10px; }
    </style>
""", unsafe_html=True)

# ==========================================================
# 2. FUNCIONES DE LOGICA LOCAL (HÍBRIDA)
# ==========================================================
@st.cache_resource
def cargar_modelos_locales():
    """Carga los modelos en caché para que la app responda de inmediato."""
    try:
        model = joblib.load("phishguard_nlp_model.pkl")
        vectorizer = joblib.load("phishguard_vectorizer.pkl")
        return model, vectorizer
    except Exception as e:
        st.error(f"Error al cargar los archivos binarios del modelo (.pkl): {e}")
        return None, None

detector_nlp, vectorizador_tfidf = cargar_modelos_locales()

def extraer_url(texto):
    patron_url = r'(https?://[^\s]+)'
    urls = re.findall(patron_url, texto)
    return urls[0] if urls else None

def analizar_caracteristicas_url(url):
    if not url: return 0.0
    puntos_de_riesgo = 0
    max_puntos = 5
    if len(url) > 54: puntos_de_riesgo += 1
    if len(url) > 75: puntos_de_riesgo += 1
    if url.count('.') > 3: puntos_de_riesgo += 1
    if '@' in url: puntos_de_riesgo += 1
    if url.count('-') > 2: puntos_de_riesgo += 1
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url): puntos_de_riesgo += 2
    return (min(puntos_de_riesgo, max_puntos) / max_puntos) * 100

# ==========================================================
# 3. INTERFAZ DE USUARIO (DASHBOARD)
# ==========================================================

# Barra lateral izquierda informative
with st.sidebar:
    st.image("https://img.shields.io/badge/PhishGuard--ML-Tesis%20Ingeniería-blue?style=for-the-badge")
    st.markdown("### Configuración de Pesos de Tesis")
    st.write("Establece la influencia del modelo híbrido en el Score de Riesgo Final:")
    
    # Parámetros dinámicos configurables por el usuario
    peso_url = st.slider("Peso del Análisis de URL (β)", 0.0, 1.0, 0.6, 0.05)
    peso_nlp = 1.0 - peso_url
    st.caption(f"Peso del Análisis de Texto (α): {peso_nlp:.2f}")
    
    st.markdown("---")
    st.markdown("**Desarrollado por:**")
    st.write("Juan Carlos Vite Agurto")
    st.caption("Facultad de Ingeniería y Arquitectura - USMP")

# Cuerpo Principal del Dashboard
st.markdown("<div class='main-title'>🛡️ Panel de Control PhishGuard-ML</div>", unsafe_html=True)
st.markdown("<div class='subtitle'>Prototipo interactivo de detección inteligente de phishing y mitigación de hurto sistemático digital.</div>", unsafe_html=True)

# Área de entrada de datos
mensaje_entrada = st.text_area(
    "Pegue el mensaje sospechoso (SMS o Correo electrónico) a evaluar:",
    height=120,
    placeholder="Ejemplo: BANC0: Se ha detectado un movimiento inusual. Valide sus accesos de inmediato en: http://banco-seguridad-alerta.net/login"
)

# Botón de ejecución
if st.button("Ejecutar Análisis Inteligente", type="primary"):
    if mensaje_entrada.strip() == "":
        st.warning("Por favor, ingrese un mensaje de texto válido para procesar el análisis.")
    elif detector_nlp is None or vectorizador_tfidf is None:
        st.error("Los modelos de Machine Learning no están cargados. Verifique que los archivos .pkl existan.")
    else:
        # 1. Procesar modelo NLP (Ingeniería Social)
        texto_transformado = vectorizador_tfidf.transform([mensaje_entrada])
        prob_nlp = detector_nlp.predict_proba(texto_transformado)[0][1] * 100
        
        # 2. Procesar análisis heurístico estructural de URL
        url_detectada = extraer_url(mensaje_entrada)
        prob_url = analizar_caracteristicas_url(url_detectada) if url_detectada else 0.0
        
        # 3. Calcular Score Unificado de Riesgo
        if url_detectada:
            score_final = (peso_nlp * prob_nlp) + (peso_url * prob_url)
            metodo_msg = "Análisis Híbrido Activado (Contenido Textual + Estructura de Enlace)"
        else:
            score_final = prob_nlp
            metodo_msg = "Análisis Basado Exclusivamente en NLP (No se interceptaron URLs)"
            
        # 4. Clasificación y Veredicto
        es_phishing = score_final >= 50.0
        
        st.markdown("---")
        st.markdown("### 📊 Reporte de Evaluación de Seguridad")
        
        # Bloques de Visualización de Alerta
        if es_phishing:
            st.error(f"🚨 **VERDICTO: AMENAZA DETECTADA (Phishing)** \n\n Este mensaje presenta patrones críticos de fraude digital. No interactúe con los enlaces ni proporcione datos sensibles.")
        else:
            st.success(f"✅ **VERDICTO: MENSAJE SEGURO (Legítimo)** \n\n El nivel de riesgo se encuentra dentro del rango de tolerancia normal establecido por el sistema.")
            
        st.caption(f"**Método de cálculo empleado:** {metodo_msg}")
        
        # Sección de Métricas Numéricas en Columnas
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown("<div class='metric-box'>", unsafe_html=True)
            st.metric(label="Persuasión / Ingeniería Social (NLP)", value=f"{prob_nlp:.2f}%")
            st.caption("Riesgo analizado mediante el patrón lingüístico del texto.")
            st.markdown("</div>", unsafe_html=True)
            
        with col2:
            st.markdown("<div class='metric-box'>", unsafe_html=True)
            st.metric(label="Riesgo Estructural (URL)", value=f"{prob_url:.2f}%")
            st.caption(f"Enlace detectado: `{url_detectada if url_detectada else 'Ninguno'}`")
            st.markdown("</div>", unsafe_html=True)
            
        with col3:
            st.markdown("<div class='metric-box'>", unsafe_html=True)
            st.metric(label="SCORE FINAL COMBINADO", value=f"{score_final:.2f}%", delta="- Peligro" if not es_phishing else "+ Crítico", delta_color="inverse")
            st.caption("Ponderación matemática unificada final de la tesis.")
            st.markdown("</div>", unsafe_html=True)
            
        # Gráfico de Barras Horizontal de Riesgos Cruzados (Interactivo)
        st.markdown("#### 📈 Desglose Comparativo de Riesgos")
        data_grafico = pd.DataFrame({
            'Componente Evaluado': ['Ingeniería Social (NLP)', 'Anomalías en URL', 'Score Global Unificado'],
            'Nivel de Riesgo (%)': [prob_nlp, prob_url, score_final]
        })
        st.bar_chart(data=data_grafico, x='Componente Evaluado', y='Nivel de Riesgo (%)', use_container_width=True)
