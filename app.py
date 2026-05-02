import streamlit as st
import pandas as pd
import os
import re
from utils import extract_features # Importamos tu lógica de análisis técnico

# 1. Configuración de la interfaz 
st.set_page_config(page_title="PhishGuard ML", page_icon="🛡️")

st.title("🛡️ PhishGuard: Detector de Phishing")
st.write("Análisis de URLs maliciosas e Inteligencia de Datos - Ingeniería de Sistemas")

# 2. Carga optimizada de la base de datos
@st.cache_data
def load_data():
    # Usamos el nombre exacto de tu archivo real en la MacBook
    csv_path = "data/Phishing URLs.csv"
    if os.path.exists(csv_path):
        return pd.read_csv(csv_path)
    return None

df = load_data()

# 3. Entrada de usuario
url_input = st.text_input("Ingresa la URL a consultar:", placeholder="https://ejemplo.com")

if st.button("Verificar"):
    if url_input:
        # --- PARTE A: ANÁLISIS TÉCNICO (NUEVO) ---
        st.subheader("🔍 Análisis Técnico Preventivo")
        features = extract_features(url_input)
        
        col1, col2, col3 = st.columns(3)
        col1.metric("Longitud URL", features['longitud'])
        col2.metric("Puntos detectados", features['puntos'])
        col3.metric("¿Es una IP?", "Sí" if features['es_ip'] else "No")
        
        # Alertas preventivas basadas en patrones
        if features['tiene_arroba']:
            st.warning("⚠️ Atención: La URL contiene un símbolo '@', técnica común para ocultar el destino real.")
        if features['guiones'] > 3:
            st.warning(f"⚠️ Nota: Se detectaron {features['guiones']} guiones. Los atacantes suelen usarlos para imitar marcas reales.")

        st.markdown("---")

        # --- PARTE B: BÚSQUEDA EN BASE DE DATOS ---
        if df is not None:
            # Buscamos la columna de URL dinámicamente
            try:
                col_url = [c for c in df.columns if 'url' in c.lower()][0]
                # Limpiamos la entrada del usuario para evitar errores de búsqueda
                clean_input = url_input.strip()
                result = df[df[col_url].str.contains(clean_input, case=False, na=False)]
                
                if not result.empty:
                    st.error("🚨 URL CONFIRMADA: Esta dirección se encuentra en los registros de phishing.")
                    st.table(result)
                else:
                    st.info("ℹ️ La URL no se encuentra en los registros históricos del CSV.")
            except IndexError:
                st.error("No se encontró una columna de 'URL' en el archivo CSV.")
        else:
            st.error("Archivo de datos no encontrado. Verifica la carpeta 'data/' en tu Mac.")
    else:
        st.warning("Por favor, ingresa una URL para iniciar el análisis.")

# Pie de página profesional
st.markdown("---")
st.caption("Proyecto de Tesis - Juan Carlos Vite - Ingeniería de Sistemas USMP")