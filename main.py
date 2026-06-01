from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import joblib
import re
import os

# 1. CONFIGURACIÓN DE LA API
app = FastAPI(
    title="PhishGuard-ML API",
    description="Backend inteligente para la detección de phishing e ingeniería social mediante ML y NLP.",
    version="1.0.0"
)

MODEL_PATH = "phishguard_nlp_model.pkl"
VECTORIZER_PATH = "phishguard_vectorizer.pkl"

# Cargar modelos en memoria (Manejo seguro)
try:
    detector_nlp = joblib.load(MODEL_PATH)
    vectorizador_tfidf = joblib.load(VECTORIZER_PATH)
except Exception as e:
    print(f"Advertencia al cargar modelos locales: {e}")

# 2. MODELOS DE VALIDACIÓN DE DATOS (Pydantic)
class AnalisisRequest(BaseModel):
    mensaje: str = Field(..., min_length=5, example="BANC0: Cuenta bloqueada. Link: http://falso.com")

class AnalisisResponse(BaseModel):
    metodo_analisis: str
    url_detectada: str | None
    probabilidad_ingenieria_social: float
    riesgo_estructural_url: float
    score_riesgo_final: float
    veredicto: str

# 3. FUNCIONES AUXILIARES DE EXTRACCIÓN Y HEURÍSTICA
def extraer_url(texto: str) -> str | None:
    patron_url = r'(https?://[^\s]+)'
    urls = re.findall(patron_url, texto)
    return urls[0] if urls else None

def analizar_caracteristicas_url(url: str | None) -> float:
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

# 4. ENDPOINTS
@app.get("/")
def read_root():
    return {"status": "online", "sistema": "PhishGuard-ML API Active"}

@app.post("/analizar", response_model=AnalisisResponse)
async def analizar_mensaje(request: AnalisisRequest):
    try:
        texto_usuario = request.mensaje
        texto_transformado = vectorizador_tfidf.transform([texto_usuario])
        probabilidad_nlp = detector_nlp.predict_proba(texto_transformado)[0][1] * 100
        
        url_detectada = extraer_url(texto_usuario)
        if url_detectada:
            probabilidad_url = analizar_caracteristicas_url(url_detectada)
            alpha, beta = 0.4, 0.6
            score_final = (alpha * probabilidad_nlp) + (beta * probabilidad_url)
            metodo = "Híbrido (Texto + URL)"
        else:
            probabilidad_url = 0.0
            score_final = probabilidad_nlp
            metodo = "Exclusivo NLP"
            
        veredicto = "AMENAZA (Phishing)" if score_final >= 50.0 else "SEGURO (Legítimo)"
        
        return AnalisisResponse(
            metodo_analisis=metodo,
            url_detectada=url_detectada,
            probabilidad_ingenieria_social=round(probabilidad_nlp, 2),
            riesgo_estructural_url=round(probabilidad_url, 2),
            score_riesgo_final=round(score_final, 2),
            veredicto=veredicto
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
