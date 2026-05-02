import re
from urllib.parse import urlparse

def extract_features(url):
    features = {}
    # 1. Longitud de la URL
    features['longitud'] = len(url)
    
    # 2. Cantidad de puntos (un exceso es sospechoso)
    features['puntos'] = url.count('.')
    
    # 3. ¿Contiene el símbolo @? (Usado para engañar navegadores)
    features['tiene_arroba'] = 1 if '@' in url else 0
    
    # 4. ¿Es una dirección IP en lugar de dominio?
    ip_pattern = r'(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])'
    features['es_ip'] = 1 if re.search(ip_pattern, url) else 0
    
    # 5. Cantidad de guiones (común en dominios falsos)
    features['guiones'] = url.count('-')
    
    return features