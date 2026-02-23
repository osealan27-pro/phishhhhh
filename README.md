# 🛡 VulnScan — Web Vulnerability Scanner

Outil de scan de vulnérabilités web éducatif et open-source.

## ⚠️ Usage légal uniquement
Ne scanner QUE des cibles dont vous êtes propriétaire ou avez une autorisation explicite.

---

## 🚀 Installation rapide

### Option 1 — Docker (recommandé)
```bash
git clone https://github.com/TON_REPO/vulnscan
cd vulnscan
docker compose up -d
```
→ Frontend : http://localhost  
→ Backend API : http://localhost:8000

### Option 2 — Manuel

**Backend (Python 3.10+)**
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

**Frontend**
```bash
# Ouvrir simplement frontend/index.html dans un navigateur
# Ou servir avec :
cd frontend
python -m http.server 3000
```

---

## 📊 Fonctionnalités

| Module | Description |
|--------|-------------|
| 🌐 DNS | Résolution d'IP, enregistrements |
| 🔒 SSL/TLS | Validité, expiration, certificat |
| 📋 HTTP Headers | CSP, HSTS, X-Frame-Options, etc. (grade A-F) |
| 📁 Fichiers sensibles | .env, .git, phpinfo, wp-config, etc. |
| 🔌 Ports | Scan de 18 ports communs (SSH, RDP, MySQL...) |

---

## 🔧 Configuration

Dans `frontend/index.html`, modifier la ligne :
```js
const API = 'http://localhost:8000'; // → URL de votre backend
```

Pour déployer sur GitHub Pages (frontend uniquement) + un hébergeur pour le backend (Railway, Render, etc.)

---

## 📦 Stack technique
- **Backend** : FastAPI (Python) + httpx + asyncio
- **Frontend** : HTML/CSS/JS vanilla (zéro dépendance)
- **Déploiement** : Docker + Nginx

---

## 🗺 Roadmap
- [ ] Authentification utilisateur
- [ ] Vérification de propriété du domaine
- [ ] Scan OWASP Top 10 basique
- [ ] Export PDF des rapports
- [ ] Intégration Nuclei/Nikto
- [ ] Historique des scans

---

Fait avec ❤️ pour l'éducation à la cybersécurité.
