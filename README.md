# 🏠 Agence Immo - Backend API (Flask)

Bienvenue dans **Agence Immo**, une API RESTful développée avec **Flask** pour gérer les biens immobiliers, les utilisateurs, et les réservations. Cette API est conçue pour être utilisée avec une application frontend (comme React, Vue ou autre) pour construire une plateforme complète de gestion et de réservation de biens.

---

## 🚀 Fonctionnalités

- 🔐 Authentification utilisateur (inscription, connexion, déconnexion)
- 👤 Rôles utilisateurs : Admin / Utilisateur
- 🏡 CRUD complet sur les **biens immobiliers**
- 📆 Réservations de biens par les utilisateurs
- 📊 Statistiques globales sur les biens
- 🔍 Filtres de recherche sur les biens

---

## 🛠️ Stack technique

- **Backend** : Python, Flask, Flask-Restful, Flask-JWT-Extended
- **Base de données** : MySQL
- **ORM** : SQLAlchemy
- **Sécurité** : JWT (JSON Web Tokens), gestion des rôles
- **Cross-Origin** : CORS activé pour frontend React

---

## ⚙️ Installation

1. **Cloner le projet :**

```bash
git clone https://github.com/ton-utilisateur/agence-immo-backend.git
cd agence-immo-backend 
```

2. **Créer et activer un environnement virtuel :**
```bash
python -m venv venv
source venv/bin/activate    # sous Linux/macOS
venv\Scripts\activate       # sous Windows
```

3. **Installer les dépendances :**
```bash
pip install -r requirements.txt
```

4. **Configurer la base de données dans app.py**
```python
SQLALCHEMY_DATABASE_URI = 'mysql://user:password@localhost/agence_immo'
```

5. **Lancer le serveur**
```bash
python app.py
```
