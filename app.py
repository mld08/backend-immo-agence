from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from datetime import datetime, timedelta
import os
import hashlib
from functools import wraps
from werkzeug.exceptions import BadRequest

app = Flask(__name__)
CORS(app, origins=['http://localhost:5173'], supports_credentials=True)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/immo'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key-here'

db = SQLAlchemy(app)

# Modèle User
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(100), nullable=False)
    prenom = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    telephone = db.Column(db.String(20))
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum('ADMIN', 'CLIENT'), default='CLIENT')
    date_creation = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relation avec les réservations
    reservations = db.relationship('Reservation', backref='client', lazy=True)
    
    def set_password(self, password):
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    def check_password(self, password):
        return self.password_hash == hashlib.sha256(password.encode()).hexdigest()
    
    def to_dict(self):
        return {
            'id': self.id,
            'nom': self.nom,
            'prenom': self.prenom,
            'email': self.email,
            'telephone': self.telephone,
            'role': self.role,
            'date_creation': self.date_creation.isoformat() if self.date_creation else None
        }

# Modèle Bien 
class Bien(db.Model):
    __tablename__ = 'biens'
    
    id = db.Column(db.Integer, primary_key=True)
    titre = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    prix = db.Column(db.Float, nullable=False)
    surface = db.Column(db.Float, nullable=False)
    nb_pieces = db.Column(db.Integer, nullable=False)
    type_bien = db.Column(db.Enum('APPARTEMENT', 'MAISON', 'TERRAIN', 'COMMERCIAL', 'BUREAU'), nullable=False)
    type_transaction = db.Column(db.Enum('VENTE', 'LOCATION'), nullable=False)
    statut = db.Column(db.Enum('DISPONIBLE', 'RESERVE', 'VENDU_LOUE', 'RETIRE'), default='DISPONIBLE')
    
    # Adresse
    rue = db.Column(db.String(255), nullable=False)
    ville = db.Column(db.String(100), nullable=False)
    code_postal = db.Column(db.String(10), nullable=False)
    pays = db.Column(db.String(50), default='France')
    
    # Caractéristiques
    balcon = db.Column(db.Boolean, default=False)
    terrasse = db.Column(db.Boolean, default=False)
    garage = db.Column(db.Boolean, default=False)
    cave = db.Column(db.Boolean, default=False)
    ascenseur = db.Column(db.Boolean, default=False)
    
    date_creation = db.Column(db.DateTime, default=datetime.utcnow)
    date_modification = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relation avec les réservations
    reservations = db.relationship('Reservation', backref='bien', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'titre': self.titre,
            'description': self.description,
            'prix': self.prix,
            'surface': self.surface,
            'nb_pieces': self.nb_pieces,
            'type_bien': self.type_bien,
            'type_transaction': self.type_transaction,
            'statut': self.statut,
            'adresse': {
                'rue': self.rue,
                'ville': self.ville,
                'code_postal': self.code_postal,
                'pays': self.pays
            },
            'caracteristiques': {
                'balcon': self.balcon,
                'terrasse': self.terrasse,
                'garage': self.garage,
                'cave': self.cave,
                'ascenseur': self.ascenseur
            },
            'date_creation': self.date_creation.isoformat() if self.date_creation else None,
            'date_modification': self.date_modification.isoformat() if self.date_modification else None
        }

# Modèle Reservation
class Reservation(db.Model):
    __tablename__ = 'reservations'
    
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    bien_id = db.Column(db.Integer, db.ForeignKey('biens.id'), nullable=False)
    date_debut = db.Column(db.Date, nullable=False)
    date_fin = db.Column(db.Date)
    nb_personnes = db.Column(db.Integer, default=1)
    message = db.Column(db.Text)
    statut = db.Column(db.Enum('PENDING', 'CONFIRMED', 'CANCELLED', 'COMPLETED'), default='PENDING')
    date_reservation = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'client_id': self.client_id,
            'bien_id': self.bien_id,
            'client': self.client.to_dict() if self.client else None,
            'bien': self.bien.to_dict() if self.bien else None,
            'date_debut': self.date_debut.isoformat() if self.date_debut else None,
            'date_fin': self.date_fin.isoformat() if self.date_fin else None,
            'nb_personnes': self.nb_personnes,
            'message': self.message,
            'statut': self.statut,
            'date_reservation': self.date_reservation.isoformat() if self.date_reservation else None
        }

# Décorateurs pour l'authentification
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentification requise'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentification requise'}), 401
        user = User.query.get(session['user_id'])
        if not user or user.role != 'ADMIN':
            return jsonify({'error': 'Accès administrateur requis'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Routes d'authentification
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        # Vérifier si l'email existe déjà
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email déjà utilisé'}), 400
        
        # Créer un nouvel utilisateur
        user = User(
            nom=data['nom'],
            prenom=data['prenom'],
            email=data['email'],
            telephone=data.get('telephone', ''),
            role=data.get('role', 'CLIENT')
        )
        user.set_password(data['password'])
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({'message': 'Utilisateur créé avec succès'}), 201
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        user = User.query.filter_by(email=data['email']).first()
        
        if user and user.check_password(data['password']):
            session['user_id'] = user.id
            return jsonify({
                'message': 'Connexion réussie',
                'user': user.to_dict()
            })
        else:
            return jsonify({'error': 'Email ou mot de passe incorrect'}), 401
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'Déconnexion réussie'})

@app.route('/api/current-user', methods=['GET'])
@login_required
def get_current_user():
    try:
        user = User.query.get(session['user_id'])
        return jsonify(user.to_dict())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Routes des biens (modifiées pour inclure l'authentification)
@app.route('/api/biens', methods=['GET'])
def get_biens():
    try:
        query = Bien.query
        
        # Pour les clients, ne montrer que les biens disponibles
        if 'user_id' in session:
            user = User.query.get(session['user_id'])
            if user and user.role == 'CLIENT':
                query = query.filter(Bien.statut == 'DISPONIBLE')
        
        # Filtres
        type_bien = request.args.get('type_bien')
        type_transaction = request.args.get('type_transaction')
        prix_min = request.args.get('prix_min', type=float)
        prix_max = request.args.get('prix_max', type=float)
        ville = request.args.get('ville')
        statut = request.args.get('statut')
        
        if type_bien:
            query = query.filter(Bien.type_bien == type_bien)
        if type_transaction:
            query = query.filter(Bien.type_transaction == type_transaction)
        if prix_min:
            query = query.filter(Bien.prix >= prix_min)
        if prix_max:
            query = query.filter(Bien.prix <= prix_max)
        if ville:
            query = query.filter(Bien.ville.ilike(f'%{ville}%'))
        if statut and 'user_id' in session:
            user = User.query.get(session['user_id'])
            if user and user.role == 'ADMIN':
                query = query.filter(Bien.statut == statut)
        
        biens = query.order_by(Bien.date_creation.desc()).all()
        return jsonify([bien.to_dict() for bien in biens])
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/biens/<int:bien_id>', methods=['GET'])
def get_bien(bien_id):
    try:
        bien = Bien.query.get_or_404(bien_id)
        
        # Les clients ne peuvent voir que les biens disponibles
        if 'user_id' in session:
            user = User.query.get(session['user_id'])
            if user and user.role == 'CLIENT' and bien.statut != 'DISPONIBLE':
                return jsonify({'error': 'Bien non disponible'}), 404
        
        return jsonify(bien.to_dict())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Routes des réservations
@app.route('/api/reservations', methods=['POST'])
@login_required
def create_reservation():
    try:
        data = request.get_json()
        user = User.query.get(session['user_id'])
        
        # Vérifier que l'utilisateur est un client
        if user.role != 'CLIENT':
            return jsonify({'error': 'Seuls les clients peuvent faire des réservations'}), 403
        
        # Vérifier que le bien existe et est disponible
        bien = Bien.query.get_or_404(data['bien_id'])
        if bien.statut != 'DISPONIBLE':
            return jsonify({'error': 'Ce bien n\'est pas disponible'}), 400
        
        # Créer la réservation
        reservation = Reservation(
            client_id=user.id,
            bien_id=data['bien_id'],
            date_debut=datetime.strptime(data['date_debut'], '%Y-%m-%d').date(),
            date_fin=datetime.strptime(data['date_fin'], '%Y-%m-%d').date() if data.get('date_fin') else None,
            nb_personnes=data.get('nb_personnes', 1),
            message=data.get('message', '')
        )
        
        db.session.add(reservation)
        
        # Marquer le bien comme réservé
        bien.statut = 'RESERVE'
        
        db.session.commit()
        
        return jsonify(reservation.to_dict()), 201
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/reservations', methods=['GET'])
@login_required
def get_reservations():
    try:
        user = User.query.get(session['user_id'])
        
        if user.role == 'ADMIN':
            # Les admins voient toutes les réservations
            reservations = Reservation.query.order_by(Reservation.date_reservation.desc()).all()
        else:
            # Les clients voient seulement leurs réservations
            reservations = Reservation.query.filter_by(client_id=user.id).order_by(Reservation.date_reservation.desc()).all()
        
        return jsonify([reservation.to_dict() for reservation in reservations])
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reservations/<int:reservation_id>', methods=['GET'])
@login_required
def get_reservation(reservation_id):
    try:
        reservation = Reservation.query.get_or_404(reservation_id)
        user = User.query.get(session['user_id'])
        
        # Vérifier les permissions
        if user.role == 'CLIENT' and reservation.client_id != user.id:
            return jsonify({'error': 'Accès non autorisé'}), 403
        
        return jsonify(reservation.to_dict())
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reservations/<int:reservation_id>', methods=['PUT'])
@login_required
def update_reservation(reservation_id):
    try:
        reservation = Reservation.query.get_or_404(reservation_id)
        user = User.query.get(session['user_id'])
        data = request.get_json()
        
        # Vérifier les permissions
        if user.role == 'CLIENT' and reservation.client_id != user.id:
            return jsonify({'error': 'Accès non autorisé'}), 403
        
        # Mise à jour des champs autorisés
        if 'statut' in data and user.role == 'ADMIN':
            old_statut = reservation.statut
            reservation.statut = data['statut']
            
            # Gérer le statut du bien
            if old_statut == 'PENDING' and data['statut'] == 'CONFIRMED':
                reservation.bien.statut = 'RESERVE'
            elif data['statut'] == 'CANCELLED':
                reservation.bien.statut = 'DISPONIBLE'
            elif data['statut'] == 'COMPLETED' and reservation.bien.type_transaction == 'VENTE':
                reservation.bien.statut = 'VENDU_LOUE'
        
        if 'message' in data:
            reservation.message = data['message']
        
        db.session.commit()
        
        return jsonify(reservation.to_dict())
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/reservations/<int:reservation_id>', methods=['DELETE'])
@login_required
def delete_reservation(reservation_id):
    try:
        reservation = Reservation.query.get_or_404(reservation_id)
        user = User.query.get(session['user_id'])
        
        # Vérifier les permissions
        if user.role == 'CLIENT' and reservation.client_id != user.id:
            return jsonify({'error': 'Accès non autorisé'}), 403
        
        # Libérer le bien si la réservation est annulée
        if reservation.statut in ['PENDING', 'CONFIRMED']:
            reservation.bien.statut = 'DISPONIBLE'
        
        db.session.delete(reservation)
        db.session.commit()
        
        return jsonify({'message': 'Réservation supprimée avec succès'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Routes admin pour la gestion des biens (existantes mais protégées)
@app.route('/api/biens', methods=['POST'])
@admin_required
def create_bien():
    try:
        data = request.get_json()
        
        required_fields = ['titre', 'prix', 'surface', 'nb_pieces', 'type_bien', 'type_transaction', 'rue', 'ville', 'code_postal']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Le champ {field} est obligatoire'}), 400
        
        bien = Bien(
            titre=data['titre'],
            description=data.get('description', ''),
            prix=data['prix'],
            surface=data['surface'],
            nb_pieces=data['nb_pieces'],
            type_bien=data['type_bien'],
            type_transaction=data['type_transaction'],
            rue=data['rue'],
            ville=data['ville'],
            code_postal=data['code_postal'],
            pays=data.get('pays', 'France'),
            balcon=data.get('balcon', False),
            terrasse=data.get('terrasse', False),
            garage=data.get('garage', False),
            cave=data.get('cave', False),
            ascenseur=data.get('ascenseur', False)
        )
        
        db.session.add(bien)
        db.session.commit()
        
        return jsonify(bien.to_dict()), 201
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/biens/<int:bien_id>', methods=['PUT'])
@admin_required
def update_bien(bien_id):
    try:
        bien = Bien.query.get_or_404(bien_id)
        data = request.get_json()
        
        for field in ['titre', 'description', 'prix', 'surface', 'nb_pieces', 'type_bien', 'type_transaction', 'statut', 'rue', 'ville', 'code_postal', 'pays', 'balcon', 'terrasse', 'garage', 'cave', 'ascenseur']:
            if field in data:
                setattr(bien, field, data[field])
        
        bien.date_modification = datetime.utcnow()
        db.session.commit()
        
        return jsonify(bien.to_dict())
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/biens/<int:bien_id>', methods=['DELETE'])
@admin_required
def delete_bien(bien_id):
    try:
        bien = Bien.query.get_or_404(bien_id)
        db.session.delete(bien)
        db.session.commit()
        
        return jsonify({'message': 'Bien supprimé avec succès'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
@admin_required
def get_stats():
    try:
        total_biens = Bien.query.count()
        biens_disponibles = Bien.query.filter(Bien.statut == 'DISPONIBLE').count()
        biens_vente = Bien.query.filter(Bien.type_transaction == 'VENTE').count()
        biens_location = Bien.query.filter(Bien.type_transaction == 'LOCATION').count()
        total_reservations = Reservation.query.count()
        reservations_pending = Reservation.query.filter(Reservation.statut == 'PENDING').count()
        
        return jsonify({
            'total_biens': total_biens,
            'biens_disponibles': biens_disponibles,
            'biens_vente': biens_vente,
            'biens_location': biens_location,
            'total_reservations': total_reservations,
            'reservations_pending': reservations_pending
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Initialisation
@app.before_request
def create_tables():
    db.create_all()
    
    # Créer un utilisateur admin par défaut
    admin = User.query.filter_by(email='admin@example.com').first()
    if not admin:
        admin = User(
            nom='Admin',
            prenom='System',
            email='admin@example.com',
            role='ADMIN'
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)