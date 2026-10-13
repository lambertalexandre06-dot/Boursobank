import os
from flask import Flask, render_template, request, redirect, url_for, flash, abort, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from email.message import EmailMessage
import smtplib
from datetime import datetime
from queue import Queue
import random
import re
import string
from threading import Thread
import pyotp

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'boursobank_super_secret_key_12345')

database_url = os.environ.get('DATABASE_URL', 'sqlite:///boursobank.db')
# Render provides 'postgres://', but SQLAlchemy requires 'postgresql://'
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png', 'txt', 'doc', 'docx'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@app.before_request
def require_cgu_and_2fa():
    allowed_endpoints = {
        'login',
        'logout',
        'cgu',
        'two_factor',
        'static'
    }

    if current_user.is_authenticated and current_user.role == 'client':
        if request.endpoint not in allowed_endpoints:
            if not current_user.cgu_accepted:
                return redirect(url_for('cgu'))
            if current_user.two_factor_enabled and not session.get('two_factor_verified'):
                return redirect(url_for('two_factor'))

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    num_client = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='client') # 'admin' or 'client'
    prenom = db.Column(db.String(100), nullable=False)
    nom = db.Column(db.String(100), nullable=False)
    date_naissance = db.Column(db.String(20), nullable=False)
    adresse = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=True)
    phone = db.Column(db.String(40), nullable=True)
    is_frozen = db.Column(db.Boolean, default=False)
    cgu_accepted = db.Column(db.Boolean, default=False)
    cgu_accepted_at = db.Column(db.DateTime, nullable=True)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    totp_secret = db.Column(db.String(64), nullable=True)
    
    comptes = db.relationship('Compte', backref='client', lazy=True)
    documents = db.relationship('Document', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Compte(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    iban = db.Column(db.String(34), unique=True, nullable=False)
    solde = db.Column(db.Float, default=0.0)
    
    transactions_sortantes = db.relationship('Transaction', foreign_keys='Transaction.compte_source_id', backref='source', lazy=True)
    transactions_entrantes = db.relationship('Transaction', foreign_keys='Transaction.compte_dest_id', backref='destination', lazy=True)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    compte_source_id = db.Column(db.Integer, db.ForeignKey('compte.id'), nullable=True) # None si dépôt initial
    compte_dest_id = db.Column(db.Integer, db.ForeignKey('compte.id'), nullable=False)
    montant = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    type_trans = db.Column(db.String(50), nullable=False) # 'virement', 'depot', 'retrait'
    libelle = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='APPROVED')
    review_reason = db.Column(db.String(255), nullable=True)
    beneficiary_iban = db.Column(db.String(34), nullable=True)
    beneficiary_email = db.Column(db.String(255), nullable=True)
    beneficiary_phone = db.Column(db.String(40), nullable=True)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(80), nullable=False)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    type_doc = db.Column(db.String(100), nullable=False, default='Justificatif')
    status = db.Column(db.String(20), nullable=False, default='PENDING')
    review_reason = db.Column(db.String(255), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_iban():
    # FR76 + bank code (5) + branch code (5) + account number (11) + key (2) = 27 chars
    account_number = ''.join(random.choices(string.digits, k=11))
    return f"FR763000400001{account_number}12"

TRANSFER_REVIEW_THRESHOLD = 15000.0
VALIDATED_TRANSACTION_STATUSES = {'APPROVED', 'VALIDATED'}
notification_queue = Queue()

def generate_num_client():
    return ''.join(random.choices(string.digits, k=10))


def normalize_iban(iban):
    return re.sub(r'\s+', '', (iban or '').upper())


def is_valid_iban_format(iban):
    normalized = normalize_iban(iban)
    return bool(re.fullmatch(r'[A-Z]{2}[0-9A-Z]{13,32}', normalized))


def normalize_optional_text(value):
    value = (value or '').strip()
    return value or None


def log_audit(action, user_id=None, details=None):
    audit = AuditLog(user_id=user_id, action=action, details=details)
    db.session.add(audit)
    db.session.commit()


def generate_totp_secret():
    return pyotp.random_base32()


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def send_email_notification(to_email, subject, body):
    email_host = os.environ.get('EMAIL_HOST')
    email_port = int(os.environ.get('EMAIL_PORT', 587))
    email_user = os.environ.get('EMAIL_USERNAME')
    email_password = os.environ.get('EMAIL_PASSWORD')
    email_from = os.environ.get('EMAIL_FROM', email_user)

    if not (email_host and email_user and email_password and to_email):
        return False

    message = EmailMessage()
    message['Subject'] = subject
    message['From'] = email_from
    message['To'] = to_email
    message.set_content(body)

    try:
        if email_port == 465:
            server = smtplib.SMTP_SSL(email_host, email_port)
        else:
            server = smtplib.SMTP(email_host, email_port)
            server.starttls()
        server.login(email_user, email_password)
        server.send_message(message)
        server.quit()
        return True
    except Exception as e:
        print(f"Erreur d'envoi email: {e}")
        return False


def send_sms_notification(to_phone, message):
    twilio_sid = os.environ.get('TWILIO_ACCOUNT_SID')
    twilio_token = os.environ.get('TWILIO_AUTH_TOKEN')
    twilio_from = os.environ.get('TWILIO_FROM')

    if not (twilio_sid and twilio_token and twilio_from and to_phone):
        return False

    try:
        from twilio.rest import Client
        client = Client(twilio_sid, twilio_token)
        client.messages.create(body=message, from_=twilio_from, to=to_phone)
        return True
    except ImportError:
        print('Twilio non installé: notification SMS ignorée.')
        return False
    except Exception as e:
        print(f"Erreur d'envoi SMS: {e}")
        return False


def notify_user(user, subject, message):
    if hasattr(user, 'email') and user.email:
        send_email_notification(user.email, subject, message)
    if hasattr(user, 'phone') and user.phone:
        send_sms_notification(user.phone, message)
    log_audit('notify_user', user.id if user else None, f'{subject} / {message}')


def notify_external_beneficiary(email, phone, subject, message, transaction_id):
    sent = False
    if email:
        sent = send_email_notification(email, subject, message) or sent
    if phone:
        sent = send_sms_notification(phone, message) or sent
    if email or phone:
        log_audit(
            'notify_external_beneficiary',
            None,
            f'Transaction {transaction_id} / email={email or "N/A"} / phone={phone or "N/A"} / sent={sent}'
        )


def build_transfer_receipt(transaction, source_user, dest_user):
    reference = f"VIR-{transaction.id:06d}"
    source_iban = transaction.source.iban if transaction.source else 'N/A'
    dest_iban = transaction.beneficiary_iban or (transaction.destination.iban if transaction.destination else 'N/A')
    dest_name = f"{dest_user.prenom} {dest_user.nom}" if dest_user else "Bénéficiaire externe"
    date_value = transaction.date.strftime('%d/%m/%Y à %H:%M') if transaction.date else datetime.utcnow().strftime('%d/%m/%Y à %H:%M')

    return f"""Bonjour {source_user.prenom} {source_user.nom},

Votre virement BoursoBank a été validé.

Reçu numérique
Référence : {reference}
Date : {date_value}
Montant : {transaction.montant:,.2f} €
Donneur d'ordre : {source_user.prenom} {source_user.nom}
IBAN donneur d'ordre : {source_iban}
Bénéficiaire : {dest_name}
IBAN bénéficiaire : {dest_iban}
Libellé : {transaction.libelle}

Ce message est généré automatiquement après validation de l'opération.
BoursoBank
"""


def handle_transaction_validated_event(transaction_id):
    transaction = Transaction.query.get(transaction_id)
    if not transaction or transaction.type_trans != 'virement':
        return
    if transaction.status not in VALIDATED_TRANSACTION_STATUSES:
        return

    source_user = transaction.source.client if transaction.source else None
    beneficiary_iban = transaction.beneficiary_iban or (transaction.destination.iban if transaction.destination else None)
    internal_dest_account = Compte.query.filter_by(iban=beneficiary_iban).first() if beneficiary_iban else transaction.destination
    dest_user = internal_dest_account.client if internal_dest_account else None
    if not source_user:
        return

    subject = f"Reçu de virement BoursoBank VIR-{transaction.id:06d}"
    receipt = build_transfer_receipt(transaction, source_user, dest_user)
    beneficiary_alert = (
        f"BoursoBank : vous avez reçu un virement de {transaction.montant:,.2f} € "
        f"de {source_user.prenom} {source_user.nom}. Réf. VIR-{transaction.id:06d}."
    )

    notify_user(source_user, subject, receipt)
    if dest_user:
        notify_user(dest_user, 'Virement reçu sur votre compte BoursoBank', beneficiary_alert)
    else:
        notify_external_beneficiary(
            transaction.beneficiary_email,
            transaction.beneficiary_phone,
            'Virement BoursoBank en votre faveur',
            beneficiary_alert,
            transaction.id
        )
    log_audit('transaction.validated.notified', source_user.id, f'Transaction {transaction.id} notifiée')


def notification_worker():
    with app.app_context():
        while True:
            event_name, payload = notification_queue.get()
            try:
                if event_name == 'transaction.validated':
                    handle_transaction_validated_event(payload['transaction_id'])
            except Exception as exc:
                print(f"Erreur worker notification {event_name}: {exc}")
            finally:
                notification_queue.task_done()


def emit_transaction_validated(transaction_id):
    notification_queue.put(('transaction.validated', {'transaction_id': transaction_id}))


notification_thread = Thread(target=notification_worker, daemon=True)
notification_thread.start()


def recalculate_balance(compte_id):
    if not compte_id:
        return
    compte = Compte.query.get(compte_id)
    if not compte:
        return
    
    # Inbound: transactions where compte_dest_id == compte.id and compte_source_id != compte.id
    inbound = db.session.query(db.func.sum(Transaction.montant)).filter(
        Transaction.compte_dest_id == compte.id,
        Transaction.compte_source_id != compte.id
    ).scalar() or 0.0
    
    # Outbound: transactions where compte_source_id == compte.id
    outbound = db.session.query(db.func.sum(Transaction.montant)).filter(
        Transaction.compte_source_id == compte.id
    ).scalar() or 0.0
    
    compte.solde = inbound - outbound
    db.session.commit()

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('client_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        num_client = request.form.get('num_client')
        password = request.form.get('password')
        user = User.query.filter_by(num_client=num_client).first()
        
        if user and user.check_password(password):
            login_user(user)
            session['two_factor_verified'] = False
            log_audit('login', user.id, 'Connexion réussie')
            if user.role == 'client' and not user.cgu_accepted:
                return redirect(url_for('cgu'))
            if user.role == 'client' and user.two_factor_enabled:
                return redirect(url_for('two_factor'))
            return redirect(url_for('index'))
        flash('Numéro client ou mot de passe incorrect.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('two_factor_verified', None)
    logout_user()
    return redirect(url_for('login'))

@app.route('/cgu', methods=['GET', 'POST'])
@login_required
def cgu():
    if current_user.role != 'client':
        return redirect(url_for('index'))
    if current_user.cgu_accepted:
        return redirect(url_for('client_dashboard'))

    if request.method == 'POST':
        current_user.cgu_accepted = True
        current_user.cgu_accepted_at = datetime.utcnow()
        db.session.commit()
        log_audit('cgu_accepted', current_user.id, 'CGU acceptées par le client')
        flash('CGU acceptées. Vous pouvez maintenant accéder à votre espace sécurisé.', 'success')
        if current_user.two_factor_enabled:
            session['two_factor_verified'] = False
            return redirect(url_for('two_factor'))
        return redirect(url_for('client_dashboard'))

    return render_template('cgu.html')

@app.route('/two_factor', methods=['GET', 'POST'])
@login_required
def two_factor():
    if current_user.role != 'client':
        abort(403)
    if not current_user.two_factor_enabled:
        return redirect(url_for('client_dashboard'))

    if request.method == 'POST':
        otp_code = request.form.get('otp_code')
        if current_user.totp_secret and pyotp.TOTP(current_user.totp_secret).verify(otp_code, valid_window=1):
            session['two_factor_verified'] = True
            log_audit('2fa_verified', current_user.id, '2FA validé par TOTP')
            flash('Authentification à deux facteurs validée.', 'success')
            return redirect(url_for('client_dashboard'))
        flash('Code 2FA invalide. Veuillez réessayer.', 'error')

    provisioning_uri = None
    if current_user.totp_secret:
        provisioning_uri = pyotp.totp.TOTP(current_user.totp_secret).provisioning_uri(
            name=f"{current_user.num_client}@boursobank",
            issuer_name='BoursoBank'
        )
    return render_template('two_factor.html', provisioning_uri=provisioning_uri)

@app.route('/api/recuperer_identifiant', methods=['POST'])
def api_recuperer_identifiant():
    data = request.get_json() or {}
    prenom = data.get('prenom', '').strip()
    nom = data.get('nom', '').strip()
    date_naissance = data.get('date_naissance', '').strip() # DD/MM/YYYY
    
    if not prenom or not nom or not date_naissance:
        return {"success": false, "message": "Tous les champs sont requis."}, 400
        
    user = User.query.filter(
        db.func.lower(User.prenom) == prenom.lower(),
        db.func.lower(User.nom) == nom.lower(),
        User.date_naissance == date_naissance,
        User.role == 'client'
    ).first()
    
    if user:
        # Return success with client number
        return {
            "success": True, 
            "num_client": user.num_client,
            "prenom": user.prenom,
            "nom": user.nom
        }
    
    return {"success": False, "message": "Aucun client correspondant trouvé."}


# --- ADMIN ROUTES ---
@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        abort(403)
    clients = User.query.filter_by(role='client').all()
    pending_transfers = Transaction.query.filter(Transaction.status.in_(['PENDING', 'REVIEWING'])).order_by(Transaction.date.desc()).all()
    pending_documents = Document.query.filter(Document.status == 'PENDING').order_by(Document.uploaded_at.desc()).all()
    pending_count = len(pending_transfers)
    pending_docs_count = len(pending_documents)
    return render_template('admin_dashboard.html', clients=clients, pending_count=pending_count, pending_docs_count=pending_docs_count)

@app.route('/admin/review_virements')
@login_required
def admin_review_virements():
    if current_user.role != 'admin':
        abort(403)

    transfers = Transaction.query.filter(Transaction.status.in_(['PENDING', 'REVIEWING'])).order_by(Transaction.date.desc()).all()
    return render_template('admin_review_virements.html', transfers=transfers)

@app.route('/admin/documents')
@login_required
def admin_review_documents():
    if current_user.role != 'admin':
        abort(403)

    documents = Document.query.order_by(Document.uploaded_at.desc()).all()
    return render_template('admin_review_documents.html', documents=documents)

@app.route('/admin/document/review/<int:doc_id>', methods=['POST'])
@login_required
def admin_review_document(doc_id):
    if current_user.role != 'admin':
        abort(403)

    document = Document.query.get_or_404(doc_id)
    action = request.form.get('action')
    review_reason = request.form.get('review_reason', '')

    if action == 'approve':
        document.status = 'APPROVED'
        document.review_reason = review_reason or 'Justificatif validé par l\'administration.'
        subject = 'Justificatif validé'
        message = f'Votre justificatif {document.file_name} a été validé par BoursoBank.'
    elif action == 'reject':
        document.status = 'REJECTED'
        document.review_reason = review_reason or 'Justificatif rejeté par l\'administration.'
        subject = 'Justificatif rejeté'
        message = f'Votre justificatif {document.file_name} n\'a pas été validé. Raison : {review_reason or "Non conforme"}.'
    else:
        flash('Action inconnue pour le document.', 'error')
        return redirect(url_for('admin_review_documents'))

    db.session.commit()
    log_audit('document_reviewed', current_user.id, f'Document {doc_id} {document.status}')
    notify_user(document.user, subject, message)
    flash('Décision enregistrée pour le document.', 'success')
    return redirect(url_for('admin_review_documents'))

@app.route('/admin/document/download/<int:doc_id>')
@login_required
def admin_download_document(doc_id):
    if current_user.role != 'admin':
        abort(403)

    document = Document.query.get_or_404(doc_id)
    if not document.file_path:
        abort(404)

    return send_from_directory(app.config['UPLOAD_FOLDER'], document.file_path, as_attachment=True, download_name=document.file_name)

@app.route('/admin/review_virement/<int:trans_id>', methods=['POST'])
@login_required
def admin_review_virement(trans_id):
    if current_user.role != 'admin':
        abort(403)

    transaction = Transaction.query.get_or_404(trans_id)
    action = request.form.get('action')
    reason = request.form.get('reason') or ''

    if transaction.status not in ['PENDING', 'REVIEWING']:
        flash('Cette transaction a déjà été validée ou rejetée.', 'error')
        return redirect(url_for('admin_review_virements'))

    compte_source = Compte.query.get(transaction.compte_source_id)
    beneficiary_iban = transaction.beneficiary_iban or (transaction.destination.iban if transaction.destination else None)
    compte_dest = Compte.query.filter_by(iban=beneficiary_iban).first() if beneficiary_iban else Compte.query.get(transaction.compte_dest_id)

    if action == 'approve':
        if not compte_source:
            flash('Impossible de valider : compte source introuvable.', 'error')
            return redirect(url_for('admin_review_virements'))
        if compte_source.solde < transaction.montant:
            flash('Solde insuffisant pour valider cette transaction.', 'error')
            return redirect(url_for('admin_review_virements'))

        compte_source.solde -= transaction.montant
        if compte_dest and compte_dest.id != compte_source.id:
            compte_dest.solde += transaction.montant
        transaction.status = 'APPROVED'
        transaction.review_reason = reason or 'Approuvé par l\'administration.'
        db.session.commit()
        log_audit('transfer_approved', current_user.id, f'Transaction {trans_id} approuvée')
        emit_transaction_validated(transaction.id)
        flash('Virement validé et appliqué.', 'success')
    elif action == 'reject':
        transaction.status = 'REJECTED'
        transaction.review_reason = reason or 'Rejeté par l\'administration.'
        db.session.commit()
        log_audit('transfer_rejected', current_user.id, f'Transaction {trans_id} rejetée')
        flash('Virement rejeté.', 'success')
    else:
        flash('Action inconnue pour la transaction.', 'error')

    return redirect(url_for('admin_review_virements'))

@app.route('/admin/create_client', methods=['GET', 'POST'])
@login_required
def admin_create_client():
    if current_user.role != 'admin':
        abort(403)
        
    if request.method == 'POST':
        prenom = request.form.get('prenom')
        nom = request.form.get('nom')
        date_naissance = request.form.get('date_naissance')
        adresse = request.form.get('adresse')
        solde_initial = float(request.form.get('solde', 0.0))
        password = request.form.get('password')
        
        num_client = generate_num_client()
        while User.query.filter_by(num_client=num_client).first():
            num_client = generate_num_client()
            
        new_user = User(
            num_client=num_client, 
            prenom=prenom, 
            nom=nom, 
            date_naissance=date_naissance, 
            adresse=adresse,
            email=request.form.get('email'),
            phone=request.form.get('phone'),
            role='client'
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        iban = generate_iban()
        while Compte.query.filter_by(iban=iban).first():
            iban = generate_iban()
            
        new_compte = Compte(user_id=new_user.id, iban=iban, solde=solde_initial)
        db.session.add(new_compte)
        db.session.commit()
        
        if solde_initial > 0:
            depot = Transaction(
                compte_dest_id=new_compte.id,
                montant=solde_initial,
                type_trans='depot',
                libelle='Dépôt initial'
            )
            db.session.add(depot)
            db.session.commit()
            
        flash(f'Client créé avec succès. Numéro client: {num_client}', 'success')
        return redirect(url_for('admin_dashboard'))
        
    return render_template('create_client.html')

@app.route('/admin/toggle_freeze/<int:user_id>')
@login_required
def toggle_freeze(user_id):
    if current_user.role != 'admin':
        abort(403)
    user = User.query.get_or_404(user_id)
    if user.role != 'admin':
        user.is_frozen = not user.is_frozen
        db.session.commit()
        status = "gelé" if user.is_frozen else "dégelé"
        flash(f'Le compte de {user.prenom} {user.nom} a été {status}.', 'success')
    return redirect(url_for('admin_dashboard'))

# --- CLIENT DETAILS & TRANSACTIONS ---
@app.route('/admin/transaction/<int:user_id>', methods=['GET', 'POST'])
@login_required
def admin_transaction(user_id):
    if current_user.role != 'admin':
        abort(403)
    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        abort(400)
    
    compte = Compte.query.filter_by(user_id=user.id).first()
    
    if request.method == 'POST':
        montant = float(request.form.get('montant'))
        type_trans = request.form.get('type_trans') # 'depot' ou 'retrait' ou 'virement'
        libelle = request.form.get('libelle')
        date_str = request.form.get('date') # Format YYYY-MM-DD
        iban_dest = normalize_iban(request.form.get('iban_dest'))
        beneficiary_email = normalize_optional_text(request.form.get('beneficiary_email'))
        beneficiary_phone = normalize_optional_text(request.form.get('beneficiary_phone'))
        
        try:
            trans_date = datetime.strptime(date_str, '%Y-%m-%d')
        except ValueError:
            trans_date = datetime.utcnow()
            
        if type_trans == 'virement':
            if not iban_dest:
                flash('Veuillez renseigner l\'IBAN du bénéficiaire pour un virement.', 'error')
                return redirect(url_for('admin_transaction', user_id=user.id))
            libelle = f"{libelle} (Vers: {iban_dest})"
            compte.solde -= montant
            
            # Check if internal
            compte_cible = Compte.query.filter_by(iban=iban_dest).first()
            if compte_cible:
                compte_cible.solde += montant
                # Create the mirror transaction for the recipient
                trans_cible = Transaction(
                    compte_dest_id=compte_cible.id,
                    compte_source_id=compte.id,
                    montant=montant,
                    type_trans='virement',
                    libelle=f"Virement reçu de {user.prenom} {user.nom}",
                    date=trans_date
                )
                db.session.add(trans_cible)
                
        elif type_trans == 'retrait':
            compte.solde -= montant
        else:
            compte.solde += montant
            
        transaction = Transaction(
            compte_dest_id=compte.id,
            compte_source_id=compte.id if type_trans == 'retrait' or type_trans == 'virement' else None,
            montant=montant,
            type_trans=type_trans,
            libelle=libelle,
            date=trans_date
        )
        db.session.add(transaction)
        db.session.commit()
        
        flash(f'Transaction ajoutée avec succès pour {user.prenom} {user.nom}.', 'success')
        return redirect(url_for('admin_dashboard'))
        
    return render_template('admin_transaction.html', user=user, compte=compte)

@app.route('/admin/client/<int:user_id>')
@login_required
def admin_client_details(user_id):
    if current_user.role != 'admin':
        abort(403)
    user = User.query.get_or_404(user_id)
    compte = Compte.query.filter_by(user_id=user.id).first()
    
    transactions = []
    if compte:
        transactions = Transaction.query.filter(
            (Transaction.compte_source_id == compte.id) | (Transaction.compte_dest_id == compte.id)
        ).order_by(Transaction.date.desc()).all()
        
    return render_template('admin_client_details.html', user=user, compte=compte, transactions=transactions)

@app.route('/admin/client/delete/<int:user_id>')
@login_required
def admin_delete_client(user_id):
    if current_user.role != 'admin':
        abort(403)
    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        flash('Impossible de supprimer un compte administrateur.', 'error')
        return redirect(url_for('admin_dashboard'))
        
    comptes = Compte.query.filter_by(user_id=user.id).all()
    for compte in comptes:
        Transaction.query.filter((Transaction.compte_source_id == compte.id) | (Transaction.compte_dest_id == compte.id)).delete()
        db.session.delete(compte)
        
    db.session.delete(user)
    db.session.commit()
    
    flash(f'Le compte client de {user.prenom} {user.nom} a été supprimé définitivement.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/transaction/edit/<int:trans_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_transaction(trans_id):
    if current_user.role != 'admin':
        abort(403)
    transaction = Transaction.query.get_or_404(trans_id)
    compte = Compte.query.get(transaction.compte_dest_id)
    user = User.query.get(compte.user_id) if compte else None
    
    if request.method == 'POST':
        old_source_id = transaction.compte_source_id
        old_dest_id = transaction.compte_dest_id
        
        transaction.libelle = request.form.get('libelle')
        transaction.montant = float(request.form.get('montant'))
        transaction.type_trans = request.form.get('type_trans')
        date_str = request.form.get('date')
        
        try:
            transaction.date = datetime.strptime(date_str, '%Y-%m-%d')
        except ValueError:
            pass
            
        db.session.commit()
        
        recalculate_balance(old_source_id)
        recalculate_balance(old_dest_id)
        
        flash('Transaction modifiée avec succès.', 'success')
        return redirect(url_for('admin_client_details', user_id=user.id) if user else url_for('admin_dashboard'))
        
    return render_template('admin_edit_transaction.html', transaction=transaction, user=user)

@app.route('/admin/transaction/delete/<int:trans_id>')
@login_required
def admin_delete_transaction(trans_id):
    if current_user.role != 'admin':
        abort(403)
    transaction = Transaction.query.get_or_404(trans_id)
    source_id = transaction.compte_source_id
    dest_id = transaction.compte_dest_id
    
    compte = Compte.query.get(dest_id)
    user = User.query.get(compte.user_id) if compte else None
    
    db.session.delete(transaction)
    db.session.commit()
    
    recalculate_balance(source_id)
    recalculate_balance(dest_id)
    
    flash('Transaction supprimée définitivement.', 'success')
    return redirect(url_for('admin_client_details', user_id=user.id) if user else url_for('admin_dashboard'))

# --- CLIENT ROUTES ---
@app.route('/dashboard')
@login_required
def client_dashboard():
    if current_user.role != 'client':
        return redirect(url_for('admin_dashboard'))
    
    compte = Compte.query.filter_by(user_id=current_user.id).first()
    transactions = Transaction.query.filter(
        (Transaction.compte_source_id == compte.id) | 
        (Transaction.compte_dest_id == compte.id)
    ).order_by(Transaction.date.desc()).all()
    
    return render_template('client_dashboard.html', compte=compte, transactions=transactions)

@app.route('/virement', methods=['GET', 'POST'])
@login_required
def virement():
    if current_user.role != 'client':
        abort(403)
        
    compte_source = Compte.query.filter_by(user_id=current_user.id).first()
    
    if request.method == 'POST':
        if current_user.is_frozen:
            flash('Opération impossible : Vos mouvements financiers sont gelés. Veuillez contacter votre conseiller.', 'error')
            return redirect(url_for('virement'))
            
        iban_dest = normalize_iban(request.form.get('iban_dest'))
        beneficiary_email = normalize_optional_text(request.form.get('beneficiary_email'))
        beneficiary_phone = normalize_optional_text(request.form.get('beneficiary_phone'))
        try:
            montant = float(request.form.get('montant'))
        except (TypeError, ValueError):
            montant = 0.0
        libelle = request.form.get('libelle')
        
        if montant <= 0:
            flash('Le montant doit être supérieur à 0.', 'error')
            return redirect(url_for('virement'))
            
        if compte_source.solde < montant:
            flash('Solde insuffisant pour effectuer ce virement.', 'error')
            return redirect(url_for('virement'))
            
        if not is_valid_iban_format(iban_dest):
            flash('IBAN bénéficiaire invalide. Vérifiez le format du RIB/IBAN saisi.', 'error')
            return redirect(url_for('virement'))

        compte_dest = Compte.query.filter_by(iban=iban_dest).first()
        is_internal_transfer = compte_dest is not None

        if iban_dest == compte_source.iban:
            flash('Vous ne pouvez pas virer de l\'argent vers le même compte.', 'error')
            return redirect(url_for('virement'))

        status = 'APPROVED'
        review_reason = None
        if montant > TRANSFER_REVIEW_THRESHOLD:
            status = 'REVIEWING'
            review_reason = 'Montant supérieur au seuil de contrôle de 15 000 €.'
        elif is_internal_transfer and compte_dest.client and compte_dest.client.is_frozen:
            status = 'PENDING'
            review_reason = 'Compte bénéficiaire gelé à la date de la demande.'

        if status == 'APPROVED':
            compte_source.solde -= montant
            if is_internal_transfer:
                compte_dest.solde += montant

        transaction = Transaction(
            compte_source_id=compte_source.id,
            compte_dest_id=compte_dest.id if is_internal_transfer else compte_source.id,
            montant=montant,
            type_trans='virement',
            libelle=libelle,
            status=status,
            review_reason=review_reason,
            beneficiary_iban=iban_dest,
            beneficiary_email=beneficiary_email,
            beneficiary_phone=beneficiary_phone
        )
        db.session.add(transaction)
        db.session.commit()
        log_audit('transfer_created', current_user.id, f'Virement de {montant} € vers {iban_dest} statut {status}')
        if status in VALIDATED_TRANSACTION_STATUSES:
            emit_transaction_validated(transaction.id)
        
        if status == 'REVIEWING' or status == 'PENDING':
            flash('Virement créé : il est en attente d\'une validation administrative.', 'success')
        else:
            flash('Virement effectué avec succès.', 'success')
        return redirect(url_for('client_dashboard'))
        
    return render_template('virement.html', compte=compte_source)

@app.route('/profil', methods=['GET', 'POST'])
@login_required
def profil():
    if current_user.role == 'admin':
        flash("La gestion de profil client n'est pas applicable aux administrateurs.", "error")
        return redirect(url_for('admin_dashboard'))
        
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'toggle_2fa':
            if current_user.two_factor_enabled:
                current_user.two_factor_enabled = False
                current_user.totp_secret = None
                db.session.commit()
                log_audit('2fa_disabled', current_user.id, '2FA désactivée par le client')
                flash('L\'authentification à deux facteurs a été désactivée.', 'success')
            else:
                current_user.two_factor_enabled = True
                current_user.totp_secret = generate_totp_secret()
                db.session.commit()
                log_audit('2fa_enabled', current_user.id, '2FA activée par le client')
                flash('2FA activée avec succès. Conservez votre clé secrète en lieu sûr.', 'success')
            return redirect(url_for('profil'))

        if action == 'upload_document':
            file = request.files.get('document')
            type_doc = request.form.get('type_doc', 'Justificatif')
            if not file or not file.filename:
                flash('Aucun fichier sélectionné pour le téléchargement.', 'error')
                return redirect(url_for('profil'))
            if not allowed_file(file.filename):
                flash('Type de fichier non autorisé. Utilisez PDF, JPG, PNG, DOC ou DOCX.', 'error')
                return redirect(url_for('profil'))

            filename = secure_filename(file.filename)
            timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
            storage_name = f"{current_user.id}_{timestamp}_{filename}"
            storage_path = os.path.join(app.config['UPLOAD_FOLDER'], storage_name)
            file.save(storage_path)

            document = Document(
                user_id=current_user.id,
                file_name=filename,
                file_path=storage_name,
                type_doc=type_doc,
                status='PENDING'
            )
            db.session.add(document)
            db.session.commit()
            log_audit('document_uploaded', current_user.id, f'Justificatif {filename} uploadé')
            notify_user(current_user, 'Justificatif reçu', f'Votre document {filename} a bien été reçu et sera validé par nos équipes.')
            flash('Document reçu avec succès. Le traitement est en cours.', 'success')
            return redirect(url_for('profil'))

        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not current_user.check_password(old_password):
            flash("L'ancien code confidentiel est incorrect.", "error")
            return redirect(url_for('profil'))
            
        if len(new_password) < 6:
            flash("Le nouveau code confidentiel doit faire au moins 6 caractères.", "error")
            return redirect(url_for('profil'))
            
        if new_password != confirm_password:
            flash("La confirmation du nouveau code confidentiel ne correspond pas.", "error")
            return redirect(url_for('profil'))
            
        current_user.set_password(new_password)
        db.session.commit()
        flash("Votre code confidentiel a été modifié avec succès !", "success")
        return redirect(url_for('profil'))
        
    documents = Document.query.filter_by(user_id=current_user.id).order_by(Document.uploaded_at.desc()).all()
    return render_template('profil.html', documents=documents)

@app.route('/aide')
@login_required
def aide():
    return render_template('aide.html')

@app.route('/offre')
@login_required
def offre():
    return render_template('offre.html')

def setup_database():
    with app.app_context():
        db.create_all()
        # Force la mise à jour de la colonne password_hash si elle est trop courte
        # (cas où la table existait déjà avec VARCHAR(128) depuis un ancien déploiement)
        try:
            db.session.execute(db.text('ALTER TABLE "user" ALTER COLUMN password_hash TYPE VARCHAR(255)'))
            db.session.commit()
        except Exception:
            db.session.rollback()

        # Add new user columns when migrating from older schema
        additional_columns = [
            ('user', 'cgu_accepted', 'BOOLEAN DEFAULT FALSE'),
            ('user', 'cgu_accepted_at', 'DATETIME'),
            ('user', 'two_factor_enabled', 'BOOLEAN DEFAULT FALSE'),
            ('user', 'totp_secret', 'VARCHAR(64)'),
            ('user', 'email', 'VARCHAR(255)'),
            ('user', 'phone', 'VARCHAR(40)'),
            ('transaction', 'status', "VARCHAR(20) DEFAULT 'APPROVED'"),
            ('transaction', 'review_reason', 'VARCHAR(255)'),
            ('transaction', 'beneficiary_iban', 'VARCHAR(34)'),
            ('transaction', 'beneficiary_email', 'VARCHAR(255)'),
            ('transaction', 'beneficiary_phone', 'VARCHAR(40)')
        ]

        for table_name, column_name, column_type in additional_columns:
            try:
                db.session.execute(db.text(f'ALTER TABLE "{table_name}" ADD COLUMN {column_name} {column_type}'))
                db.session.commit()
            except Exception:
                db.session.rollback()

        # Création de l'admin par défaut s'il n'existe pas
        if not User.query.filter_by(role='admin').first():
            admin = User(
                num_client='ADMIN001',
                prenom='Admin',
                nom='BoursoBank',
                date_naissance='01/01/1990',
                adresse='Siège Social BoursoBank',
                role='admin'
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("Administrateur BoursoBank créé : Numéro client 'ADMIN001', Mot de passe 'admin123'")

setup_database()

if __name__ == '__main__':
    app.run(debug=True)
