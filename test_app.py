import os
import sys
from app import app, db, User, Compte
from flask_login import login_user

def test_user_routes():
    print("Testing client routes...")
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    
    with app.app_context():
        # Clean/Find client user
        client_user = User.query.filter_by(num_client='1234567890').first()
        if client_user:
            db.session.delete(client_user)
            db.session.commit()
            
        client_user = User(
            num_client='1234567890',
            prenom='Test',
            nom='User',
            date_naissance='01/01/2000',
            adresse='Test Address',
            role='client'
        )
        client_user.set_password('pass123')
        db.session.add(client_user)
        db.session.commit()
        
        compte = Compte(user_id=client_user.id, iban='FR76300040000100000000012', solde=1000.0)
        db.session.add(compte)
        db.session.commit()
        
        client_id = client_user.id
        num_client = client_user.num_client
        print(f"Using client user: {client_user.prenom} {client_user.nom} ({num_client})")

        with app.test_client() as client:
            # Login the user via session transaction
            with client.session_transaction() as sess:
                sess['_user_id'] = str(client_id)
                sess['_fresh'] = True
            
            # Test dashboard
            dash_res = client.get('/dashboard')
            print(f"GET /dashboard: {dash_res.status_code}")
            
            # Test profil GET
            prof_res = client.get('/profil')
            print(f"GET /profil: {prof_res.status_code}")
            
            # Test profil POST (Change password)
            print("Sending POST /profil (changing password)...")
            change_res = client.post('/profil', data={
                'old_password': 'pass123',
                'new_password': 'newpassword123',
                'confirm_password': 'newpassword123'
            }, follow_redirects=True)
            print(f"POST /profil: {change_res.status_code}")
            
            # Check if password actually changed in DB
            db.session.refresh(client_user)
            check_ok = client_user.check_password('newpassword123')
            print(f"Is new password correct in database? {check_ok}")
            
            # Clean up
            db.session.delete(client_user)
            db.session.commit()

if __name__ == '__main__':
    test_user_routes()
