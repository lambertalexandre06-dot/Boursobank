from app import app, db, User, Compte

def read_database():
    with app.app_context():
        users = User.query.all()
        print("--- Registered Users ---")
        for u in users:
            print(f"ID: {u.id} | Client Num: {u.num_client} | Name: {u.prenom} {u.nom} | Role: {u.role} | Frozen: {u.is_frozen}")
            for c in u.comptes:
                print(f"  -> IBAN: {c.iban} | Balance: {c.solde} EUR")
        print("------------------------")

if __name__ == '__main__':
    read_database()
