from app import app, db, User  # Adjust if your app file/module name is different
from sqlalchemy import func

with app.app_context():
    # Filter users where the password length is < 60 (not hashed)
    test_users = User.query.filter(func.length(User.password) < 60).all()

    for user in test_users:
        print(f"Deleting user: {user.username} (email: {user.email})")
        db.session.delete(user)

    db.session.commit()
    print(f"Deleted {len(test_users)} test users.")
