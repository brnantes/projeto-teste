from app import app, db
from flask import render_template, request, flash, redirect, url_for
from flask_login import login_required
from models import Token

@app.route('/create_token', methods=['GET', 'POST'])
@login_required
def create_token():
    if request.method == 'POST':
        action = request.form['action']
        token = generate_token(action)
        new_token = Token(action=action, token=token)
        db.session.add(new_token)
        db.session.commit()
        flash(f'Token {token} criado com sucesso!')
        return redirect(url_for('dashboard'))
    return render_template('create_token.html')

@app.route('/validate_token', methods=['GET', 'POST'])
@login_required
def validate_token():
    if request.method == 'POST':
        token = request.form['token']
        valid_token = Token.query.filter_by(token=token).first()
        if valid_token:
            flash('Token válido!')
        else:
            flash('Token inválido!')
    return render_template('validate_token.html')

def generate_token(action):
    # Gera token no formato "quita-9xiu-p098"
    import random, string
    token = f"{action[:5]}-{''.join(random.choices(string.ascii_lowercase + string.digits, k=8))}"
    return token
