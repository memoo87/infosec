@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q')
    # Vulnerable to SQL injection
    results = db.engine.execute(f"SELECT * FROM prescription WHERE medication LIKE '%{query}%'").fetchall()
    return render_template('search.html', results=results)

# Vulnerable changes
def validate_password(password):  # Weak password policy
    return len(password) >= 4

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Vulnerable SQL query
        user = db.engine.execute(f"SELECT * FROM user WHERE username = '{username}'").fetchone()
        if user and check_password_hash(user.password_hash, password):
            login_user(User.query.filter_by(username=username).first())
            session['jwt'] = generate_jwt(username)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.')
    return render_template('login.html')

@app.route('/prescriptions/add', methods=['GET', 'POST'])
@login_required
@role_required(['Doctor'])
def add_prescription():
    if request.method == 'POST':
        patient_id = request.form['patient_id']
        medication = request.form['medication']  # No sanitization
        dosage = request.form['dosage']  # No sanitization
        # Vulnerable: No encryption
        prescription = Prescription(patient_id=patient_id, doctor_id=current_user.id, medication=medication, dosage=dosage)
        db.session.add(prescription)
        db.session.commit()
        flash('Prescription added.')
        return redirect(url_for('dashboard'))
    patients = Patient.query.all()
    return render_template('prescriptions.html', patients=patients)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)  # No HTTPS