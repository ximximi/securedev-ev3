from flask import Flask, request, render_template_string, redirect, make_response
import sqlite3

app = Flask(__name__)

def db_query(query):
    """Función auxiliar para ejecutar queries (Vulnerable por diseño)"""
    conn = sqlite3.connect('vulnerable.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    # Aquí ocurre el SQLi: ejecutamos la string tal cual viene
    cursor.execute(query)
    result = cursor.fetchall()
    conn.commit()
    conn.close()
    return result

# --- LOGIN (Vulnerable a SQL Injection) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('username')
        pw = request.form.get('password')
        
        # El SQLi clásico: saltarse el password con ' OR '1'='1
        query = f"SELECT * FROM usuarios WHERE username = '{user}' AND password = '{pw}'"
        usuarios = db_query(query)
        
        if usuarios:
            usuario = usuarios[0]
            resp = make_response(redirect('/dashboard'))
            # Vulnerable: Cookie de sesión en texto plano y sin flags de seguridad
            resp.set_cookie('user_session', usuario['username'])
            return resp
        return "<h3>Acceso denegado</h3><a href='/login'>Volver</a>", 401

    return '''
        <h2>Login del Sistema Académico</h2>
        <form method="post">
            Usuario: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Ingresar">
        </form>
    '''

# --- DASHBOARD (Vulnerable a XSS y CSRF) ---
@app.route('/dashboard')
def dashboard():
    username = request.cookies.get('user_session')
    if not username:
        return redirect('/login')

    # Buscamos los datos del usuario logueado
    datos = db_query(f"SELECT * FROM usuarios WHERE username = '{username}'")[0]

    # Vulnerabilidad XSS: render_template_string no escapa variables puestas con f-strings
    html = f"""
    <h1>Panel de {datos['username']}</h1>
    <p><b>Rol:</b> {datos['rol']}</p>
    <p><b>Biografía:</b> {datos['bio']}</p>
    <hr>
    <h3>Actualizar Biografía (Objetivo CSRF)</h3>
    <form action="/update_bio" method="POST">
        <input type="text" name="nueva_bio" placeholder="Escribe algo...">
        <input type="submit" value="Guardar Cambios">
    </form>
    <br><a href="/logout">Cerrar Sesión</a>
    """
    return render_template_string(html)

@app.route('/update_bio', methods=['POST'])
def update_bio():
    username = request.cookies.get('user_session')
    if username:
        nueva_bio = request.form.get('nueva_bio')
        # Vulnerable a CSRF: No hay token de validación
        db_query(f"UPDATE usuarios SET bio = '{nueva_bio}' WHERE username = '{username}'")
    return redirect('/dashboard')

@app.route('/logout')
def logout():
    resp = make_response(redirect('/login'))
    resp.set_cookie('user_session', '', expires=0)
    return resp

@app.route('/')
def home():
    return redirect('/login')

if __name__ == '__main__':
    # Ejecución en modo debug para fines académicos
    app.run(debug=True, port=5000)
