from flask import Flask, request, render_template_string, redirect, session, abort
import sqlite3
import secrets
import os

app = Flask(__name__)
# Clave secreta para firmar sesiones y proteger cookies
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

def db_query(query, params=()):
    """Función segura usando consultas parametrizadas"""
    conn = sqlite3.connect('vulnerable.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(query, params)
    result = cursor.fetchall()
    conn.commit()
    conn.close()
    return result

@app.after_request
def add_security_headers(response):
    """Cabeceras de seguridad recomendadas (mitigación para OWASP ZAP)"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

# --- LOGIN (Mitigado contra SQLi y cookies inseguras) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('username', '')
        pw = request.form.get('password', '')

        query = "SELECT * FROM usuarios WHERE username = ? AND password = ?"
        usuarios = db_query(query, (user, pw))

        if usuarios:
            usuario = usuarios[0]
            session['user_session'] = usuario['username']
            session['csrf_token'] = secrets.token_hex(32)
            return redirect('/dashboard')
        return "<h3>Acceso denegado</h3><a href='/login'>Volver</a>", 401

    return '''
        <h2>Login del Sistema Académico</h2>
        <form method="post">
            Usuario: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Ingresar">
        </form>
    '''

# --- DASHBOARD (Mitigado contra XSS y CSRF) ---
@app.route('/dashboard')
def dashboard():
    username = session.get('user_session')
    if not username:
        return redirect('/login')

    resultados = db_query("SELECT * FROM usuarios WHERE username = ?", (username,))
    if not resultados:
        return redirect('/logout')
    datos = resultados[0]

    # Jinja2 escapa automáticamente las variables pasadas como argumentos
    template = """
    <h1>Panel de {{ username }}</h1>
    <p><b>Rol:</b> {{ rol }}</p>
    <p><b>Biografía:</b> {{ bio }}</p>
    <hr>
    <h3>Actualizar Biografía</h3>
    <form action="/update_bio" method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <input type="text" name="nueva_bio" placeholder="Escribe algo...">
        <input type="submit" value="Guardar Cambios">
    </form>
    <br><a href="/logout">Cerrar Sesión</a>
    """
    return render_template_string(
        template,
        username=datos['username'],
        rol=datos['rol'],
        bio=datos['bio'],
        csrf_token=session.get('csrf_token', '')
    )

@app.route('/update_bio', methods=['POST'])
def update_bio():
    username = session.get('user_session')
    if not username:
        return redirect('/login')

    # Validación de token CSRF
    token_enviado = request.form.get('csrf_token', '')
    if not token_enviado or token_enviado != session.get('csrf_token'):
        abort(403, description="Token CSRF inválido")

    nueva_bio = request.form.get('nueva_bio', '')
    db_query("UPDATE usuarios SET bio = ? WHERE username = ?", (nueva_bio, username))
    return redirect('/dashboard')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/')
def home():
    return redirect('/login')

if __name__ == '__main__':
    # Modo debug desactivado para entorno de producción
    app.run(debug=False, port=5000)
