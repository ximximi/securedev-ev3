import sqlite3

def crear_base_de_datos():
    conexion = sqlite3.connect('vulnerable.db')
    cursor = conexion.cursor()
    
    cursor.execute('DROP TABLE IF EXISTS usuarios')
    cursor.execute('''
        CREATE TABLE usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            rol TEXT NOT NULL,
            bio TEXT
        )
    ''')
    
    # Usuarios de prueba: el admin tiene una contraseña "fuerte" pero es vulnerable a SQLi
    usuarios = [
        ('admin', 'admin123', 'admin', 'Cuenta de administrador del sistema.'),
        ('alumno', '12345', 'user', 'Soy un estudiante aprendiendo hacking.')
    ]
    
    cursor.executemany('INSERT INTO usuarios (username, password, rol, bio) VALUES (?, ?, ?, ?)', usuarios)
    conexion.commit()
    conexion.close()
    print("Base de datos inicializada con sistema de roles.")

if __name__ == "__main__":
    crear_base_de_datos()
