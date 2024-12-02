import os
import hashlib
import jwt
import datetime
import json
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'  # This key is used to sign the JWT
app.config['UPLOAD_FOLDER'] = 'uploads'

# Путь к JSON-файлам для хранения данных
ADMIN_DATA_FILE = 'admins.json'
FILES_DATA_FILE = 'files.json'

# Функция для загрузки данных из JSON
def load_data(file_path):
    if not os.path.exists(file_path):
        return []
    with open(file_path, 'r') as file:
        return json.load(file)

# Функция для сохранения данных в JSON
def save_data(file_path, data):
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)

# Инициализация данных
admins = load_data(ADMIN_DATA_FILE)
files = load_data(FILES_DATA_FILE)

# Функция для проверки токена
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('x-access-token') or session.get('token')  # Проверяем заголовок или сессию
        if not token:
            return jsonify({'message': 'Токен отсутствует!'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = next((admin for admin in admins if admin['id'] == data['id']), None)
            if not current_user:
                return jsonify({'message': 'Пользователь не найден!'}), 403
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Срок действия токена истёк!'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Недействительный токен!'}), 403
        return f(current_user, *args, **kwargs)
    return decorated_function

# Страница для входа
@app.route('/', methods=['GET', 'POST'])
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin = next((admin for admin in admins if admin['username'] == username), None)
        if admin and check_password_hash(admin['password'], password):
            token = jwt.encode({'id': admin['id'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm="HS256")
            session['token'] = token  # Сохранение токена в сессии
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Неверный логин или пароль', 'error')
    return render_template('login.html')

# Админ-панель
@app.route('/admin')
@token_required
def admin_dashboard(current_user):
    return render_template('admin_dashboard.html', files=files, current_user=current_user)

# Загрузка файла
@app.route('/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    if 'file' not in request.files:
        flash('Нет файла для загрузки', 'error')
        return redirect(url_for('admin_dashboard'))

    file = request.files['file']
    if file.filename == '':
        flash('Нет выбранного файла', 'error')
        return redirect(url_for('admin_dashboard'))

    if file:
        # Генерация хеша для файла
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        file_hash = hashlib.sha256(file.filename.encode()).hexdigest()
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        # Сохраняем информацию о файле
        new_file = {
            'id': len(files) + 1,
            'filename': file.filename,
            'upload_date': str(datetime.datetime.utcnow()),
            'hash': file_hash
        }
        files.append(new_file)
        save_data(FILES_DATA_FILE, files)

        flash('Файл успешно загружен', 'success')
        return redirect(url_for('admin_dashboard'))

# Удаление файла
@app.route('/delete/<file_hash>', methods=['POST'])
@token_required
def delete_file(current_user, file_hash):
    global files
    file = next((f for f in files if f['hash'] == file_hash), None)
    if file:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file['filename']))
            files = [f for f in files if f['hash'] != file_hash]
            save_data(FILES_DATA_FILE, files)
            flash('Файл успешно удален', 'success')
        except Exception as e:
            flash(f'Ошибка при удалении файла: {e}', 'error')
    else:
        flash('Файл не найден', 'error')

    return redirect(url_for('admin_dashboard'))

# Скачивание файла по хешу
@app.route('/download/<file_hash>')
def download(file_hash):
    file = next((f for f in files if f['hash'] == file_hash), None)
    if file:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
        if os.path.exists(file_path):
            return send_from_directory(app.config['UPLOAD_FOLDER'], file['filename'])
    flash('Файл не найден', 'error')
    return redirect(url_for('admin_dashboard'))

# Логин/Логаут администратора
@app.route('/logout')
def logout():
    session.pop('token', None)  # Удаляем токен из сессии
    return redirect(url_for('index'))

# Добавить администратора (ручное добавление через API)
@app.route('/add_admin', methods=['POST'])
def add_admin():
    username = request.json.get('username')
    password = request.json.get('password')
    if not username or not password:
        return jsonify({'message': 'Имя пользователя и пароль обязательны!'}), 400

    new_admin = {
        'id': len(admins) + 1,
        'username': username,
        'password': generate_password_hash(password)
    }
    admins.append(new_admin)
    save_data(ADMIN_DATA_FILE, admins)
    return jsonify({'message': 'Администратор успешно добавлен!'})

# Старт сервера
if __name__ == '__main__':
    if not os.path.exists(ADMIN_DATA_FILE):
        save_data(ADMIN_DATA_FILE, [])  # Создаём файл с администраторами
    if not os.path.exists(FILES_DATA_FILE):
        save_data(FILES_DATA_FILE, [])  # Создаём файл с файлами
    port = int(os.environ.get("PORT", 8000))
    app.run(host='0.0.0.0', port=port, debug=True)
