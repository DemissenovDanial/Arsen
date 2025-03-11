import os
import hashlib
import jwt
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session, flash, jsonify, send_file, Response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate  # Импортируем Migrate для работы с миграциями
from functools import wraps
import io
import mimetypes
from werkzeug.utils import secure_filename
from docx import Document  # Для обработки DOCX файлов
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Этот ключ используется для подписи JWT
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://edo_db:PQZio1aN7d3m2xB2Y5zrowU53M1SOAz1@dpg-cv824dqj1k6c73bjb5e0-a/edo_db_lsx9'
app.config['SQLALCHEMY_ECHO'] = True  # Включает вывод SQL-запросов в консоль

db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Инициализируем миграции

# Модели данных
class Admins(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)
        
def load_admins_from_json():
    try:
        # Открываем файл admins.json
        with open('admins.json', 'r') as f:
            admins_data = json.load(f)  # Загружаем данные из JSON

        for admin in admins_data:
            username = admin.get('username')
            password = admin.get('password')

            if username and password:
                # Проверяем, существует ли администратор в базе данных
                existing_admin = Admins.query.filter_by(username=username).first()
                if not existing_admin:
                    # Если администратора нет, добавляем его с хешированным паролем
                    new_admin = Admins(username=username)
                    new_admin.set_password(password)  # Хешируем и сохраняем пароль
                    db.session.add(new_admin)
        db.session.commit()  # Сохраняем изменения в базе данных
        print("Администраторы успешно загружены из файла admins.json")
    except FileNotFoundError:
        print("Файл admins.json не найден. Проверьте наличие файла в папке.")
    except json.JSONDecodeError:
        print("Ошибка декодирования файла admins.json. Проверьте формат файла.")
    except Exception as e:
        print(f"Произошла ошибка: {e}")


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    hash = db.Column(db.String(255), unique=True, nullable=False)
    data = db.Column(db.LargeBinary)  # Столбец для хранения данных файла

def extract_text_from_docx(file_data):
    doc = Document(io.BytesIO(file_data))
    text_content = []
    for para in doc.paragraphs:
        text_content.append(para.text)
    return '\n'.join(text_content)

# Функция для проверки JWT токена
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('x-access-token') or session.get('token')  # Проверяем заголовок или сессию
        if not token:
            return jsonify({'message': 'Токен отсутствует!'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Admins.query.filter_by(id=data['id']).first()
            if not current_user:
                return jsonify({'message': 'Пользователь не найден!'}), 403
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Срок действия токена истёк!'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Недействительный токен!'}), 403
        return f(current_user, *args, **kwargs)
    return decorated_function

@app.after_request
def add_headers(response: Response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Cache-Control'] = 'public, max-age=86400'  # кешировать на 1 день
    return response
    
# Страница для входа
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        return redirect(url_for('login'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin = Admins.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password, password):
            token = jwt.encode({'id': admin.id, 'exp': datetime.utcnow() + timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm="HS256")
            session['token'] = token  # Сохраняем токен в сессии
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Неверный логин или пароль', 'error')
    return render_template('login.html')


# Страница админ панели (управление файлами)
@app.route('/admin')
@token_required
def admin_dashboard(current_user):
    if not current_user:
        flash('Необходима авторизация!', 'error')
        return redirect(url_for('login'))
    files = File.query.all()
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
        file_hash = hashlib.sha256(file.filename.encode()).hexdigest()

        # Чтение данных файла в байты
        file_data = file.read()
        if not file_data:
            flash('Не удалось прочитать данные файла', 'error')
            return redirect(url_for('admin_dashboard'))

        # Сохраняем информацию о файле в базу данных
        new_file = File(filename=file.filename, hash=file_hash, data=file_data)
        try:
            db.session.add(new_file)
            db.session.commit()
            flash('Файл успешно загружен в базу данных', 'success')
        except Exception as e:
            flash(f'Ошибка при сохранении файла в базе данных: {e}', 'error')

        return redirect(url_for('admin_dashboard'))



# Удаление файла
@app.route('/delete/<int:file_id>', methods=['POST'])
@token_required
def delete_file(current_user, file_id):
    file = File.query.get(file_id)
    if file:
        try:
            db.session.delete(file)
            db.session.commit()
            flash('Файл успешно удален', 'success')
        except Exception as e:
            flash(f'Ошибка при удалении файла: {e}', 'error')
    else:
        flash('Файл не найден', 'error')

    return redirect(url_for('admin_dashboard'))


# Скачивание файла по хешу
@app.route('/download/<file_hash>')
def download(file_hash):
    file = File.query.filter_by(hash=file_hash).first_or_404()
    if file.data:
        try:
            return send_file(io.BytesIO(file.data), as_attachment=True, download_name=file.filename)
        except Exception as e:
            flash(f'Ошибка при отправке файла: {e}', 'error')
            return redirect(url_for('admin_dashboard'))
    flash('Файл не найден', 'error')
    return redirect(url_for('admin_dashboard'))

# Просмотр и скачивание файла
@app.route('/view/<file_hash>')
def view_file(file_hash):
    file = File.query.filter_by(hash=file_hash).first_or_404()

    # Определяем MIME тип файла
    mime_type, _ = mimetypes.guess_type(file.filename)

    # Логика обработки типов файлов
    if mime_type and mime_type.startswith('image'):
        file_type = 'image'
        text_content = None
    elif mime_type == 'text/plain':
        file_type = 'text'
        text_content = file.data.decode('utf-8')
    elif mime_type == 'application/pdf':
        file_type = 'pdf'
        text_content = None
    elif mime_type == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
        file_type = 'docx'
        try:
            text_content = extract_text_from_docx(file.data)
        except Exception as e:
            text_content = f"Ошибка при чтении файла: {e}"
    else:
        file_type = 'other'
        text_content = None

    # Отправляем данные в шаблон
    return render_template('view_file.html', file=file, file_type=file_type, text_content=text_content)


@app.route('/serve/<file_hash>')
def serve_file_data(file_hash):
    """Служебный маршрут для отдачи данных файла."""
    file = File.query.filter_by(hash=file_hash).first_or_404()

    # Определяем MIME тип
    mime_type, _ = mimetypes.guess_type(file.filename)

    # Отправляем файл с соответствующим MIME типом
    return send_file(io.BytesIO(file.data), mimetype=mime_type, download_name=file.filename)


# Логин/Логаут администратора
@app.route('/logout')
def logout():
    session.pop('token', None)  # Удаляем токен из сессии
    return redirect(url_for('index'))  # Правильное имя функции


# Инициализация базы данных и создание таблиц
with app.app_context():
    db.create_all()
    load_admins_from_json() 

# Старт сервера
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8000))
    app.run(host='0.0.0.0', port=port, debug=True)
