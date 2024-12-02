import os
import hashlib
import jwt
import datetime
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate  # Импортируем Migrate для работы с миграциями
from functools import wraps
import io

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Этот ключ используется для подписи JWT
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://edo_db:9CxmsGqtplllIiNHeLWQRNlLQfv7IfAE@dpg-ct67sblumphs73949hd0-a/edo_db'
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


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, default=db.func.current_timestamp())
    hash = db.Column(db.String(255), unique=True, nullable=False)
    data = db.Column(db.LargeBinary)  # Столбец для хранения данных файла

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
            token = jwt.encode({'id': admin.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm="HS256")
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
    if file.data:
        try:
            # Выводим файл для просмотра и предоставляем ссылку для скачивания
            return render_template('view_file.html', file=file)
        except Exception as e:
            flash(f'Ошибка при отображении файла: {e}', 'error')
            return redirect(url_for('admin_dashboard'))
    flash('Файл не найден', 'error')
    return redirect(url_for('admin_dashboard'))

# Логин/Логаут администратора
@app.route('/logout')
def logout():
    session.pop('token', None)  # Удаляем токен из сессии
    return redirect(url_for('index'))  # Правильное имя функции


# Инициализация базы данных и создание таблиц
with app.app_context():
    db.create_all()

# Старт сервера
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8000))
    app.run(host='0.0.0.0', port=port, debug=True)
