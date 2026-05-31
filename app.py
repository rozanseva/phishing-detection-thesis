from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
import io
import base64
import pandas as pd
import matplotlib.pyplot as plt

app = Flask(__name__)
app.secret_key = 'key'  #  ключ

# Настройка Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Простая модель пользователя
class User(UserMixin):
    def __init__(self, id, username, password_hash, otp_secret):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.otp_secret = otp_secret

# Администратор с паролем и секретом 2FA
admin_user = User(
    id='admin',
    username='admin',
    password_hash=generate_password_hash('admin'),  # пароль
    otp_secret=pyotp.random_base32()
)

users = {admin_user.id: admin_user}

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

# Маршрут для логина
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = next((u for u in users.values() if u.username == username), None)
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('two_factor'))
        else:
            flash('Неверный логин или пароль', 'error')
    return render_template('login.html')

# Двухфакторная аутентификация
@app.route('/two_factor', methods=['GET', 'POST'])
@login_required
def two_factor():
    totp = pyotp.TOTP(current_user.otp_secret)

    if request.method == 'POST':
        token = request.form.get('token')
        if totp.verify(token):
            # Прошел всю аутентификацию, открываем доступ
            return redirect(url_for('index'))
        else:
            flash('Неверный код 2FA', 'error')
            logout_user()
            return redirect(url_for('login'))

    # Генерация QR кода для настройки 2FA
    otp_uri = totp.provisioning_uri(name=current_user.username, issuer_name="ВашПроект")
    img = qrcode.make(otp_uri)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    img_b64 = base64.b64encode(buf.read()).decode('utf-8')

    return render_template('two_factor.html', qr_code=img_b64)

# Основной защищённый маршрут с отчётом
@app.route('/')
@login_required
def index():
    df = pd.read_csv("analysis_report.csv")
    img = None
    if not df.empty:
        fig, ax = plt.subplots(figsize=(8,4))
        df['Уровень риска'].plot(
            kind='hist',
            bins=range(0, df['Уровень риска'].max()+2),
            rwidth=0.8,
            ax=ax,
            color='salmon',
            title='Распределение уровня риска писем'
        )
        ax.set_ylabel('Количество писем')
        ax.set_xlabel('Уровень риска')
        plt.tight_layout()
        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        buf.seek(0)
        img = base64.b64encode(buf.read()).decode('utf-8')
        plt.close(fig)
    return render_template('index.html', tables=[df.head(20).to_html(classes='data', index=False)], img=img)

# Маршрут добавления разметки
@app.route('/add_label', methods=['POST'])
@login_required
def add_label():
    subject = request.form['subject']
    body = request.form['body']
    label = int(request.form['label'])  # 1 - фишинг, 0 - не фишинг
    with open("custom_training.csv", "a", encoding="utf-8") as f:
        f.write(f"{subject}\t{body}\t{label}\n")
    return redirect(url_for('index'))

# Выход из системы
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    print(f"Ключ для 2FA (добавьте в приложение-генератор): {admin_user.otp_secret}")
    app.run(debug=True, ssl_context=None)  
