#уралвагонзовод  концерн калашникова



import csv
import hashlib
import io
import logging
import os
import re
import secrets
import datetime
import uvicorn

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.templating import Jinja2Templates
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.exception_handlers import http_exception_handler
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware
from PIL import Image, ImageOps

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


USERS_FILE = 'user.csv'        
SECRET_FILE = '.secret_key'   
MIN_PASSWORD, MAX_PASSWORD = 8, 64
MIN_NAME, MAX_NAME = 2, 50
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

# Аватары
AVATAR_DIR = 'avatars'                  # папка для аватаров
AVATAR_SIZE = 256                       # аватар делаем квадратом 256×256
MAX_AVATAR_BYTES = 5 * 1024 * 1024      # не больше 5 МБ

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[logging.FileHandler('sessions.log', encoding='utf-8'), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


def generate_or_load_cert():
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return KEY_FILE, CERT_FILE

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "BY"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Minsk"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Minsk"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FastAPI In-Memory"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.DNSName("10.100.0.2")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    with open(KEY_FILE, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return KEY_FILE, CERT_FILE


def get_secret_key():
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, encoding='utf-8') as f:
            key = f.read().strip()
        if key:
            return key
    key = secrets.token_hex(32)
    with open(SECRET_FILE, 'w', encoding='utf-8') as f:
        f.write(key)
    return key


app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=get_secret_key(), max_age=1500, same_site='lax')
app.mount('/static', StaticFiles(directory='static'), name='static')
app.mount('/sources', StaticFiles(directory='sources'), name='sources')
templates = Jinja2Templates(directory='templates')


#  Пользователи
def read_users():
    if not os.path.exists(USERS_FILE):
        return []
    with open(USERS_FILE, encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))


def find_user(email):
    for user in read_users():
        if user['email'] == email:
            return user
    return None


def add_user(name, email, password):
    new_file = not os.path.exists(USERS_FILE)
    with open(USERS_FILE, 'a', encoding='utf-8-sig', newline='') as f:
        writer = csv.writer(f)
        if new_file:
            writer.writerow(['name', 'email', 'password'])
        writer.writerow([name, email, hash_password(password)])


#  Пароли 
def make_hash(password, salt):
    return hashlib.sha256((salt + password).encode('utf-8')).hexdigest()


def hash_password(password):
    salt = secrets.token_hex(8)
    return salt + '$' + make_hash(password, salt)


def check_password(password, saved):
    salt = saved.split('$')[0]
    return saved == salt + '$' + make_hash(password, salt)


#  Проверка данных регистрации
def check_name(name):
    if len(name) < MIN_NAME:
        return f'Введите имя (минимум {MIN_NAME} символа)'
    if len(name) > MAX_NAME:
        return f'Имя слишком длинное (максимум {MAX_NAME} символов)'


def check_email(email):
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email):
        return 'Некорректный email'


def check_password_strength(password):
    if len(password) < MIN_PASSWORD:
        return f'Пароль должен быть не короче {MIN_PASSWORD} символов'
    if len(password) > MAX_PASSWORD:
        return f'Пароль слишком длинный (не больше {MAX_PASSWORD} символов)'
    if not re.search(r'[A-Za-zА-Яа-яЁё]', password):
        return 'В пароле должна быть хотя бы одна буква'
    if not re.search(r'[0-9]', password):
        return 'В пароле должна быть хотя бы одна цифра'


#  Аватары
def avatar_path(email):
    # Имя файла — отпечаток почты, а не имя от пользователя: так нельзя подсунуть свой путь
    return os.path.join(AVATAR_DIR, hashlib.sha256(email.encode('utf-8')).hexdigest() + '.png')


def save_avatar(email, data):
    """Делает из присланных байтов квадратную PNG-картинку. True — получилось, False — это не картинка."""
    try:
        img = Image.open(io.BytesIO(data))
        img = ImageOps.exif_transpose(img)                                   # повернуть, как снято на телефон
        img = ImageOps.fit(img.convert('RGBA'), (AVATAR_SIZE, AVATAR_SIZE))  # обрезать до квадрата
    except Exception:
        return False
    os.makedirs(AVATAR_DIR, exist_ok=True)
    img.save(avatar_path(email), 'PNG')                                      # сохраняем заново — лишнее пропадает
    logger.info(f'Аватар обновлён | email={email}')
    return True


#  Сессии 

active_sessions = set()


def client_ip(request):
    return request.client.host if request.client else 'неизвестен'


def start_session(request, email):
    end_session(request)                         
    sid = secrets.token_hex(16)
    active_sessions.add(sid)
    request.session['sid'] = sid
    request.session['user_email'] = email
    logger.info(f'Сессия создана | email={email}')


def end_session(request):
    email = request.session.get('user_email')
    active_sessions.discard(request.session.get('sid'))
    request.session.clear()
    if email:
        logger.info(f'Сессия завершена | email={email}')


def session_email(request):
    sid = request.session.get('sid')
    email = request.session.get('user_email')
    if email and sid in active_sessions:
        return email
    if email:
        logger.warning(f'Устаревшая сессия | email={email}')
    return None


def get_user(request):
    email = session_email(request)
    if email is None:
        return None
    user = find_user(email)
    if user is None:                           
        end_session(request)
    return user


def require_user(request):
    """Вошедший пользователь. Если не вошёл — ошибка 403."""
    user = get_user(request)
    if user is None:
        logger.warning(f'Отказано в доступе к {request.url.path} | ip={client_ip(request)}')
        raise StarletteHTTPException(status_code=403)
    return user


# Просим браузер не хранить страницы в кэше, чтобы кнопка «Назад» не показывала старую копию
@app.middleware('http')
async def no_cache_for_pages(request: Request, call_next):
    response = await call_next(request)
    if response.headers.get('content-type', '').startswith('text/html'):
        response.headers['Cache-Control'] = 'no-store'
    return response


# Страницы 
@app.get('/', response_class=HTMLResponse)
@app.get('/home', response_class=HTMLResponse)
def home_page(request: Request):
    user = get_user(request)
    name = user['name'] if user else 'красотка'
    return templates.TemplateResponse(request=request, name='home.html', context={'username': name})


@app.get('/login', response_class=HTMLResponse)
def login_page(request: Request, registered: str = None, loggedout: str = None):
    notice = None
    if registered:
        notice = 'Аккаунт создан, нужно войти'
    elif loggedout:
        notice = 'Ты нажала «Назад», поэтому сессия закрыта. Войди снова 💖'
    return templates.TemplateResponse(request=request, name='login.html', context={'notice': notice})


@app.get('/register', response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse(request=request, name='register.html')


@app.get('/main', response_class=HTMLResponse)
def cabinet_page(request: Request):
    user = require_user(request)
    message = request.session.pop('avatar_message', None)      # сообщение показываем один раз
    return templates.TemplateResponse(
        request=request, name='main.html',
        context={'username': user['name'], 'message': message,
                 'has_avatar': os.path.exists(avatar_path(user['email']))})


@app.get('/logout')
def logout(request: Request):
    end_session(request)
    return RedirectResponse(url='/login', status_code=303)


@app.post('/back')
def pressed_back(request: Request):
    email = session_email(request)
    if email:
        logger.info(f'Нажата кнопка «Назад» | email={email}')
    end_session(request)
    return {'logged_out': email is not None}


#  Аватар: показать и загрузить
@app.get('/avatar')
def show_avatar(request: Request):
    user = require_user(request)
    path = avatar_path(user['email'])
    if not os.path.exists(path):
        raise StarletteHTTPException(status_code=404)
    return FileResponse(path, media_type='image/png', headers={'Cache-Control': 'no-cache'})


@app.post('/avatar')
async def upload_avatar(request: Request, file: UploadFile = File(None)):
    user = require_user(request)

    message = 'Сначала выбери картинку'
    if file and file.filename:
        data = await file.read(MAX_AVATAR_BYTES + 1)           # читаем не больше лимита
        if len(data) > MAX_AVATAR_BYTES:
            message = 'Файл слишком большой (не больше 5 МБ)'
        elif save_avatar(user['email'], data):
            message = 'Аватар обновлён 💖'
        else:
            message = 'Это не картинка. Выбери JPG, PNG или WEBP'

    request.session['avatar_message'] = message
    return RedirectResponse(url='/main', status_code=303)


@app.get('/404', response_class=HTMLResponse)
def not_found_page(request: Request):
    return templates.TemplateResponse(request=request, name='404.html', status_code=404)


@app.get('/403', response_class=HTMLResponse)
def forbidden_page(request: Request):
    return templates.TemplateResponse(request=request, name='403.html', status_code=403)


@app.exception_handler(StarletteHTTPException)
async def error_pages(request: Request, exc: StarletteHTTPException):
    pages = {403: '403.html', 404: '404.html'}
    if exc.status_code in pages:
        return templates.TemplateResponse(request=request, name=pages[exc.status_code], status_code=exc.status_code)
    return await http_exception_handler(request, exc)


# Регистрация и вход 
@app.post('/register')
def register(request: Request,
             name: str = Form(...),
             email: str = Form(...),
             password: str = Form(...),
             confirm: str = Form(...)):
    name = name.strip()
    email = email.strip().lower()

    error = check_name(name) or check_email(email) or check_password_strength(password)
    if not error and password != confirm:
        error = 'Пароли не совпадают'
    if not error and find_user(email):
        error = 'Такой email уже зареган'

    if error:
        return templates.TemplateResponse(
            request=request, name='register.html',
            context={'error': error, 'name': name, 'email': email}, status_code=400)

    add_user(name, email, password)
    logger.info(f'Новый пользователь | email={email} | name={name}')
    return RedirectResponse(url='/login?registered=1', status_code=303)


@app.post('/login')
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    user = find_user(username.strip().lower())

    if user is None or not check_password(password, user['password']):
        logger.warning(f'Неудачный вход | email={username!r} | ip={client_ip(request)}')
        return templates.TemplateResponse(
            request=request, name='login.html', context={'error': 'Неверный email или пароль'})

    start_session(request, user['email'])
    return RedirectResponse(url='/main', status_code=303)


if __name__ == "__main__":
    key_path, cert_path = generate_or_load_cert()
    uvicorn.run(
        "__main__:app",
        host="10.100.0.2",
        port=443,
        ssl_keyfile=key_path,
        ssl_certfile=cert_path,
    )
