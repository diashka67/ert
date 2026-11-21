#python -m uvicorn file:app --host 127.0.0.1 --port 8000 --ssl-keyfile key.pem --ssl-certfile cert.pem --reload
import csv
import datetime
import hashlib
import json
import logging
import os
import re
import secrets
import uvicorn

from fastapi import FastAPI, Form, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.exception_handlers import http_exception_handler
from starlette.exceptions import HTTPException
from starlette.middleware.sessions import SessionMiddleware

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# ---------- настройки ----------
USERS_FILE = 'user.csv'
NEWS_FILE = 'news.json'
SECRET_FILE = '.secret_key'
CERT_FILE = 'cert.pem'
KEY_FILE = 'key.pem'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[logging.FileHandler('sessions.log', encoding='utf-8'), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


# ---------- секретный ключ для cookie ----------
def get_secret_key():
    # если ключ уже есть в файле - берём его, если нет - создаём новый
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, encoding='utf-8') as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(SECRET_FILE, 'w', encoding='utf-8') as f:
        f.write(key)
    return key


# ---------- приложение ----------
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=get_secret_key(), max_age=1500)

# папки для картинок должны существовать до запуска
os.makedirs('avatars', exist_ok=True)
os.makedirs('news_images', exist_ok=True)

app.mount('/static', StaticFiles(directory='static'), name='static')
app.mount('/sources', StaticFiles(directory='sources'), name='sources')
app.mount('/news_images', StaticFiles(directory='news_images'), name='news_images')
templates = Jinja2Templates(directory='templates')


# ---------- пользователи (файл user.csv) ----------
def read_users():
    if not os.path.exists(USERS_FILE):
        return []
    with open(USERS_FILE, encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))


def find_user(email):
    for user in read_users():
        if user['email'] == email:
            if not user.get('role'):
                user['role'] = 'reader'
            return user
    return None


def add_user(name, email, password, role):
    new_file = not os.path.exists(USERS_FILE)
    with open(USERS_FILE, 'a', encoding='utf-8-sig', newline='') as f:
        writer = csv.writer(f)
        if new_file:
            writer.writerow(['name', 'email', 'password', 'role'])
        writer.writerow([name, email, hash_password(password), role])


# ---------- пароли ----------
def hash_password(password):
    salt = secrets.token_hex(8)
    h = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
    return salt + '$' + h


def check_password(password, saved):
    salt = saved.split('$')[0]
    h = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
    return saved == salt + '$' + h


# ---------- проверка email и пароля ----------
def check_email(email):
    if len(email) > 100:
        return 'Email слишком длинный (не больше 100 символов)'
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email):
        return 'Некорректный email'
    return None


def check_password_strength(password):
    if len(password) < 8:
        return 'Пароль должен быть не короче 8 символов'
    if len(password) > 64:
        return 'Пароль слишком длинный (не больше 64 символов)'
    if not re.search(r'[A-Za-zА-Яа-яЁё]', password):
        return 'В пароле должна быть хотя бы одна буква'
    if not re.search(r'[0-9]', password):
        return 'В пароле должна быть хотя бы одна цифра'
    return None


# ---------- роли ----------
def can_edit(user):
    return user is not None and user['role'] in ('moderator', 'admin')


def is_admin(user):
    return user is not None and user['role'] == 'admin'


# ---------- сессии ----------
active_sessions = []   # номера сессий тех, кто сейчас вошёл


def start_session(request, email):
    sid = secrets.token_hex(16)
    active_sessions.append(sid)
    request.session['sid'] = sid
    request.session['email'] = email


def end_session(request):
    sid = request.session.get('sid')
    if sid in active_sessions:
        active_sessions.remove(sid)
    request.session.clear()


def get_user(request):
    # вошёл ли человек: номер сессии должен быть в списке
    sid = request.session.get('sid')
    email = request.session.get('email')
    if sid in active_sessions and email:
        return find_user(email)
    return None


# ---------- картинки ----------
def save_image(file, folder, name=None):
    if not getattr(file, 'filename', None):
        return None
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ['.png', '.jpg', '.jpeg', '.gif', '.webp']:
        return None
    if name is None:
        name = secrets.token_hex(8) + ext     
    with open(os.path.join(folder, name), 'wb') as f:
        f.write(file.file.read())
    return name


def avatar_path(email):
    return os.path.join('avatars', hashlib.sha256(email.encode('utf-8')).hexdigest() + '.png')


# ---------- новости ----------
def read_news():
    if not os.path.exists(NEWS_FILE):
        return []
    with open(NEWS_FILE, encoding='utf-8') as f:
        news = json.load(f)
    for n in news: 
        n.setdefault('annotation', n['text'][:150])
        n.setdefault('preview', None)
        n.setdefault('images', [])
        n.setdefault('likes', [])
        n.setdefault('dislikes', [])
        n.setdefault('comments', [])
        n.setdefault('views', 0)
    return news


def save_news(news):
    with open(NEWS_FILE, 'w', encoding='utf-8') as f:
        json.dump(news, f, ensure_ascii=False, indent=2)


def find_news(news, news_id):
    for n in news:
        if n['id'] == news_id:
            return n
    return None


# ---------- каждый раз просим браузер не запоминать страницы ----------
@app.middleware('http')
async def no_cache(request: Request, call_next):
    response = await call_next(request)
    if response.headers.get('content-type', '').startswith('text/html'):
        response.headers['Cache-Control'] = 'no-store'
    return response


# ---------- ошибки 403 и 404 ----------
@app.exception_handler(HTTPException)
async def error_pages(request: Request, exc: HTTPException):
    if exc.status_code == 403:
        return templates.TemplateResponse(request=request, name='403.html', status_code=403)
    if exc.status_code == 404:
        return templates.TemplateResponse(request=request, name='404.html', status_code=404)
    return await http_exception_handler(request, exc)


@app.get('/403', response_class=HTMLResponse)
def page_403(request: Request):
    return templates.TemplateResponse(request=request, name='403.html', status_code=403)


@app.get('/404', response_class=HTMLResponse)
def page_404(request: Request):
    return templates.TemplateResponse(request=request, name='404.html', status_code=404)


# ---------- главная ----------
@app.get('/', response_class=HTMLResponse)
@app.get('/home', response_class=HTMLResponse)
def home(request: Request):
    user = get_user(request)
    name = 'красотка'
    if user:
        name = user['name']
    return templates.TemplateResponse(request=request, name='home.html', context={
        'username': name,
        'user': user,
        'can_edit': can_edit(user),
        'is_admin': is_admin(user),
        'news': read_news()
    })


# ---------- регистрация ----------
@app.get('/register', response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse(request=request, name='register.html')


@app.post('/register')
def register(request: Request, name: str = Form(...), email: str = Form(...),
            password: str = Form(...), confirm: str = Form(...)):
    name = name.strip()
    email = email.strip().lower()

    error = None
    if len(name) < 2:
        error = 'Введите имя (минимум 2 символа)'
    if not error:
        error = check_email(email) or check_password_strength(password)
    if not error and password != confirm:
        error = 'Пароли не совпадают'
    if not error and find_user(email):
        error = 'Такой email уже зареган'

    if error:
        return templates.TemplateResponse(request=request, name='register.html', context={'error': error, 'name': name, 'email': email}, status_code=400)

    # первый пользователь - админ, остальные - читатели
    role = 'reader'
    if len(read_users()) == 0:
        role = 'admin'

    add_user(name, email, password, role)
    logger.info(f'Новый пользователь | email={email} | role={role}')
    return RedirectResponse(url='/login?registered=1', status_code=303)


# ---------- вход и выход ----------
@app.get('/login', response_class=HTMLResponse)
def login_page(request: Request, registered: str = None, loggedout: str = None):
    notice = None
    if registered:
        notice = 'Аккаунт создан, нужно войти'
    if loggedout:
        notice = 'Ты нажала «Назад», поэтому сессия закрыта. Войди снова 💖'
    return templates.TemplateResponse(request=request, name='login.html', context={'notice': notice})


@app.post('/login')
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    user = find_user(username.strip().lower())
    if user is None or not check_password(password, user['password']):
        logger.warning(f'Неудачный вход | email={username!r}')
        return templates.TemplateResponse(request=request, name='login.html', context={'error': 'Неверный email или пароль'})
    start_session(request, user['email'])
    logger.info(f'Вход | email={user["email"]}')
    return RedirectResponse(url='/main', status_code=303)


@app.get('/logout')
def logout(request: Request):
    end_session(request)
    return RedirectResponse(url='/login', status_code=303)


@app.post('/back')
def pressed_back(request: Request):
    # сюда обращается sources/back.js, когда нажали кнопку «Назад» в браузере
    was_logged = get_user(request) is not None
    end_session(request)
    return {'logged_out': was_logged}


# ---------- личный кабинет и аватар ----------
def show_cabinet(request, user, message=None):
    return templates.TemplateResponse(request=request, name='main.html', context={
        'username': user['name'],
        'role': user['role'],
        'has_avatar': os.path.exists(avatar_path(user['email'])),
        'message': message
    })


@app.get('/main', response_class=HTMLResponse)
def cabinet(request: Request):
    user = get_user(request)
    if user is None:
        raise HTTPException(status_code=403)
    return show_cabinet(request, user)


@app.get('/avatar')
def get_avatar(request: Request):
    user = get_user(request)
    if user is None:
        raise HTTPException(status_code=403)
    path = avatar_path(user['email'])
    if not os.path.exists(path):
        raise HTTPException(status_code=404)
    # no-cache: чтобы после смены аватара браузер не показывал старую картинку
    return FileResponse(path, media_type='image/png', headers={'Cache-Control': 'no-cache'})


@app.post('/avatar')
async def update_avatar(request: Request):
    user = get_user(request)
    if user is None:
        raise HTTPException(status_code=403)

    form = await request.form()          # форму читаем сами, чтобы пустой выбор файла не давал ошибку 422
    file = form.get('file')
    if not getattr(file, 'filename', None):
        return show_cabinet(request, user, 'Файл не выбран')

    name = os.path.basename(avatar_path(user['email']))
    if save_image(file, 'avatars', name) is None:
        return show_cabinet(request, user, 'Нужна картинка: png, jpg, gif или webp')
    return RedirectResponse(url='/main', status_code=303)


# ---------- добавление новости ----------
@app.get('/add_news', response_class=HTMLResponse)
def add_news_page(request: Request):
    user = get_user(request)
    if not can_edit(user):
        raise HTTPException(status_code=403)
    return templates.TemplateResponse(request=request, name='add_news.html', context={
        'user': user,
        'date': datetime.date.today().isoformat()
    })


@app.post('/add_news')
async def add_news(request: Request):
    user = get_user(request)
    if not can_edit(user):
        raise HTTPException(status_code=403)

    form = await request.form()          # форму читаем сами: так работают и пустые поля для файлов
    title = form.get('title', '').strip()
    annotation = form.get('annotation', '').strip()
    text = form.get('text', '').strip()
    date = form.get('date', '')

    if not title or not annotation or not text:
        return templates.TemplateResponse(request=request, name='add_news.html', status_code=400, context={
            'user': user, 'error': 'Заполни заголовок, аннотацию и текст',
            'title': title, 'annotation': annotation, 'text': text, 'date': date
        })

    preview = save_image(form.get('preview'), 'news_images')
    images = []
    for file in form.getlist('images'):
        name = save_image(file, 'news_images')
        if name:
            images.append(name)

    news = read_news()
    news.insert(0, {
        'id': secrets.token_hex(4),
        'title': title,
        'annotation': annotation,
        'text': text,
        'author': user['name'],
        'date': '.'.join(reversed(date.split('-'))),     # 2026-11-20 -> 20.11.2026
        'preview': preview,
        'images': images,
        'likes': [],
        'dislikes': [],
        'comments': [],
        'views': 0
    })
    save_news(news)
    logger.info(f'Новость добавлена | author={user["email"]} | title={title}')
    return RedirectResponse(url='/home', status_code=303)


# ---------- страница новости ----------
@app.get('/news/{news_id}', response_class=HTMLResponse)
def news_page(request: Request, news_id: str):
    news = read_news()
    item = find_news(news, news_id)
    if item is None:
        raise HTTPException(status_code=404)

    # просмотр считаем один раз за сессию, иначе каждый лайк накручивал бы счётчик
    viewed = request.session.get('viewed', [])
    if news_id not in viewed:
        item['views'] += 1
        save_news(news)
        viewed.append(news_id)
        request.session['viewed'] = viewed

    user = get_user(request)
    email = None
    if user:
        email = user['email']
    return templates.TemplateResponse(request=request, name='news.html', context={
        'item': item,
        'user': user,
        'is_admin': is_admin(user),
        'liked': email in item['likes'],
        'disliked': email in item['dislikes']
    })


def vote(request, news_id, mine, other):
    # mine - список, куда голосуем (likes или dislikes), other - противоположный список
    user = get_user(request)
    if user is None:
        raise HTTPException(status_code=403)
    news = read_news()
    item = find_news(news, news_id)
    if item is None:
        raise HTTPException(status_code=404)

    email = user['email']
    if email in item[mine]:
        item[mine].remove(email)         # нажали второй раз - оценка снимается
    else:
        item[mine].append(email)
        if email in item[other]:
            item[other].remove(email)    # лайк и дизлайк одновременно нельзя
    save_news(news)
    return RedirectResponse(url=f'/news/{news_id}', status_code=303)


@app.post('/news/{news_id}/like')
def like(request: Request, news_id: str):
    return vote(request, news_id, 'likes', 'dislikes')


@app.post('/news/{news_id}/dislike')
def dislike(request: Request, news_id: str):
    return vote(request, news_id, 'dislikes', 'likes')


@app.post('/news/{news_id}/comment')
def comment(request: Request, news_id: str, text: str = Form(...)):
    user = get_user(request)
    if user is None:
        raise HTTPException(status_code=403)
    news = read_news()
    item = find_news(news, news_id)
    if item is None:
        raise HTTPException(status_code=404)

    if text.strip():
        item['comments'].append({
            'author': user['name'],
            'text': text.strip(),
            'date': datetime.datetime.now().strftime('%d.%m.%Y %H:%M')
        })
        save_news(news)
    return RedirectResponse(url=f'/news/{news_id}#comments', status_code=303)


@app.post('/delete_news')
def delete_news(request: Request, news_id: str = Form(...)):
    user = get_user(request)
    if not is_admin(user):
        raise HTTPException(status_code=403)
    news = [n for n in read_news() if n['id'] != news_id]
    save_news(news)
    logger.info(f'Новость удалена | id={news_id} | by={user["email"]}')
    return RedirectResponse(url='/home', status_code=303)


# ---------- HTTPS: сертификат (создаётся один раз) ----------
def generate_or_load_cert():
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return KEY_FILE, CERT_FILE

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'BY'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'Minsk'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, 'Minsk'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'BarbieLand'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'localhost'),
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
            x509.SubjectAlternativeName([x509.DNSName('localhost'), x509.DNSName('10.100.0.2')]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    with open(KEY_FILE, 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(CERT_FILE, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return KEY_FILE, CERT_FILE


if __name__ == '__main__':
    key_path, cert_path = generate_or_load_cert()
    uvicorn.run('__main__:app', host='10.100.0.2', port=443,
                ssl_keyfile=key_path, ssl_certfile=cert_path)