"""Login and self-service account pages. Incomplete MFA never authorizes APIs."""
import hmac
import logging

from flask import g, jsonify, redirect, render_template, request
from markupsafe import Markup
import qrcode
from qrcode.image.svg import SvgPathImage

from .auth import COOKIE, LoginLimited, SessionExpired

logger = logging.getLogger('oma_monitor.audit')


def valid_csrf(current, candidate):
    return bool(current and isinstance(candidate,str) and candidate and candidate.isascii() and
                hmac.compare_digest(candidate,current['csrf']))


def register_account_routes(app, accounts, settings, authenticated):
    def cookie(response, token=None):
        if token:
            response.set_cookie(COOKIE,token,secure=settings.cookie_secure,httponly=True,samesite='Strict',path='/')
        else:
            response.delete_cookie(COOKIE,secure=settings.cookie_secure,httponly=True,samesite='Strict',path='/')
        return response

    def fields():
        try:
            data = request.get_json(silent=True) if request.is_json else request.form
            if not hasattr(data,'get') or any(not isinstance(value,str) for value in data.values()):
                return {}
            for value in data.values():
                value.encode('utf-8')
            return data
        except (UnicodeEncodeError,RecursionError):
            return {}

    def protected(current, data):
        candidate = request.headers.get('X-CSRF-Token') or str(data.get('csrf_token',''))
        return request.headers.get('Sec-Fetch-Site','').lower() != 'cross-site' and valid_csrf(current,candidate)

    def next_page(path, token=None, clear=False):
        response = jsonify({'ok':True,'next':path}) if request.is_json else redirect(path,303)
        return cookie(response,token) if token or clear else response

    def enrollment(token):
        data = accounts.enrollment(token)
        if data:
            # SVG contains generated QR paths only, no externally loaded resources.
            data['qr'] = Markup(qrcode.make(data['uri'],image_factory=SvgPathImage).to_string(encoding='unicode'))
        return data

    def profile(error=None, status=200):
        if error and request.is_json:
            return jsonify({'error':'profile-update-failed','message':error}),status
        return render_template('profile.html',username=g.identity['username'],role=g.identity['role'],
                               csrf_token=g.identity['csrf'],error=error,
                               enrollment=enrollment(request.cookies.get(COOKIE,''))),status

    @app.errorhandler(LoginLimited)
    def limited(_error):
        if request.is_json:
            response = jsonify({'error':'login-limited','message':'Too many attempts. Try again in 15 minutes.'})
        else:
            response = app.make_response(render_template('account_error.html',
                                         message='Too many attempts. Try again in 15 minutes.'))
        response.status_code = 429
        response.headers['Retry-After'] = '900'
        return response

    @app.errorhandler(SessionExpired)
    def expired(_error):
        response = jsonify({'error':'authentication-required'}) if request.is_json else redirect('/login?updated=expired',303)
        if request.is_json:
            response.status_code = 401
        return cookie(response) if request.cookies.get(COOKIE) else response

    @app.route('/login',methods=['GET','POST'])
    def login():
        token = request.cookies.get(COOKIE,'')
        current = accounts.session(token,phases=('full','verify','enroll'))
        if current and current['username']:
            return next_page('/' if current['phase']=='full' else '/login/mfa')
        if request.method == 'GET':
            if current is None:
                token,_ = accounts.anonymous_session()
                current = accounts.session(token)
            messages={'password':'Password updated. Sign in again using a new authenticator code.',
                      'mfa':'Authenticator updated. Wait for a new code, then sign in again.',
                      'expired':'Your sign-in session expired. Start again.'}
            response = app.make_response(render_template('login.html',csrf_token=current['csrf'],
                                         message=messages.get(request.args.get('updated'))))
            return cookie(response,token)
        data = fields()
        if not protected(current,data):
            return jsonify({'error':'invalid-csrf-token'}),403
        username,password = (str(data.get(key,'')) for key in ('username','password'))
        result = accounts.begin_login(username,password,request.remote_addr or 'unknown',token) if (
                 0 < len(username) <= 64 and 0 < len(password) <= 1024) else None
        if result is None:
            logger.warning('login result=denied stage=password')
            if request.is_json:
                return jsonify({'error':'invalid-credentials'}),401
            return render_template('login.html',csrf_token=current['csrf'],error='Invalid username or password.'),401
        return next_page('/login/mfa',result[0])

    @app.route('/login/mfa',methods=['GET','POST'])
    def mfa():
        token = request.cookies.get(COOKIE,'')
        current = accounts.session(token,phases=('full','verify','enroll'))
        if current and current['phase']=='full':
            return next_page('/')
        if not current or not current['username']:
            raise SessionExpired()
        error=None
        if request.method=='POST':
            data=fields()
            if not protected(current,data):
                return jsonify({'error':'invalid-csrf-token'}),403
            result=accounts.complete_login(token,str(data.get('otp','')),request.remote_addr or 'unknown')
            if result:
                logger.info('login user=%s result=accepted mfa=verified',current['username'])
                return next_page('/',result[0])
            logger.warning('login result=denied stage=mfa')
            if request.is_json:
                return jsonify({'error':'invalid-authenticator-code'}),401
            if not accounts.session(token,phases=('verify','enroll')):
                raise SessionExpired()
            error='Invalid or already used code. Wait for a new code and try again.'
        return render_template('mfa.html',csrf_token=current['csrf'],username=current['username'],error=error,
                               enrollment=enrollment(token)),401 if error else 200

    @app.post('/logout')
    def logout():
        token=request.cookies.get(COOKIE,'')
        current=accounts.session(token,phases=('full','verify','enroll'))
        if not current or not current['username']:
            raise SessionExpired()
        if not protected(current,fields()):
            return jsonify({'error':'invalid-csrf-token'}),403
        accounts.revoke(token)
        if request.headers.get('X-CSRF-Token'):
            return cookie(jsonify({'ok':True}))
        return next_page('/login',clear=True)

    @app.get('/profile')
    @authenticated
    def profile_page():
        accounts.session(request.cookies.get(COOKIE,''),touch=True)
        return profile()

    @app.post('/profile/<action>')
    @authenticated
    def update_profile(action):
        data=fields()
        if not protected(g.identity,data):
            return jsonify({'error':'invalid-csrf-token'}),403
        token=request.cookies.get(COOKIE,'')
        ip=request.remote_addr or 'unknown'
        password,code=(str(data.get(key,'')) for key in ('current_password','otp'))
        if len(password)>1024 or len(code)>6:
            return profile('Invalid credentials.',400)
        if action=='password':
            new,confirmation=(str(data.get(key,'')) for key in ('new_password','confirm_password'))
            if new != confirmation:
                return profile('New passwords do not match.',400)
            try:
                accepted=accounts.change_password(token,password,code,new,ip)
            except ValueError as exc:
                return profile(str(exc),400)
            destination='/login?updated=password'
        elif action=='mfa-start':
            accepted=accounts.begin_replacement(token,password,code,ip)
            destination='/profile'
        elif action=='mfa-confirm':
            accepted=accounts.complete_replacement(token,code,ip)
            destination='/login?updated=mfa'
        elif action=='mfa-cancel':
            accounts.cancel_replacement(token)
            return next_page('/profile')
        else:
            return jsonify({'error':'unsupported-action'}),404
        if not accepted:
            logger.warning('profile_change user=%s action=%s result=denied',g.identity['username'],action)
            if request.is_json:
                return jsonify({'error':'invalid-credentials-or-code'}),401
            return profile('Invalid credentials or already used code. Wait for a new code and try again.',401)
        logger.info('profile_change user=%s action=%s result=accepted',g.identity['username'],action)
        return next_page(destination,token=accepted[0] if action=='mfa-start' else None,
                         clear=action in {'password','mfa-confirm'})
