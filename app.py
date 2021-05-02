import json

import pylibmc
import os
import uuid

from shutil import rmtree

import datetime
import smtplib
import ssl

import requests
from flask_session import Session
import argparse

from google.cloud import pubsub_v1

from sqlalchemy.dialects.mysql import CHAR

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from os import abort

from flask import Flask, jsonify, g, render_template, session, send_file, redirect
from flask import request, url_for, flash
from flask_httpauth import HTTPBasicAuth
from flask_marshmallow import Marshmallow
from flask_login import LoginManager, login_user, UserMixin, current_user, logout_user
from flask_restful import Api
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from passlib.apps import custom_app_context as pwd_context

# configuraciones
# Nombre de archivo
from werkzeug.utils import secure_filename
from flask_caching import Cache

# MongoDB Database
from flask_mongoengine import MongoEngine, Pagination
import mongoengine as me

# GCP Utils
import gcp_utils

cache = Cache()
ROOT_PATH = os.path.dirname(
    (os.sep).join(os.path.abspath(__file__)))

app = Flask(__name__, template_folder="templates",
            static_folder="static",
            static_url_path="")

# MONGODB
app.config['MONGODB_SETTINGS'] = {
    'db': os.environ["MONGO_DB"],
    'host': "mongodb+srv://" + os.environ["MONGO_USER"] + ":" + os.environ["MONGO_PASSWORD"] + "@" + os.environ[
        "MONGO_HOST"] + "/" + os.environ["MONGO_DB"] + "?retryWrites=true&w=majority"
}

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
FILE_FOLDER = 'Audios/Original'
FILE_FOLDER_CONVERTED = 'Audios/Converted'

ALLOWED_EXTENSIONS = set(['WAV', 'AAC', 'AIFF', 'AIFF', 'DSD', 'FLAC', 'MP3', 'MQA', 'OGG', 'WMA'])
ALLOWED_CONVERTED_EXTENSIONS = set(['MP3'])
if not os.path.exists(FILE_FOLDER):
    os.umask(0)
    os.makedirs(FILE_FOLDER, mode=0o777)
if not os.path.exists(FILE_FOLDER_CONVERTED):
    os.umask(0)
    os.makedirs(FILE_FOLDER_CONVERTED, mode=0o777)
app.config['UPLOAD_FOLDER'] = FILE_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['SECRET_KEY'] = 'S3cretH4sh'

# GCP Config
GCP_FOLDER = 'https://storage.googleapis.com/group13_cloud/audio_original'
GCP_FOLDER_CONVERTED = 'https://storage.googleapis.com/group13_cloud/audio_converted'

# Mongo
db = MongoEngine(app)

# db = SQLAlchemy(app)
ma = Marshmallow(app)
api = Api(app)
auth = HTTPBasicAuth()
cache_servers = os.environ.get('MEMCACHIER_BRONZE_SERVERS')
if cache_servers is None:
    cache.init_app(app, config={'CACHE_TYPE': 'simple'})
else:
    cache_user = os.environ.get('MEMCACHIER_BRONZE_USERNAME') or ''
    cache_pass = os.environ.get('MEMCACHIER_BRONZE_PASSWORD') or ''
    cache.init_app(app,
                   config={'CACHE_TYPE': 'saslmemcached',
                           'CACHE_MEMCACHED_SERVERS': cache_servers.split(','),
                           'CACHE_MEMCACHED_USERNAME': cache_user,
                           'CACHE_MEMCACHED_PASSWORD': cache_pass,
                           'CACHE_OPTIONS': {'behaviors': {
                               # Faster IO
                               'tcp_nodelay': True,
                               # Keep connection alive
                               'tcp_keepalive': True,
                               # Timeout for set/get requests
                               'connect_timeout': 2000,  # ms
                               'send_timeout': 750 * 1000,  # us
                               'receive_timeout': 750 * 1000,  # us
                               '_poll_timeout': 2000,  # ms
                               # Better failover
                               'ketama': True,
                               'remove_failed': 1,
                               'retry_timeout': 2,
                               'dead_timeout': 30}}})
    app.config.update(
            SESSION_TYPE = 'memcached',
            SESSION_MEMCACHED =
                pylibmc.Client(cache_servers.split(','), binary=True,
                               username=cache_user, password=cache_pass,
                               behaviors={
                                    # Faster IO
                                    'tcp_nodelay': True,
                                    # Keep connection alive
                                    'tcp_keepalive': True,
                                    # Timeout for set/get requests
                                    'connect_timeout': 2000, # ms
                                    'send_timeout': 750 * 1000, # us
                                    'receive_timeout': 750 * 1000, # us
                                    '_poll_timeout': 2000, # ms
                                    # Better failover
                                    'ketama': True,
                                    'remove_failed': 1,
                                    'retry_timeout': 2,
                                    'dead_timeout': 30,
                               })
        )
    Session(app)

login_manager = LoginManager()
login_manager.login_view = 'get_auth_token'
login_manager.init_app(app)


def allowed_file(filename, isOriginal):
    if isOriginal == 1:
        return '.' in filename and \
               filename.rsplit('.', 1)[1].upper() in ALLOWED_EXTENSIONS
    else:
        return '.' in filename and \
               filename.rsplit('.', 1)[1].upper() in ALLOWED_CONVERTED_EXTENSIONS


class UserAdmin(UserMixin, me.Document):
    meta = {
        'collection': 'admins',
        'index_background': True
    }
    id = me.StringField(default=lambda: str(uuid.uuid4()),
                        primary_key=True)  # UUIDField(primary_key=True, default=uuid.uuid4, unique=True, binary=False)
    first_name = me.StringField(max_length=40)
    last_name = me.StringField(max_length=40)
    company = me.StringField(max_length=100)
    email = me.StringField(max_length=200, unique=True)
    password_hash = me.StringField(max_length=128)

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': str(self.id)})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return False
        user = UserAdmin.objects.get(id=data['id'])
        return user


class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'first_name', 'last_name', 'company', 'email', 'password_hash')


post_schema = UserSchema()
posts_schema = UserSchema(many=True)


class Contest(me.Document):
    meta = {
        'collection': 'contests',
        'index_background': True
    }
    id = me.StringField(default=lambda: str(uuid.uuid4()),
                        primary_key=True)  # me.UUIDField(primary_key=True, default=uuid.uuid4, unique=True, max_length=36, binary=False)
    name = me.StringField(max_length=100, unique=True)
    image_url = me.StringField(max_length=400, unique=True)
    begin_date = me.DateTimeField()
    end_date = me.DateTimeField()
    price = me.IntField()
    guide = me.StringField(max_length=4000)
    recommendations = me.StringField(max_length=4000)
    creation_date = me.DateTimeField(default=datetime.datetime.utcnow)
    user_id = me.ReferenceField(UserAdmin)
    audios = me.ListField(me.ReferenceField('Audio'))


class ContestSchema(ma.Schema):
    class Meta:
        fields = ('id', 'name', 'image_url', 'begin_date', 'end_date', 'price', 'guide', 'recommendations',
                  'creation_date', 'user_id')


contest_schema = ContestSchema()
contests_schema = ContestSchema(many=True)


class Audio(me.Document):
    meta = {
        'collection': 'audios',
        'index_background': True
    }
    id = me.StringField(default=lambda: str(uuid.uuid4()),
                        primary_key=True)  # UUIDField(primary_key=True, default=uuid.uuid4, unique=True, max_length=36, binary=False)
    email = me.StringField(max_length=200)
    first_name = me.StringField(max_length=40)
    last_name = me.StringField(max_length=40)
    status = me.StringField(choices=('En Proceso', 'Convertida'), default='En Proceso')
    original_url = me.StringField(max_length=400)
    converted_url = me.StringField(max_length=400)
    observations = me.StringField(max_length=4000)
    creation_date = me.DateTimeField(default=datetime.datetime.utcnow)
    contest_id = me.StringField(max_length=36)
    creation_date = me.DateTimeField(default=datetime.datetime.utcnow)
    contest = me.ReferenceField(Contest)


class AudioSchema(ma.Schema):
    class Meta:
        fields = ('id', 'email', 'first_name', 'last_name', 'id', 'email', 'first_name', 'last_name',
                  'status', 'original_url', 'converted_url', 'observations', 'creation_date', 'email',
                  'contest_id')


audio_schema = AudioSchema()
audios_schema = AudioSchema(many=True)


@app.route('/api/user', methods=['POST'])
def post():
    if request.json['email'] is None or request.json['password'] is None:
        abort(400)  # missing arguments
    if UserAdmin.objects(email=request.json['email']).first() is not None:
        abort(400)  # existing user
    newClient = UserAdmin(
        company=request.json['company'],
        first_name=request.json['first_name'],
        last_name=request.json['last_name'],
        email=request.json['email']
    )
    newClient.hash_password(request.json['password'])
    newClient.save()

    return post_schema.dump(newClient)


import io


@app.route('/admincreaconcurso', methods=['POST'])
def post_contest():
    # obtaining file
    image_contest = request.files['img_concurso']
    image_filename = secure_filename(image_contest.filename)

    # obtaining contest
    newContest = Contest(
        name=request.form.get('nom_concurso'),
        image_url=image_filename,
        begin_date=request.form.get('fin_concurso'),
        end_date=request.form.get('ffi_concurso'),
        price=request.form.get('val_concurso'),
        guide=request.form.get('guion'),
        recommendations=request.form.get('recommendations'),
        user_id=current_user.first().id
    )

    newContest.save()
    final_filename = '.' + image_filename.rsplit('.', 1)[1].lower()
    os.mkdir('static/contest_images/' + str(newContest.id), mode=0o777)
    image_contest.save('static/contest_images/' + str(newContest.id) + '/archivo' + final_filename)

    # save image to gcp
    gcp_utils.upload_blob('group13_cloud',
                          'static/contest_images/' + str(newContest.id) + '/archivo' + final_filename,
                          'contest_images/' + str(newContest.id) + final_filename)
    newContest.image_url = 'contest_images/' + str(newContest.id) + final_filename
    newContest.save()

    flash('Concurso ' + str(newContest.name) + ' creado.')
    # delete image from machine
    if os.path.exists('static/contest_images/' + str(newContest.id)):
        rmtree('static/contest_images/' + str(newContest.id))
        print('paso x aqui')
    return redirect(url_for('indexadmin'))


@app.route('/api/editcontest', methods=['PUT'])
def edit_contest():
    contest_id = request.json['id']
    contest = Contest.objects(id=contest_id).first()
    if 'name' in request.json:
        contest.name = request.json['name']
    if 'begin_date' in request.json:
        contest.begin_date = request.json['begin_date']
    if 'end_date' in request.json:
        contest.end_date = request.json['end_date']
    if 'price' in request.json:
        contest.price = request.json['price']
    if 'guide' in request.json:
        contest.guide = request.json['guide']
    if 'recommendations' in request.json:
        contest.recommendations = request.json['recommendations']

    contest.save()
    flash('Concurso ' + str(contest.name) + ' actualizado.')
    return post_schema.dump(contest)


# @app.route('/api/newaudio', methods=['POST'])
def post_audiok():
    return json.dumps({'success': True}), 200, {'ContentType': 'application/json'}


@app.route('/participarconcurso/<string:contest_id>', methods=['POST'])  # '/api/newaudio', methods=['POST'])#
def post_audio(contest_id):
    # obtaining file
    audio = request.files['audio']
    audio_name = secure_filename(audio.filename)

    # obtaining contest
    newAudio = Audio(
        email=request.form.get('email'),
        first_name=request.form.get('fname'),
        last_name=request.form.get('lname'),
        original_url=audio_name,
        converted_url=audio_name,
        observations=request.form.get('observations'),
        contest_id=contest_id
    )

    newAudio.save()
    newAudio_pub = str(newAudio.id)
    final_filename = str(newAudio.id) + '.' + audio_name.rsplit('.', 1)[1].lower()
    if not os.path.exists('Audios/Original/' + contest_id):
        os.umask(0)
        os.mkdir('Audios/Original/' + contest_id, mode=0o777)
        os.mkdir('Audios/Converted/' + contest_id, mode=0o777)
    audio.save('Audios/Original/' + contest_id + '/' + final_filename)
    gcp_utils.upload_blob('group13_cloud', 'Audios/Original/' + contest_id + '/' + final_filename,
                          'audio_original/' + contest_id + '/' + final_filename)
    newAudio.original_url = contest_id + '/' + final_filename
    newAudio.converted_url = contest_id + '/' + final_filename
    # if audio_name.rsplit('.', 1)[1].upper() in ALLOWED_CONVERTED_EXTENSIONS:
    #    audio.save('Audios/Converted/' + contest_id + '/' + final_filename)
    #    gcp_utils.upload_blob('group13_cloud', 'Audios/Converted/' + contest_id + '/' + final_filename,
    #                          'audio_converted/' + contest_id + '/' + final_filename)
    #    newAudio.status = 'Convertida'
    newAudio.save()
    flash('Hemos recibido tu voz. Ahora, la procesaremos para que sea publicada en la página del concurso y '
          'revisada por nuestro equipo de trabajo. Tan pronto la voz quede publicada'
          ' en la página del concurso, te notificaremos por email.')

    # pub(project_id, topic_id, newAudio_pub)
    pub(os.environ["PROJECT"], os.environ["ID_TOPIC"], newAudio_pub)

    return redirect(url_for('indexpeople'))


@app.route('/api/token', methods=['GET', 'POST'])
def get_auth_token():
    user = UserAdmin.objects(email=request.json['email']).first()

    if not user:
        return 'Access Denied', 403
    if not user.verify_password(request.json['password']):
        return 'Access Denied', 403
    g.user = user

    token = user.generate_auth_token()
    # Put it in the session
    session['api_user_id'] = user.id
    login_user(user, remember=True)
    return jsonify({'token': token.decode('ascii')})


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = UserAdmin.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = UserAdmin.objects(email=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@login_manager.user_loader
@cache.memoize()
def load_user(user_id):
    return UserAdmin.objects(id=user_id)


@app.route('/api/contest', methods=['GET'])
# @login_required
def getContests():
    contests = Contest.objects(Contest.user_id == session.get('api_user_id')).order_by('-creation_date')
    return jsonify(contests_schema.dump(contests))


per_page = 50


@app.route('/consultaconcurso/<string:contests_id>', methods=['GET'], defaults={"page": 1})
@app.route('/consultaconcurso/<string:contests_id>/<int:page>', methods=['GET'])
# @login_required
def getAudios(contests_id, page):
    try:
        contest = Contest.objects(name=contests_id).first()
        if contest is None:
            contest = Contest.objects(id=contests_id).all()
        if contest and current_user.first().is_authenticated:
            is_authenticated = True
            audios = Audio.objects(contest_id=contest.first().id).order_by("-creation_date")
            list = Pagination(audios, page, per_page)
    except Audio.DoesNotExist:
        return render_template('consultarconcurso.html', contest=contest.first(),
                               contests_id=contest.first().id, is_authenticated=is_authenticated)
    except AttributeError as err:
        is_authenticated = False
        try:
            audios = Audio.objects(contest_id=contest.first().id).order_by("-creation_date")
            list = Pagination(audios, page, per_page)
        except Audio.DoesNotExist:
            return render_template('consultarconcurso.html', contest=contest.first(),
                                   contests_id=contest.first().id, is_authenticated=is_authenticated)
    except Exception as e:
        return "Error al recuperar el concurso"
    if audios.count() == 0:
        return render_template('consultarconcurso.html', contest=contest.first(),
                               contests_id=contest.first().id, is_authenticated=is_authenticated)
    else:
        return render_template('consultarconcurso.html', audios=list, contest=contest.first(),
                               contests_id=contest.first().id, is_authenticated=is_authenticated)


@app.route('/')
def index():
    try:
        if current_user.is_authenticated:
            return redirect(url_for('indexadmin'))
        else:
            return redirect(url_for('indexpeople'))
    except:
        return redirect(url_for('indexadmin'))


@app.route('/home')
def indexpeople():
    contests = Contest.objects().order_by("-creation_date")
    return render_template('index.html', contests=contests)


@app.route('/indexadmin')
def indexadmin():
    contestslist = Contest.objects.filter(user_id=current_user.first().id).order_by(
        "-creation_date").all().values_list()
    return render_template('index_admin.html', contests=contestslist)


@app.route('/admin')
def admin():
    return render_template('admin.html')


@app.route('/addadmin', methods=['GET', 'POST'])
def addadmin():
    return render_template('addadmin.html')


@app.route('/admincreaconcurso')
@app.route('/admincreaconcurso/<string:contests_id>')
def admincreaconcurso(contests_id=None):
    return render_template('admincreaconcurso.html', contests_id=contests_id)


@app.route('/edit/<string:id>')
def admineditarconcurso(id):
    contest = Contest.objects(id=id).first()
    audios = Audio.objects(contest_id=id)
    if audios.count() > 0:
        audios = audios.order_by('-creation_date').all()
        return render_template('admingestionconcurso.html', contest=contest, audios=audios)
    else:
        return render_template('admingestionconcurso.html', contest=contest)


@app.route('/consultaconcurso/<string:id>')
def consultaconcurso(id):
    try:
        if current_user.first().is_authenticated:
            is_authenticated = True
    except:
        is_authenticated = False
    contest = Contest.objects(id=id).first()
    audios = Audio.objects(contest_id=id)
    if audios.count() > 0:
        audios = audios.order_by("-creation_date")
        return render_template('consultarconcurso.html', contest=contest, audios=audios,
                               is_authenticated=is_authenticated)
    else:
        return render_template('consultarconcurso.html', contest=contest, is_authenticated=is_authenticated)


@app.route('/delete/<string:id>')
def borrarconcurso(id):
    contest = Contest.objects(id=id).first()
    if os.path.exists('Audios/Original/' + str(contest.id)):
        rmtree('Audios/Original/' + str(contest.id))
    if os.path.exists('Audios/Converted/' + str(contest.id)):
        rmtree('Audios/Converted/' + str(contest.id))
    Audio.objects(contest_id=contest.id).delete()
    gcp_utils.delete_blobs('group13_cloud', str(contest.id))
    contest.delete()
    return redirect(url_for('indexadmin'))


@app.route('/participarconcurso/<string:contest_id>')
def participar(contest_id):
    contest = Contest.objects(id=contest_id).first()
    return render_template('inscribirparticipante.html', contest=contest)


@app.route('/inscribir/<string:id>')
def inscribir(id):
    return render_template('inscribirparticipante.html')


@app.route('/add_administrador', methods=['POST'])
def addadministrador():
    return render_template('addadmin.html')


@app.route('/add_concurso', methods=['POST'])
def add_concurso():
    return render_template('admincreaconcurso.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


def send_email(email_to='grupo13cloud@gmail.com', name='usuario', contest='', link='https://www.google.com/'):
    sender_email = 'grupo13cloud@gmail.com'
    receiver_email = email_to
    password = 'uniandes_cloud'

    message = MIMEMultipart("alternative")
    message["Subject"] = "SuperVoices - Hemos recibido tu voz!"
    message["From"] = sender_email
    message["To"] = receiver_email

    # Create the plain-text and HTML version of your message

    textmail = """Hola {name}! \n
    Hemos procesado tu aplicación al concurso {contest}.
    Ya puedes verlo en la página oficial del concurso, al que puedes acceder por medio del link:\n\n
    {link}\n\n
    Cordialmente, \n\n\n Equipo de SuperVoices.
    """.format(name=name, contest=contest, link=link)

    htmlmail = """\
    <html>
      <body>
        <p>Hola <b>{name}</b> !<br/>
            Hemos procesado tu aplicación al concurso <b>{contest}</b>.
            Ya puedes verlo en la página oficial del concurso, al que puedes acceder oprimiendo
            <a href={link}>aquí</a> , o accede por medio del link:<br/><br/>
            <center>
            {link}
            </center>
            <br/><br/>

            Cordialmente, <br/><br/><br/>Equipo de <b>SuperVoices</b>.
        </p>
      </body>
    </html>
    """.format(name=name, contest=contest, link=link)

    # Turn these into plain/html MIMEText objects

    part1 = MIMEText(textmail, "plain")
    part2 = MIMEText(htmlmail, "html")  # Add HTML/plain-text parts to MIMEMultipart message

    # The email client will try to render the last part first
    message.attach(part1)
    message.attach(part2)  # Create secure connection with server and send email
    context = ssl.create_default_context()

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        try:
            server.ehlo()
            server.starttls()
            server.login(sender_email, password)
            server.sendmail(
                sender_email, receiver_email, message.as_string()
            )
            server.close()
            # print('successfully sent the mail')
        except Exception as e:
            None


main_path = "/home/dvergel/Proyecto1-Grupo13/app/Audios/Original/"
dir_dst = "/home/dvergel/Proyecto1-Grupo13/app/Audios/Converted/"


@app.route('/converted', methods=['GET'])
def converted():
    # TODO conteo y limite a 15
    audios = Audio.objects(Audio.status == 'En Proceso').order_by('+creation_date')
    audios_count = audios.count()
    # filter_files = [file for file in listing_files if file.endswith(".ttt")]
    for audio in audios:

        filename = main_path + audio.original_url
        fileout = dir_dst + str(audio.contest_id) + "/" + str(audio.id) + ".mp3"
        fileout2 = str(audio.contest_id) + "/" + str(audio.id) + ".mp3"

        # print (filename , " Buscar:" , subname)
        # fullname_scr = main_path + filename + " " + fileout

        # print(filename)
        # print(fileout)

        command = f"ffmpeg  -i {filename} {fileout}"

        # print(command)
        os.system(command)
        ip = requests.get('https://checkip.amazonaws.com').text.strip()
        if os.path.exists(fileout):
            audio.status = "Convertida"
            audio.converted_url = fileout2
            audio.save()
            gcp_utils.upload_blob('group13_cloud', 'Audios/Converted/' + fileout2,
                                  'audio_converted/' + fileout2)
            send_email(audio.email, audio.first_name + " " + audio.last_name, audio.contest.name,
                       "http://" + ip + "/consultaconcurso/" + str(audio.contest.id))
            if os.path.exists('Audios/Original/' + str(audio.contest_id)):
                rmtree('Audios/Original/' + str(audio.contest_id))
            if os.path.exists('Audios/Converted/' + str(audio.contest_id)):
                rmtree('Audios/Converted/' + str(audio.contest_id))
    return json.dumps({'success': True}), 200, {'ContentType': 'application/json'}


def pub(project_id, topic_id, newAudio_pub):
    """Publishes a message to a Pub/Sub topic."""
    # Initialize a Publisher client.
    client = pubsub_v1.PublisherClient()
    # Create a fully qualified identifier of form `projects/{project_id}/topics/{topic_id}`
    topic_path = client.topic_path(project_id, topic_id)

    # Data sent to Cloud Pub/Sub must be a bytestring.
    # data = b"cadena"

    id_audio = newAudio_pub
    data = id_audio.encode("utf-8")

    # When you publish a message, the client returns a future.
    api_future = client.publish(topic_path, data)
    message_id = api_future.result()

    # print(f"Published {data} to {topic_path}: {message_id}")


if __name__ == '__main__':
    app.run(port=3000, debug=True)
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("project_id", help="Google Cloud project ID")
    parser.add_argument("topic_id", help="Pub/Sub topic ID")
    args = parser.parse_args()
