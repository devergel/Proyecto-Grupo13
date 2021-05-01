import socket

import requests
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mysqldb import MySQL
import os
import sys
import shutil
from flask_login import LoginManager, login_user, UserMixin, current_user
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy
from ffmpy import FFmpeg
import json
import logging
import os
import uuid

import datetime
import smtplib
import ssl
import argparse
from shutil import rmtree

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from os import abort

from flask import Flask, jsonify, g, render_template, session, send_file
from flask import request
from flask_httpauth import HTTPBasicAuth
from flask_marshmallow import Marshmallow
from flask_login import LoginManager, login_user, UserMixin, current_user
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from passlib.apps import custom_app_context as pwd_context
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# MongoDB Database
from flask_mongoengine import MongoEngine, Pagination
import mongoengine as me
from google.cloud import pubsub_v1

# GCP Utils
import gcp_utils

listar = Flask(__name__, template_folder="templates",
               static_folder="static",
               static_url_path="")

FILE_FOLDER = 'Audios/Original'
FILE_FOLDER_CONVERTED = 'Audios/Converted'
ALLOWED_EXTENSIONS = set(['WAV', 'AAC', 'AIFF', 'AIFF', 'DSD', 'FLAC', 'MP3', 'MQA', 'OGG', 'WMA'])
ALLOWED_CONVERTED_EXTENSIONS = ['MP3']
if not os.path.exists(FILE_FOLDER):
    os.umask(0)
    os.makedirs(FILE_FOLDER, mode=0o777)
if not os.path.exists(FILE_FOLDER_CONVERTED):
    os.umask(0)
    os.makedirs(FILE_FOLDER_CONVERTED, mode=0o777)
listar.config['SECRET_KEY'] = 'S3cretH4sh'
listar.config['MONGODB_SETTINGS'] = {
    'db': os.environ["MONGO_DB"],
    'host': "mongodb+srv://" + os.environ["MONGO_USER"] + ":" + os.environ["MONGO_PASSWORD"] + "@" + os.environ[
        "MONGO_HOST"] + "/" + os.environ["MONGO_DB"] + "?retryWrites=true&w=majority"
}

db = MongoEngine(listar)
ma = Marshmallow(listar)


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
        s = Serializer(listar.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': str(self.id)})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(listar.config['SECRET_KEY'])
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

main_path = "/home/c_caballeroa/Proyecto1-Grupo13/app/Audios/Original/"
dir_dst = "/home/c_caballeroa/Proyecto1-Grupo13/app/Audios/Converted/"


# main_path = "F:\\Uniandes\\S3-Desarrollo de Soluciones Cloud\\Proyecto1-Grupo13b\\Proyecto1-Grupo13\\app\\Original\\"
# dir_dst = "F:\\Uniandes\\S3-Desarrollo de Soluciones Cloud\\Proyecto1-Grupo13b\\Proyecto1-Grupo13\\app\\Converted\\"
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
    # context = ssl.create_default_context()

    with smtplib.SMTP("smtp.sendgrid.net", 587) as server:
        try:
            server.ehlo()
            server.starttls()
            server.login(os.environ["APIUSER"], os.environ["APIKEY"])
            server.sendmail(
                sender_email, receiver_email, message.as_string()
            )
            server.close()
            # ('successfully sent the mail')
        except Exception as e:
            print("failed to send mail" + str(e))


def converted(id_audio):

    # audios = Audio.query.filter(Audio.status == 'En Proceso' and Audio.id == id_audio). \
    #    order_by(Audio.creation_date.desc())
    audios = Audio.objects(id=id_audio)

    # filter_files = [file for file in listing_files if file.endswith(".ttt")]
    for audio in audios:

        contest = Contest.objects(id=audio.contest_id).first()
        print(audio.contest_id)
        if not os.path.exists(main_path + audio.contest_id):
            print("crea ruta")
            os.umask(0)
            os.mkdir(main_path + audio.contest_id, mode=0o777)
            os.mkdir(dir_dst + audio.contest_id, mode=0o777)

        filename = main_path + audio.original_url

        fileout = dir_dst + audio.contest_id + "/" + str(audio.id) + ".mp3"
        fileout2 = audio.contest_id + "/" + str(audio.id) + ".mp3"
        print("descarga archivo")
        gcp_utils.download_blob('group13_cloud',
                                'audio_original/' + audio.original_url,
                                main_path + audio.original_url)

        # print (filename , " Buscar:" , subname)
        # fullname_scr = main_path + filename + " " + fileout
        print("covierte")
        command = f"ffmpeg  -i {filename} {fileout}"

        print(command)
        os.system(command)
        ip = requests.get('https://checkip.amazonaws.com').text.strip()
        if os.path.exists(fileout):
            audio.status = "Convertida"
            audio.converted_url = fileout2
            audio.save()
            gcp_utils.upload_blob('group13_cloud', dir_dst + fileout2,
                                  'audio_converted/' + fileout2)
            send_email(audio.email, audio.first_name + " " + audio.last_name, contest.name,
                       "http://" + ip + "/consultaconcurso/" + str(contest.id))
            if os.path.exists(main_path + str(audio.contest_id)):
                rmtree(main_path + str(audio.contest_id))
            if os.path.exists(dir_dst + str(audio.contest_id)):
                rmtree(dir_dst + str(audio.contest_id))


## Sub Pub/Sub
def sub(project_id, subscription_id, timeout=None):
    """Receives messages from a Pub/Sub subscription."""
    # Initialize a Subscriber client
    subscriber_client = pubsub_v1.SubscriberClient()
    # Create a fully qualified identifier in the form of
    # `projects/{project_id}/subscriptions/{subscription_id}`
    subscription_path = subscriber_client.subscription_path(project_id, subscription_id)

    def callback(message):
        # print(f"Received {message}.")
        # Acknowledge the message. Unack'ed messages will be redelivered.
        id_audio = message.data.decode("utf-8")

        message.ack()
        converted(id_audio)

        # print(f"Acknowledged {message.message_id}.")

    streaming_pull_future = subscriber_client.subscribe(
        subscription_path, callback=callback
    )

    try:
        # Calling result() on StreamingPullFuture keeps the main thread from
        # exiting while messages get processed in the callbacks.
        streaming_pull_future.result(timeout=timeout)
    except:  # noqa
        streaming_pull_future.cancel()

    subscriber_client.close()

    # converted(id_audio)

    #   shutil.move(fullname_scr, dir_dst)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("project_id", help="Google Cloud project ID")
    parser.add_argument("subscription_id", help="Pub/Sub subscription ID")
    parser.add_argument(
        "timeout", default=None, nargs="?", const=1, help="Pub/Sub subscription ID"
    )
    args = parser.parse_args()
    sub(args.project_id, args.subscription_id, args.timeout)
    # sub(os.environ["PROJECT"], os.environ["ID_TOPIC"], args.timeout)
