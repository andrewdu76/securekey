from flask import Blueprint, render_template, request, flash, jsonify
from flask_login import login_required, current_user
from .models import User_Credentials
from . import db
import json

views = Blueprint('views', __name__)


@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST': 
        username = request.form.get('username')
        userpassword = request.form.get('userpassword')
        urlinfo = request.form.get('urlinfo')

        if len(username) < 1 or len(userpassword)< 1 or len(urlinfo) < 1:
            flash('Credential is too short!', category='error') 
        else:
           
            new_credentials = User_Credentials(user_login=username, User_password=userpassword,  url_link=urlinfo, user_id=current_user.id)  #providing the schema for the note 
            db.session.add(new_credentials) #adding the note to the database 
            db.session.commit()
            flash('New User Credentials added!', category='success')

    return render_template("home.html", user=current_user)

@views.route('/view', methods=['GET', 'POST'])
@login_required
def view():
    return render_template("view.html", user=current_user)
    

@views.route('/delete-note', methods=['POST'])
def delete_note():  
    note = json.loads(request.data) # this function expects a JSON from the INDEX.js file 
    noteId = note['noteId']
    note = User_Credentials.query.get(noteId)
    if note:
        if note.user_id == current_user.id:
            db.session.delete(note)
            db.session.commit()

    return jsonify({})