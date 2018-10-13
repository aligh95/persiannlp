"""
Routes and views for the flask application.
"""

from flask import render_template
from TextProcessor import app

from functools import wraps
import logging
from flask import request,jsonify,Response,render_template,json
import hashlib
from werkzeug.security import check_password_hash
from flask import  redirect,  url_for, flash  
from flask import send_from_directory
from werkzeug import SharedDataMiddleware
import pymongo
from pymongo import MongoClient
import uuid
import string
import random
from werkzeug.utils import secure_filename
import os
from bson.objectid import ObjectId
import time
from bson import BSON
from bson import json_util
from bson.json_util import dumps
import smtplib
import datetime
import nltk, re, pprint
from nltk import word_tokenize

from nltk import sent_tokenize
#import language_check
from nltk.corpus import stopwords

from nltk.sentiment.vader import SentimentIntensityAnalyzer
from nltk import tokenize
from InstagramAPI import InstagramAPI

#from instagram.client import InstagramAPI

import requests 
import hazm
import goslate
from textblob import TextBlob


client = MongoClient()
client = MongoClient('localhost', 27017)
db = client.CommentProcessor
users = db.Users
categories = db.Categories
comments = db.Comments

userNameInsta = "InstagramUsername"
passwordInsta = "InstagramPassword"

until_date = '2017-03-31'
count = 100

API = InstagramAPI(userNameInsta,passwordInsta)
API.login()
#API.getUsernameInfo()

defaultHost = '36.67.119.129:65301'
nltk.set_proxy(defaultHost)


file_handler = logging.FileHandler('app.log')
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)



@app.errorhandler(401)
def unauthorized(error=None):
    message = {
            'status': 401,
            'message': 'Not authorized : ' + request.url,
    }
    resp = jsonify(message)
    resp.status_code = 401

    return resp


@app.errorhandler(404)
def not_found(error=None):
    message = {
            'status': 404,
            'message': 'Not Found: ' + request.url,
    }
    resp = jsonify(message)
    resp.status_code = 404

    return resp

@app.errorhandler(500)
def internal_server_error(error=None):
    message = {
            'status': 500,
            'message': 'Server Error In : ' + request.url,
    }
    resp = jsonify(message)
    resp.status_code = 500

    return resp

def generateUserKey():
    try:
        return str(uuid.uuid1())
    except:
        pass

def encodePassword(texttohash):
    try:
        return str(hashlib.md5(texttohash.encode('utf-8')).hexdigest())
    except:
        pass

def check_auth(username, password, key):
    password = encodePassword(password)
    is_register_user = users.find_one({'username' : username,
                                        'password': password,
                                        'keys.key': key,
                                        'keys.isExpire' : False})
    if(is_register_user):
        return True
    else:
        return False

def authenticate():
    message = {'message': "Authenticate."}
    resp = jsonify(message)

    resp.status_code = 401
    resp.headers['WWW-Authenticate'] = 'Basic realm="Example"'

    return resp

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            auth = request.authorization
            key = request.headers['x-api-key']
            if not auth: 
                return authenticate()

            elif not check_auth(auth.username, auth.password,key):
                return authenticate()
            return f(*args, **kwargs)
        except:
            return authenticate()
        

    return decorated

def returnCreator(data):
    resp = jsonify(data)
    resp.status_code = data['status']
    return resp

def id_generator(size=6, chars=string.ascii_uppercase + string.ascii_lowercase + string.digits):
    try:
        return ''.join(random.choice(chars) for _ in range(size))
    except:
        pass



@app.route('/')
@app.route('/home')
def home():
    """Renders the home page."""
    return render_template(
        'index.html',
        title='Home Page',
        year=datetime.datetime.now().year,
    )

@app.route('/contact')
def contact():
    """Renders the contact page."""
    return render_template(
        'contact.html',
        title='Contact',
        year=datetime.now().year,
        message='Your contact page.'
    )

@app.route('/about')
def about():
    """Renders the about page."""
    return render_template(
        'about.html',
        title='About',
        year=datetime.now().year,
        message='Your application description page.'
    )

@app.route('/api')
def api():
    message = {
            'status': 200,
            'message': 'wellcome to ' + request.url,
    }
    resp = jsonify(message)
    resp.status_code = 200
    return resp


@app.route('/api/login', methods=['POST'])
def login():
    data = { 'data': {} }
    if(request.data is not None):
        dataJson = json.loads(request.data)
        username = dataJson['userName']
        enterPass = dataJson['userPassword']
        password = encodePassword(enterPass)
        data['data']['key'] = 'not valid'
        is_register_user = users.find_one({'username' : username,
                                            'password': password})
        if(is_register_user):
            is_not_expire_key = users.find_one({
                                                'username' : username,
                                                'password': password,
                                                'keys.isExpire' : False
                                            })
            if(is_not_expire_key):
                data['data']['key'] = is_not_expire_key['keys'][-1]['key']
            else:
                newKey = generateUserKey()
                user_data = {'isExpire' : False , 'key' : newKey , 'createDate' : datetime.datetime.utcnow()}
                result = users.update_one({'username': username}, {'$push': {'keys': user_data}})
                data['data']['key'] = newKey

            data['status'] = 200
            data['message'] = 'Welcome'
            data['data']['userId'] = str(is_register_user['_id'])
        else:
            data['status'] = 404
            data['message'] = 'Ooops , User Not Found :('

        logins_data = {'ip' : str(request.remote_addr) ,
                        'password':enterPass, 
                        'datetime' : datetime.datetime.utcnow() , 
                        'status' : data['status'],
                        'key' : data['data']['key'] }
        result = users.update_one({'username': username}, {'$push': {'logins': logins_data}})
    else:
        return not_found()

    resp = jsonify(data)
    resp.status_code = data['status']

    return resp


@app.route('/api/CheckText', methods = ['POST'])
@requires_auth
def CheckText():
    try:
        data = { 'data': {} }
        if(request.data is not None):
            dataJson = json.loads(request.data)
            text = dataJson['text']
            #hash = dataJson['hash'] 
            #ip = request.remote_addr
            #baseUsername = request.authorization.username
            check_user = True #users.find_one({'username': baseUsername })
            orgSentence=''
            if(check_user):
                dict = checkText(text,True)
                data['data'] = dict
                data['message'] = 'every things is ok :)'
                data['status'] = 200
            else:
                data['message'] = 'oops , user not found :('
                data['status'] = 404

            resp = jsonify(data)
            resp.status_code = data['status']
            return resp
        else:
            return not_found()
    except Exception as ex:
        return internal_server_error()

@app.route('/api/CheckSentenceOfText', methods = ['POST'])
#@requires_auth
def CheckSentenceOfText():
    data = { 'data': {} }
    if(request.data is not None):
        dataJson = json.loads(request.data)
        text = dataJson['text']
        #hash = dataJson['hash'] 
        #ip = request.remote_addr
        #baseUsername = request.authorization.username
        check_user = True #users.find_one({'username': baseUsername })
        orgSentence=''
        if(check_user):
            fa_blob = TextBlob(text)    
            detected_lang = fa_blob.detect_language() 
            isNotEnglish= detected_lang is not 'en'
            if(isNotEnglish):
                orgSentence = text
                text = fa_blob.translate(to='en').raw
                sentences = tokenize.sent_tokenize(text)
            else:
                sentences = tokenize.sent_tokenize(text)
                detected_lang='en'

            sid = SentimentIntensityAnalyzer()
            dict = {}
            i = 1

            for sentence in sentences:
                oth_text= sentence
                if(isNotEnglish):
                    oth_blob = TextBlob(sentence)
                    oth_text =  oth_blob.translate(to=detected_lang).raw
                ss = sid.polarity_scores(sentence)
                
                dict[i] = {'Language':detected_lang,'Sentence':oth_text,'Positive':ss['pos'],'Negative': ss['neg'],'Compound':ss['compound'],'Neutral':ss['neu']}
                i= i+1
            data['data'] = dict
            data['message'] = 'every things is ok :)'
            data['status'] = 200
        else:
            data['message'] = 'oops , user not found :('
            data['status'] = 404

        resp = jsonify(data)
        resp.status_code = data['status']
        return resp
    else:
        return not_found()


def checkText(sent,isRaw = False):
    i = 1
    dict = {}
    isNotEnglish = True
    try:
        isPersian= True
        if(isPersian):
            text = sent
            fa_blob = TextBlob(text)
            detected_lang =  fa_blob.detect_language() 
            isNotEnglish = detected_lang is not 'en'
            if(isNotEnglish):
                text = fa_blob.translate(to='en').raw
            sid = SentimentIntensityAnalyzer()
            
            if(isRaw):
                ss = sid.polarity_scores(text)
                return {'Sentence':sent,'Positive':ss['pos'],'Negative': ss['neg'],'Compound':ss['compound'],'Neutral':ss['neu']}
                i= i+1
            else:
                sentences = tokenize.sent_tokenize(text)
                for sentence in sentences:
                    oth_text = sentence
                    if(isNotEnglish):
                        oth_blob = TextBlob(sentence)
                        oth_text =  oth_blob.translate(to=detected_lang).raw
                    ss = sid.polarity_scores(sentence)
                
                    dict[i] = {'Language':detected_lang,'Sentence':oth_text,'Positive':ss['pos'],'Negative': ss['neg'],'Compound':ss['compound'],'Neutral':ss['neu']}
                    i= i+1



        #    if(fa_blob.detect_language() != 'en'):
        #        text = fa_blob.translate(to='en').raw
        #    sentences = (text)
        #else:
        #    sentences = tokenize.sent_tokenize(text)

        #for sentence in sentences:
   
    except Exception as e:
        logger.error('Failed to upload to ftp: '+ str(e))
        return {'Sentence':sent,'Positive':0,'Negative': 0,'Compound':0,'Neutral':0}
    return dict
    

    

#@app.route('/api/CheckGrammer', methods = ['POST'])
##@requires_auth
#def CheckGrammer():
#    data = { }
#    if(request.data is not None):
#        dataJson = json.loads(request.data)
#        text = dataJson['text']
        
#        check_user = True #users.find_one({'username': baseUsername })
#        if(check_user):
#            tool = language_check.LanguageTool('en-US')
#            matches = tool.check(text)
#            if(len(matches) == 0):
#                data['isCorrect'] = 'True'
#            else:
#                data['isCorrect'] = 'False'
#            data['errorCount'] = len(matches) 
#            data['sentence'] = text
#            data['status'] = 200
#            data['correctSentence'] =  language_check.correct(text, matches)
#        else:
#            data['message'] = 'oops , user not found :('
#            data['status'] = 404

#        resp = jsonify(data)
#        resp.status_code = data['status']
#        return resp
#    else:
#        return not_found()



@app.route('/api/GetSentence', methods = ['POST'])
#@requires_auth
def SentenceCount():
    data = { 'data': {} }
    if(request.data is not None):
        dataJson = json.loads(request.data)
        text = dataJson['text']
        #hash = dataJson['hash'] 
        #ip = request.remote_addr
        #baseUsername = request.authorization.username
        check_user = True #users.find_one({'username': baseUsername })
        if(check_user):
            tokens = sent_tokenize(text)
            data['length'] = len(tokens)
            data['message'] = 'every things is ok :)'
            data['status'] = 200
            data['data'] = tokens
        else:
            data['message'] = 'oops , user not found :('
            data['status'] = 404

        resp = jsonify(data)
        resp.status_code = data['status']
        return resp
    else:
        return not_found()
    

@app.route('/api/GetWords', methods = ['POST'])
#@requires_auth
def GetSentenceWords():
    data = { 'data': {} }
    if(request.data is not None):
        dataJson = json.loads(request.data)
        text = str(dataJson['text'])
        #hash = dataJson['hash'] 
        ip = request.remote_addr
        #baseUsername = request.authorization.username
        check_user = True # users.find_one({'username': baseUsername })
        if(check_user):

            tokens = word_tokenize(text)
            data['length'] = len(tokens)
            data['message'] = 'every things is ok :)'
            data['status'] = 200
            data['data'] = tokens
        else:
            data['message'] = 'oops , user not found :('
            data['status'] = 404

        resp = jsonify(data)
        resp.status_code = data['status']
        return resp
    else:
        return not_found()

import requests 
import re



@app.route('/api/GetPublicInstagrammComments', methods = ['GET'])
def GetPublicInstagrammComments():
    mediaUrl = request.args.get('mediaUrl') 
    comments = []
    data = { 'data': {} }
    print('start get comments : ' + getNowTime())
    postinfo = get_media_idByJson(mediaUrl)
    if(postinfo):
        allcomment = getAllMediaComments(postinfo['media_id'],None)
        comments.append(
                    {
                        'postid':postinfo['media_id'],
                        'Title':postinfo['title'],
                        'full_name':postinfo['author_name'],
                        'comment_count':len(allcomment),
                        'like_count':0,
                        'allcomment':allcomment
                    })
    
            
    print('end get comments : ' + getNowTime())

    data['data'] = comments
    data['status'] = 200
    data['statustext'] = 'every Thing is ok :)'

    data['count'] = len(comments)
    return  jsonify(data)

@app.route('/api/GetInstagrammComments', methods = ['GET'])
def GetInstagrammComment():
    
    comments = []
    data = { 'data': {} }
    allposts =  getAllMyPost()
    print('start get comments : ' + getNowTime())

    for post in allposts:
        postid = post["id"]
        postTitle = post['caption']['text']
        full_name = post['user']['full_name']
        comment_count = post['comment_count']
        like_count = post['like_count']
        allcomment = getAllMediaComments(postid,None)
        comments.append(
                {
                    'postid':postid,
                    'Title':postTitle,
                    'full_name':full_name,
                    'comment_count':comment_count,
                    'like_count':like_count,
                    'allcomment':allcomment
                }
            )


    print('end get comments : ' + getNowTime())

    data['data'] = comments
    data['status'] = 200
    data['statustext'] = 'every Thing is ok :)'

    data['count'] = len(comments)
    return  jsonify(data)


def getAllMediaComments(media_id,until_date ):
    has_more_comments = True
    comments = []
    commentsText = []
    max_id = ''
    while has_more_comments:
        _ = API.getMediaComments(media_id, max_id=max_id)
        for c in reversed(API.LastJson['comments']):
            comments.append(c)
            commentText = c['text'];
            if(len(commentText)>3):
                commentsText.append(checkText(commentText,True))
        has_more_comments = API.LastJson.get('has_more_comments', False)
        if until_date:
            older_comment = comments[-1]
            dt = datetime.utcfromtimestamp(older_comment.get('created_at_utc', 0))
            # only check all records if the last is older than stop condition
            if dt.isoformat() <= until_date:
                # keep comments after until_date
                comments = [
                    c
                    for c in comments
                    if datetime.utcfromtimestamp(c.get('created_at_utc', 0)) > until_date
                ]
                # stop loop
                has_more_comments = False
                print ("stopped by until_date")
        # next page
        if has_more_comments:
            max_id = API.LastJson.get('next_max_id', '')
            time.sleep(2)

    return commentsText


def get_media_id(url):
    req = requests.get(url)
    str = req.text
    result = re.search('instagram:\/\/media\?id=(.*)\" \/>', str)
    print (result.group(1))
    media_id =result.group(1)
    return media_id


def get_media_idByJson(url):
    try:

        req = requests.get('https://api.instagram.com/oembed/?url={}'.format(url))
        #media_id = req.json()['media_id']
        #media_title = req.json()['title']
        #media_author_name = req.json()['author_name']
        #media_id = req.json()['media_id']
    
        return req.json()
    except:
        return None



def getAllMyPost():
    print('start get Post : ' + getNowTime())
    myposts=[]
    has_more_posts = True
    max_id=""

    while has_more_posts:
        API.getSelfUserFeed(maxid=max_id)
        if API.LastJson['more_available'] is not True:
            has_more_posts = False #stop condition
            print ("stopped")
    
        max_id = API.LastJson.get('next_max_id','')
        myposts.extend(API.LastJson['items']) #merge lists
        time.sleep(2) # Slows the script down to avoid flooding the servers 
    print('end get Post : ' + getNowTime())
    
    return myposts


def getNowTime():
    return(time.ctime())