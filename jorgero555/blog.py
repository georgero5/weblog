#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import re
import webapp2
import jinja2
import string
import sys
import urllib2
import logging
import time
from utils import *

from xml.dom import minidom
from google.appengine.ext import db

from google.appengine.api import memcache
from datetime import datetime, timedelta

DEBUG = os.environ['SERVER_SOFTWARE'].startswith('Development')
if DEBUG:
	logging.getLogger().setLevel(logging.DEBUG)

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
							   autoescape = True)
			
def render_str(template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)
		
class BaseHandler(webapp2.RequestHandler):
	def render_str(self, template, **params):		
		params['user'] = self.user
		return render_str(template, **params)
	
	def render(self, template, **kw):
		self.response.out.write(self.render_str(template, **kw))
		
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)
		
	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header('Set-Cookie',
										 '%s=%s; Path=/' % (name, cookie_val))
	
	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)
		
	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))
		
	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
		
	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))
	
	def notfound(self):
		self.error(404)
		self.write('<h1>404: Not Found</h1>Sorry, that page does not exist.')
		
class Register(BaseHandler):
	def get(self):
		next_url = self.request.headers.get('referer', '/')
		self.render('signup-form.html', next_url = next_url)
		
	def post(self):
		next_url = str(self.request.get('next_url'))
		if not next_url or next_url.startswith('/login'):
			next_url = '/blog/welcome'
			
		self.uname = self.request.get('username')
		self.pwd = self.request.get('password')
		self.vpwd = self.request.get('verify')
		self.email = self.request.get('email')
		error = False 

		params = dict(uname = self.uname,
				  email = self.email)
		if not(valid_user(self.uname)):
			params['error_username'] = "Incorrect user name format..."
			error = True
	
		if self.pwd != self.vpwd:
			params['error_verify'] = "Password verification doesn't match..."
			error = True
		
		if not(valid_pwd(self.pwd)):
			params['error_password'] = "You have to set a password..."
			error = True
		
		if self.email and not(valid_email(self.email)):
			params['error_email'] = "Incorrect email format..."			
			error = True
			
		if error:
			self.render('signup-form.html', **params)
		else:
			u = User.by_name(self.uname)
		
			if u:
				msg = 'That user already exists.'
				self.render('signup-form.html', error_username = msg)
			else:
				u = User.register(self.uname, self.pwd, self.email)
				u.put()
				
				self.login(u)
				self.redirect(next_url)		
			
class Login(BaseHandler):
	def get(self):
		next_url = self.request.headers.get('referer', '/')
		self.render('login-form.html', next_url = next_url)
	
	def post(self):
		uname = self.request.get('username')
		pwd = self.request.get('password')
		
		next_url = str(self.request.get('next_url'))
		if not next_url or next_url.startswith('/blog/login'):
			next_url = '/blog/welcome'
		
		u = User.login(uname, pwd)
		if u:
			self.login(u)
			self.redirect(next_url)
		else:
			msg = 'Invalid login'
			self.render('login-form.html', error = msg)
		
class Logout(BaseHandler):
	def get(self):
		next_url = '/blog/login'
		self.logout()
		self.redirect(next_url)		
	
		
class Welcome(BaseHandler):
	def get(self):
		if self.user:
			self.render('welcome.html', username = self.user.name)
		else:
			self.redirect('/blog/signup')
			
class Blog(BaseHandler):
	def get(self):
		posts = db.GqlQuery("select * from Post order by created desc limit 10")
		self.render('front.html', posts = posts)
			
class NewPost(BaseHandler):		
	def get(self):
		if self.user:
			self.render("newpost.html")
		else:
			self.redirect("/blog/login")
	
	def post(self):
		if not self.user:
			self.redirect('/blog')
			
		subject = self.request.get('subject')
		content = self.request.get('content')
		params = dict(subject = subject,
					  content = content)
		
		if subject and content:
			p = Post(parent = blog_key(), subject = subject, content = content)
			p.put()
			self.redirect('/blog/%s' % str(p.key().id()))
		else:
			params['error'] = "we need both a subject and content in the post!"
			self.render('newpost.html', **params)
			
class EditPost(BaseHandler):		
	def get(self, post_id):
		if self.user:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			p = db.get(key)			
			
			self.render("editpost.html", p = p)
		else:
			self.redirect("/blog/login")
	
	def post(self, post_id):
		if not self.user:
			self.redirect('/blog')
		
		subject = self.request.get('subject')
		content = self.request.get('content')			

		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		p = db.get(key)
		
		if subject and content:
			p.subject = subject
			p.content = content
			p.last_modified = datetime.now()
			p.put()
			self.redirect('/blog/%s' % str(p.key().id()))
		else:
			error = "we need both a subject and content in the post!"
			self.render('editpost.html', p = p, error = error)
			
class DeletePost(BaseHandler):		
	def get(self, post_id):
		if self.user:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			post = db.get(key)			
			post.delete()
			
			self.redirect("/blog")
		else:
			self.redirect("/blog/login")	
		
class PostPage(BaseHandler):
	def get(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)
		
		if not post:
			self.error(404)
			return
		self.render("permalink.html", post = post)
	
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)
	
class Post(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p = self)
		
	def as_dict(self):
		time_fmt = '%c'
		d = {'subject': self.subject,
			'content': self.content,
			'created': self.created.strftime(time_fmt),
			'last_modified': self.last_modified.strftime(time_fmt)}
		return d
		
def users_key(group = 'default'):
	return db.Key.from_path('users', group)

class User(db.Model):
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()
	
	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid, parent = users_key())
		
	@classmethod
	def by_name(cls, name):
		u = User.all().filter('name =', name).get()
		return u
		
	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return User(parent = users_key(),
					name = name,
					pw_hash = pw_hash,
					email = email)
			
	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u

app = webapp2.WSGIApplication([
	('/blog/signup/?', Register),
	('/blog/?', Blog),
	('/blog/welcome/?', Welcome),
	('/blog/newpost/?', NewPost),
	('/blog/edit/([0-9]+)/?', EditPost),
	('/blog/delete/([0-9]+)/?', DeletePost),
	('/blog/([0-9]+)/?', PostPage),
	('/blog/login/?', Login),
	('/blog/logout/?', Logout)
], debug=DEBUG)
