import os
import re
import cgi
import hashlib
import hmac
import random
import string
import sys
import urllib2

# security stuff
SECRET = 'imsosecret'

def hash_str(s):
	return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))
	
def check_secure_val(h):
	s = h.split('|')[0]
	if h == make_secure_val(s):
		return s

def make_salt(length=5):
	return ''.join(random.choice(string.letters) for x in xrange(length))	

def make_pw_hash(name, pw, salt=None):
	if not(salt):
		salt = make_salt()
        
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s|%s' % (h,salt)

def valid_pw(name, pw, h):
	s = h.split('|')[1]
	if(h == make_pw_hash(name, pw, s)):
		return True
		
# validation stuff
months = ['January',
		  'February',
		  'March',
		  'April',
		  'May',
		  'June',
		  'July',
		  'August',
		  'September',
		  'October',
		  'November',
		  'December']
		  
month_abbvs = dict((m[:3].lower(),m) for m in months)

def valid_month(month):
	if month:
		short_month = month[:3].lower()
		return month_abbvs.get(short_month)
		
def valid_day(day):
	if day and day.isdigit():
		day = int(day)
		if day>0 and day<=31:
			return day

def valid_year(year):
	if year and year.isdigit():
		year = int(year)
		if year>1900 and year<=2020:
			return year

USER_RE = re.compile("^[a-zA-Z0-9_-]{3,20}$")
def valid_user(user):
	return user and USER_RE.match(user)
	
PASSWORD_RE = re.compile("^.{3,20}$")
def valid_pwd(pwd):
	return pwd and PASSWORD_RE.match(pwd)
	
EMAIL_RE = re.compile("^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
	return EMAIL_RE.match(email)
	
# escaping html
def escape_html(s):
	return cgi.escape(s, quote = True)
	
# other stuff
def gray_style(lst):
	for n, x in enumerate(lst):
		if n % 2 == 0:
			yield x, ''
		else:
			yield x, 'gray'
			