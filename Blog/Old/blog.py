import webapp2
import re
import os
import hashlib
import random
from string import letters
import hmac
import json

import jinja2
from google.appengine.ext import db
from google.appengine.api import memcache
from datetime import datetime, timedelta

jinja_env = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))

# Normally would be stored in another module
secret = 'bo5GWcSVL.y2rYXjRf21X'
CACHE = {}


# Main Handler for Blog

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template,**kw):
        self.write(self.render_str(template, **kw))

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)
    
    # Secures cookie
    def set_secure_cookie(self,name,val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie','%s=%s; Path=/' % (name,cookie_val))

    def read_secure_cookie(self,name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)
    
    def login(self,user):
        self.set_secure_cookie('user_id',str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie','user_id=; Path=/')
    
    #Not necessarily needed
    # after every request initalize is called
    # Will check for cookie on each page
    def initialize(self,*a,**kw):
        webapp2.RequestHandler.initialize(self,*a,**kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'


class MainPage(BlogHandler):
    def get(self):
        self.render("index.html")


class Signup(BlogHandler):

    def get(self):
      self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['username_error'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['password_error'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['verify_error'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render("signup.html", **params)
        else:
            self.done()

    def done(self,*a,**kw):
        raise NotImplementedError

class BlogSignup(Signup):
    def done(self):
        #Make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = "That user already exists"
            self.render('signup.html', username_error = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')

class Login(BlogHandler):
    def get(self):
      self.render("login.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username,password)
        if  u:
            # Set cookie
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = "Invalid Login"
            self.render("login.html",error = msg)
      
class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/signup')


# Was used for a lot of testing, may not be needed
class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

def blog_key(name = 'default'):
        return db.Key.from_path('blogs', name)

def age_set(key,val):
    save_time = datetime.utcnow()
    memcache.set(key,(val,save_time))

def age_get(key):
    result = memcache.get(key)
    if result:
        val, save_time = result
        age = (datetime.utcnow() - save_time).total_seconds()
    else:
        val,age = None, 0
    return val,age

def add_post(post):
    post.put()
    get_posts(update = True) 
    return str(post.key().id())

def get_posts(update = False):
    q = db.GqlQuery("SELECT * FROM BlogEntry ORDER BY created DESC")
    mc_key = "BLOGS"

    posts, age = age_get(mc_key)
    if update or posts is None: 
        posts = list(q)
        age_set(mc_key,posts)

    return posts,age

def age_str(age):
    s = "queried %s seconds ago"
    age = int(age)
    if age == 1:
        s = s.replace("seconds", "second")
    return s % age


class BlogNewPost(BlogHandler):
    def get(self):
        self.render("newBlogPost.html")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")


        params = dict(subject = subject,
                      content = content)

        if (subject and content):
            b = BlogEntry(subject=subject,blogtext=content)
            b_key = b.put()
            self.redirect("%d" % b_key.id())
        else:
            params["error"] = "Need to fill out all fields..."
            self.render("newBlogPost.html",**params)

class BlogPermalink(BlogHandler):
    def get(self,post_id):
        post_key = 'POST_' + post_id

        post, age = age_get(post_key)
        if not post:
            key = db.Key.from_path("POST", int(post_id), parent=None)
            post = db.get(key)
            age_set(post_key, post)
            age = 0

        if not post:
            self.error(404)
            return

        
        self.render("blog.html",blogs=post)

def age_set(key,val):
    memcache.set(key,(val,datetime.utcnow()))

def age_get(key):
    result = memcache.get(key)
    if result:
        val, save_time = result
        age = (datetime.utcnow() - save_time).total_seconds()
    else:
        val,age = None, 0
    return val,age

def add_post(post):
    post.put()
    get_posts(update = True) 
    return str(post.key().id())

def get_posts(update = False):
    q = db.GqlQuery("SELECT * FROM BlogEntry ORDER BY created DESC")
    mc_key = "BLOGS"

    posts, age = age_get(mc_key)
    if update or posts is None: 
        posts = list(q)
        age_set(mc_key,posts)

    return posts,age

def age_str(age):
    s = "queried %s seconds ago"
    age = int(age)
    if age == 1:
        s = s.replace("seconds", "second")
    return s % age

class Blog(BlogHandler):
    def get(self):
        posts,age = get_posts()
        if self.format == "html":
            self.render("blog.html",blogs=posts, age = age_str(age))
        else:
            return self.render_json([p.as_dict() for p in posts])        


class JsonPostHandler(BlogHandler):
    def get(self):
        list = []
        blogs = db.GqlQuery("SELECT * FROM BlogEntry ORDER BY created DESC LIMIT 10")
        for blog in blogs:
            blogDict = {}
            blogDict["content"] = blog.blogtext
            blogDict["created"] = blog.created.strftime("%a %b %d %H:%M:%S %Y")
           # blogDict["last_modified"] = blog.last_modified.strftime("%a %b %d %H:%M:%S %Y")
            blogDict["subject"] = blog.subject
            list.append(blogDict)
        self.render_json(list)

class NewPostJson(BlogHandler):
    def get(self,blog_id):
        s = BlogEntry.get_by_id(int(blog_id))
        blogDict = {}
        blogDict["content"] = s.blogtext
        blogDict["created"] = s.created.strftime("%a %b %d %H:%M:%S %Y")
        # blogDict["last_modified"] = blog.last_modified.strftime("%a %b %d %H:%M:%S %Y")
        blogDict["subject"] = s.subject
        self.render_json(blogDict)



###############################################
# Regular Expression Validation
###############################################
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)
################################################

###############################################
# Hash Functions | Salt Functions
###############################################
def hash_str(s):
    return hashlib.md5(s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hmac.new(secret,s).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split("|")[0]
    if secure_val == make_secure_val(val):
        return val

def make_salt(length = 5):
    return "".join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name,pw,salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt,h)

def valid_pw(name,password,h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name,password,salt)

#optional
def users_key(group = "default"):
    return db.Key.from_path('users',group)

############################
# DB Objects
###########################

class BlogEntry(db.Model):
    subject = db.StringProperty(required=True)
    blogtext = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    #Declarator, call this method on this object
    # This is the alternative to GQL
    @classmethod
    def by_id(cls,uid):
        return cls.get_by_id(uid,parent=users_key())

    @classmethod
    def by_name(cls,name):
        u = cls.all().filter('name = ', name).get()
        return u

    @classmethod
    def register(cls,name,pw,email = None):
        pw_hash = make_pw_hash(name,pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls,name,pw):
        u = cls.by_name(name)
        if u and valid_pw(name,pw,u.pw_hash):
            return u


app = webapp2.WSGIApplication([('/', Blog),
                               ('/signup',BlogSignup),
                               ('/login',Login),
                               ('/logout',Logout),
                               ('/welcome',Welcome),
                               ('/newpost',BlogNewPost),
                               ('/(\d+)',BlogPermalink),
                               ('/.json',JsonPostHandler),
                               ('/(\d+).json',NewPostJson)
                               ],
                               debug=True)
