import webapp2
import re
import os

import jinja2
from google.appengine.ext import db

jinja_env = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))




class BaseHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template,**kw):
        self.write(self.render_str(template, **kw))

                   
class Birthday(BaseHandler):
    def get(self):
        #self.response.headers['Content-Type'] = 'text/plain'
        self.render("birthday.html")

    def post(self):
        user_month = self.request.get('month')
        user_day = self.request.get('day')
        user_year = self.request.get('year')
        month = valid_month(user_month)
        day = valid_day(user_day)
        year = valid_year(user_year)

        template_values = {"month" : user_month,
                           "day" : user_day,
                           "year" : user_year
                           }

        if not (month and day and year):
            error =  "That doesn't look valid to me, friend."
            self.render("birthday.html", month = user_month, day = user_day, year = user_year, error = error )
        else:
            self.redirect("/thanks")

class MainPage(BaseHandler):
    def get(self):
        self.render("index.html")

class ThanksHandler(BaseHandler):
    def get(self):
        write("Thanks! Thats a totally valid day!")

class Rot13Form(BaseHandler):

    def get(self):
        self.render("rot13.html")

    def post(self):
        usrRot13 = rot13encrypt(self.request.get('text'))
  
        self.render("rot13.html",text = usrRot13)

class Signup(BaseHandler):

    def get(self):
      self.render("signup.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
                      email = email)

        if not valid_username(username):
            params['username_error'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['password_error'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['verify_error'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render("signup.html", **params)
        else:
            self.redirect('/welcome?username=' + username)

class Welcome(BaseHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render("welcome.html", username = username)
        else:
            self.redirect("/signup")

   # Task - Build a blog
   # - Front page that lists entries
   # - Form to submit new entries
   # - Permalink page for entries
   # - Title / Date then HR and post
   # - /blog/newpost to post blog stuff
################
# BLOG
################
class BlogEntry(db.Model):
    subject = db.StringProperty(required=True)
    blogtext = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class BlogNewPost(BaseHandler):
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

class BlogPermalink(BaseHandler):
    def get(self,blog_id):
        s = BlogEntry.get_by_id(int(blog_id))
        self.render("blog.html",blogs=[s])

class Blog(BaseHandler):
    def get(self):
        s = db.GqlQuery("SELECT * FROM BlogEntry ORDER BY created DESC")
        self.render("blog.html",blogs=s)

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/birthday',Birthday),
                               ('/thanks', ThanksHandler),
                               ('/unit2/signup',Signup),
                               ('/welcome',Welcome),
                               ('/rot13', Rot13Form),
                               ('/blog/newpost',BlogNewPost),
                               ('/blog/(\d+)',BlogPermalink),
                               ('/blog',Blog)],
                               debug=True)



def rot13encrypt(text):
  return text.encode("rot13")


#############################
# birthday validation
#############################
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
          
def valid_month(month):
    for i in months:
        if(i.lower() == month.lower()):
            return month[0].upper() + month[1:].lower()
    return None

def valid_day(day):
    if day and day.isdigit():
        day = int(day)
        if day > 0 and day <= 31:
           return int(day)
    return None

def valid_year(year):
   if year and year.isdigit():
       year = int(year)
       if year > 1900 and year < 2020:
           return year
   return None


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