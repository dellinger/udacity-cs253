import webapp2

form="""
<form method="post">
    What is your birthday?
    <br>
    <label>
        Month
        <input type="text" name="month" value="%(month)s">
    </label>
    <label>
        Day
        <input type="text" name="day" value="%(day)s">
    </label>
    <label>Year
    <input type="text" name="year" value="%(year)s">
    </label>
    <div style="color: red">%(error)s</div>
    <input type="submit">
</form>
"""

signupForm = """
<form method = "post">
   <h1>Signup</h1>
   <label>
      Username
      <input type="text" name="username">
   </label>
   <label>
      Password
      <input type="text" name="password">
   </label>
   <label>
      Verify Password
      <input type="text" name="verifypass">
    </label>
    <label>
       Email(optional)
       <input type="text" name="email">
    <label>
    <input type="submit>
</form>
"""

Rot13html = """
<form method="post">
   
   <br>
   <label>
      <h1>Enter in text to encode in rot13</h1>
      <textarea name="text">%(text)s</textarea>
   </label>
   <br>
   <input type="submit">
</form>
"""


class MainPage(webapp2.RequestHandler):
    def write_form(self,error="", month="",day="", year=""):
        self.response.out.write(form % {"error" : error,
                                      "month" : escape_html(month),
                                      "day" : escape_html(day),
                                      "year" : escape_html(year)})
    def get(self):
        #self.response.headers['Content-Type'] = 'text/plain'
        self.write_form()

    def post(self):
        user_month = self.request.get('month')
        user_day = self.request.get('day')
        user_year = self.request.get('year')
        month = valid_month(user_month)
        day = valid_day(user_day)
        year = valid_year(user_year)

        if not (month and day and year):
    		    self.write_form("That doesn't look valid to me, friend.",
                        user_month,user_day,user_year)
        else:
            self.redirect("/thanks")

class ThanksHandler(webapp2.RequestHandler):
   def get(self):
       self.response.write("Thanks! Thats a totally valid day!")

class Rot13Form(webapp2.RequestHandler):

    def write_form(self,text = ""):
        self.response.out.write(Rot13html % {"text" : escape_html(text)})

    def get(self):
        self.write_form()

    def post(self):
        usrRot13 = rot13encrypt(self.request.get('text'))
  
        self.write_form(usrRot13)

class Signup(webapp2.RequestHandler):
    def write_form(self):
      self.response.out.write(signup.html)

    def get():
       self.write_form()

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/thanks', ThanksHandler),
                               ('/signup',Signup),
                               ('/rot13', Rot13Form)],
                               debug=True)





def rot13encrypt(text):
  return text.encode("rot13")

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

def escape_html(s):
    s = s.replace('&','&amp;')
    s = s.replace('>','&gt;')
    s = s.replace('<','&lt;')
    s = s.replace('"','&quot;')
    
    return s