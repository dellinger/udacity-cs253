import webapp2

form = """
    <form method="post">
       What is your birthday?
       <br>
       <input type="text" name="month">
       <input type="text" name="day">
       <input type="text" name="year">
       
       <br>
       <br>
       <input type="submit">
    </form>
    """ 
class MainPage(webapp2.RequestHandler):        
    def get(self):
        self.response.out.write(form)


app = webapp2.WSGIApplication([('/', MainPage)], debug=True)

