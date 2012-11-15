import webapp2

form="""
<form method="post">
    What is your birthday?
    <br>
    <label>
        Month
        <input type="text" name="month">
    </label>
    <label>
        Day
        <input type="text" name="day">
    </label>
    <label>Year
    <input type="text" name="year">
    </label>
    <input type="submit">
</form>
"""

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

class MainPage(webapp2.RequestHandler):
    def get(self):
        #self.response.headers['Content-Type'] = 'text/plain'
        self.response.write(form)

    def post(self):
    	user_month = valid_month(self.request.get('month'))
    	user_day = valid_day(self.request.get('day'))
    	user_year = valid_year(self.request.get('year'))

    	if not (user_month and user_day and user_year):
    		self.response.write(form)
    	else:
    		self.response.write("Thanks! Thats a totally valid day!")

app = webapp2.WSGIApplication([('/', MainPage)],
                              debug=True)
#Left off at 37