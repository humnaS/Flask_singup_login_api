from flask import Flask, jsonify,request
from flask_restful import Api,Resource
from flask_sqlalchemy import SQLAlchemy
import bcrypt



app = Flask(__name__)
db = SQLAlchemy(app)
api = Api(app)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True





class Users (db.Model) :
    id = db.Column(db.Integer , primary_key=True)
    user_name = db.Column(db.String(40))
    password = db.Column(db.String(20))
    user_email=db.Column(db.String(40))


def UserExist(username,email):
  
        s = db.session()
        query = s.query(Users).filter(Users.user_email==email) 
        query1=s.query(Users).filter(Users.user_name==username) 
        result = query.first()
        result2=query1.first()
        print(result2)
        print(result)
        if result==None and result2==None:
            return False
        else:
            return True




class Sign_Up(Resource):
    def post(self):

        postedDate=request.get_json()
        name = postedDate['user_name']
        password = postedDate['password']
        email=postedDate["user_email"]
        #yhn pe chala ky dekh lyna same pe dera hai ture ya false pe

        if UserExist(name,email):
            retJson = {"status" : 301, "msg": "already register"}

        

        #Store username and pw into the database
        else:
            hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
            user1 = Users(user_name= name,password = hashed_pw,user_email=email)
            db.session.add(user1)
            db.session.commit()
            retJson = {"status":200,"msg":"singup successfully"}
        return jsonify(retJson)

def verify_user(email,password):
    s = db.session()
    query = s.query(Users).filter(Users.user_email==email)
    result = query.first()
    if result == None:
        return False,None
   
    else:
        print("password",password)
        #hashed_pw=bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
        for name,db_password in s.query(Users.user_name,Users.password).filter(Users.user_email==email):
            print(name)
            print(db_password)
            
            if bcrypt.hashpw(password.encode('utf8'), db_password) == db_password:
                return True,name
            else:
                return False,None
    


class Login(Resource):
    def post(self):
        postedDate=request.get_json()

        email = postedDate['user_email']
        password = postedDate['password']
        result,name=verify_user(email,password)

        if  result== False:
            retJson = {"status" : 301, "msg": "Invalid Username or Password"}
            return jsonify(retJson)

        else:
            retJson = {"status":200,"msg":"You've successfully signed up to the Api","User Name":name}
            return jsonify(retJson)




api.add_resource(Sign_Up, '/sign_up')  
api.add_resource(Login, '/login')

if __name__ == "__main__":
    app.run(debug=True)
    