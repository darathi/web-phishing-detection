from flask import *
import numpy as np
from markupsafe import escape
import pickle
from inputScript import main

app = Flask(__name__)

#use the model
model=pickle.load(open('phishing.pkl',"rb"))


@app.route('/res')
def res():
    return render_template('res.html')


@app.route('/form')
def single_page():
    return render_template('index.html')


@app.route('/move', methods=["GET","POST"])
def get_prediction():
        url = request.form['url']
        checking=main(url)
        predictions=model.predict(checking)
        value=predictions[0]
        val=0
        if value==1:
            val=1
            txt="This is not a phishing website"
        else:
            val=0
            txt="This is a phishing website"
        return render_template("res.html",predicted='{}'.format(txt),url=url)

if __name__== "__main__":
    app.run(host='0.0.0.0', debug=True)













































