from flask import *
import numpy as np

import pickle
from inputScript import main

import requests

# NOTE: you must manually set API_KEY below using information retrieved from your IBM Cloud account.
API_KEY = "<apikey>"
token_response = requests.post('https://iam.cloud.ibm.com/identity/token', data={"apikey":
 API_KEY, "grant_type": 'urn:ibm:params:oauth:grant-type:apikey'})
mltoken = token_response.json()["access_token"]

header = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + mltoken}

app = Flask(__name__)


model=pickle.load(open('phishing.pkl',"rb"))




@app.route('/form')
def single_page():
    return render_template('index.html')


@app.route('/predictdata', methods=["GET","POST"])
def get_prediction():
        url = request.form['url']
        val=main(url)
        print(url)
      
        print(type(url))
        # NOTE: manually define and pass the array(s) of values to be scored in the next line
        payload_scoring = {"input_data": [{"field": 'url', "values": val}]}

        response_scoring = requests.post('<deplomentstatus>', json=payload_scoring,
        headers={'Authorization': 'Bearer ' + mltoken})
        print("Scoring response")
        predictions=response_scoring.json()
        output=predictions['predictions'][0]['values'][0][0]

        if output==-1:
            val=1
            txt="This is not a phishing website"
        if output==1:
            txt="You are in a phishing site."
        else:
            val=0
            txt="This is a suspicious website"
        return render_template("dashboard.html",predicted='{}'.format(txt),url=url)

if __name__== "__main__":
    app.run(host='0.0.0.0', debug=True)

















































