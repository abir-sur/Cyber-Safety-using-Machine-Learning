
import numpy as np
import pandas as pd
from flask import Flask, request, render_template
import pickle
import re
from tld import get_tld
from urllib.parse import urlparse
from googlesearch import search


safe_url = pd.read_csv("top500Domains.csv")

with open('model.pkl', 'rb') as f:
        model = pickle.load(f)

def if_ip_address(url):
        match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
        if match:
            return 1
        else:
            return 0
        
        
def count_dot(url):
    count_dot = url.count('.')
    return count_dot

def count_www(url):
    url.count('www')
    return url.count('www')

def count_attherate(url):
    
    return url.count('@')

def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')

def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')

def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                    'tr\.im|link\.zip\.net',
                    url)
    if match:
        return 1
    else:
        return 0
    
def count_http(url):
    return url.count('http')

def count_https(url):
    return url.count('https')

def count_per(url):
    return url.count('%')

def count_ques(url):
    return url.count('?')

def count_hyphen(url):
    return url.count('-')

def count_equal(url):
    return url.count('=')

def url_length(url):
    return len(str(url))

def hostname_length(url):
    return len(urlparse(url).netloc)

def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                    url)
    if match:
        return 1
    else:
        return 0
    
def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits

def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters

def fd_length(url):
    urlpath= urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0
    
def tld_length(tld):
    try:
        return len(tld)
    except:
        return -1

app = Flask(__name__)



@app.route('/')
def home():
    return render_template('index.html')
    


@app.route('/predict', methods=['POST'])
def predict():
    if request.method == 'POST':
        url = request.form['url']
    
    if url in safe_url["Root Domain"].values:
        res = "SAFE"
        
    else:
        tld = get_tld(url,fail_silently=True)   
        
        features = [if_ip_address(url),count_dot(url),count_www(url),count_attherate(url),no_of_dir(url),no_of_embed(url),
                    shortening_service(url),count_https(url),count_http(url),count_per(url),count_ques(url),count_hyphen(url),
                    count_equal(url),url_length(url),hostname_length(url),suspicious_words(url),digit_count(url),letter_count(url),
                    fd_length(url),tld_length(tld)]
        
        features = np.array(features).reshape((1, -1))
        pred = model.predict(features)
        
        if int(pred[0]) == 0:
            
            res="SAFE"
            
        elif int(pred[0]) == 1:
            
            res="DEFACEMENT"
        
        elif int(pred[0]) == 2:
            res="MALWARE"
    
            
        elif int(pred[0]) == 3:
            
            res="PHISHING"
    
    is_safe = res == "SAFE"
            
    return render_template('index.html', prediction = res, is_safe = is_safe, url_check = url)


if __name__ == "__main__":
    app.run(port=5500)