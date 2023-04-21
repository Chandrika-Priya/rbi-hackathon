import os
import re
from flask import Flask, request
from markupsafe import escape
from translate import Translate
from datetime import datetime
#from flask_cors import CORS

app = Flask(__name__)
#CORS(app)
t2t = None

model_path = os.environ['T2T_MODEL_PATH']
now = datetime.now()
start_time = now.strftime("%d/%m/%Y %H:%M:%S")

languages = {"telugu" : "te", "english" : "en", "tamil" : "ta", "marathi" : "ma", "hindi": "hi","kannada":"ka","gujarati":"gu"}

def initialize_models():
    global t2t
    t2t = Translate(model_path)

@app.route("/")
def hello_world():
    name = os.environ.get("NAME", "World")
    return "Hello {0}! time is {1}".format(name, start_time)

@app.route("/translate", methods=["POST"])
def translateIndicToEnglish():
    data = request.form
    sentence = data.get("q")
    source = data.get("source")
    target = data.get("target")
    translated_sentence = translate(sentence, source, target)
    return {"translatedText": translated_sentence}

@app.route("/translate/e2i", methods=["POST"])
def translateEnglishToIndic():
    data = request.json
    sentence = data["q"]
    source = data["source"]
    target = data["target"]
    translated_sentence = translate(sentence, source, target)
    return {"translatedText": translated_sentence}


def validate_language(language):
    lang_arr = ["te", "hi", "en", "ta", "ma","ka","gu"]
    if language not in lang_arr:
        raise {"error": f"{language} is not supported"}

def translate(sentence, source, target):
    try:
        #validate_language(source)
        #validate_language(target)
        pass
    except:
        return {"error": f"source or target language is not supported"}

#     global t2t
#     if t2t is None:
#         t2t = Translate(model_path)
    translated_sentence = ""
    if target == "en":
        translated_sentence = t2t.translate_indic_to_english(languages[source], sentence)
    if source == "en":
        translated_sentence = t2t.english_to_indic(languages[target], sentence)
    return translated_sentence

if __name__ == "__main__":
    initialize_models()
    app.run(debug=True, host="0.0.0.0", use_reloader=False, port=int(os.environ.get("PORT", 5001)))
