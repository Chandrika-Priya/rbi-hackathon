import os
import requests
from flask import Flask, request
from markupsafe import escape
import json
import re

app = Flask(__name__)
t2t = None

BASE_URL = "http://localhost:5005"


@app.route("/")
def hello_world():
    name = os.environ.get("NAME", "World")
    return "Hello {}!".format(name)


def get_intent(base_url, sender_id, text):
    body = {"sender_id": sender_id, "text": text}
    res = requests.post(base_url + "/model/parse", json=body).json()
    return {"context": res["intent"]["name"], "intent_ranking": res["intent_ranking"]}


def get_conversation(base_url, sender_id, message,metadata):
    body = {"sender_id": sender_id, "message": message,"metadata":metadata}
    res = requests.post(base_url + "/webhooks/rest/webhook", json=body).json()
    return [e["text"] for e in res]


@app.route("/next-step", methods=['POST'])
def process_req():
    req_json = request.json
    sender_id = req_json["sender_id"]
    message = req_json["message"]
    metadata = req_json["metadata"]
    r = {
        "nextStep": {},
        "data": [],
        "context": ""
    }
    intent_res = get_intent(
        BASE_URL, sender_id, message )
    conversations = get_conversation(
        BASE_URL, sender_id, message,metadata)
    r["context"] = intent_res["context"]
    intent_ranking = intent_res["intent_ranking"]
    all_messages = []
    for i in range(len(conversations)):
        if i >= len(intent_ranking):
            break
        m = {"message": conversations[i],
             "confidence": intent_ranking[i]["confidence"],
             "name": intent_ranking[i]["name"]}
        all_messages.append(m)
    r["data"] = pop_data_from_conversations(all_messages)
    if len(all_messages) > 0:
        r["nextStep"]["message"] = all_messages.pop(0)["message"]
    else:
        r["nextStep"]["message"] = "Result"
    r["nextStep"]["alternates"] = all_messages
    return r


def pop_data_from_conversations(conversation_arr):
    for i in range(len(conversation_arr)):
        if str(conversation_arr[i]["message"]).startswith("Data#####"):
            return parse_data(conversation_arr.pop(i)["message"])
    return []


def parse_data(data_str: str):
    if data_str == None:
        return []
    regex = r'ObjectId\("([a-fA-F0-9]+)"\)'

    # Find all matches of ObjectId instances in the input string
    matches = re.findall(regex, data_str)

    # Replace each match with a string representation of the ObjectId
    for match in matches:
        data_str = data_str.replace(f'ObjectId("{match}")', f'"{match}"')

    return json.loads(data_str[9:])


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8081)))