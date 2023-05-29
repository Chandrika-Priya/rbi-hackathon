from typing import Any, Text, Dict, List
from rasa_sdk import Action, Tracker
from rasa_sdk.executor import CollectingDispatcher
from rasa_sdk.events import SlotSet
import requests
import json

import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

private_key = b'''
-----BEGIN PRIVATE KEY-----
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
7Rs82r9SFC1sDAxxdyWKrDcijLi1SVw=
-----END PRIVATE KEY-----
'''
public_key = b'''
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvVWcF72SARmle0b5cKFy
L5HdY7uhj6Txq9hQPprYmh+edUC7BU+0UMyIn0qyU+QglYlNbtIh44Cthwgh7HEi
NckBiHY9jGOBGoC47o09j5W3NSZG6QbhCofKI5tFF6CI15j+/KSf4gfPeHC92nAx
LheaPdCO67BhYoegGSA3XfMCSg8iGtwiLEEo420VOdkccM/mMq8ZentfPSq+8bvq
ixxjwGArbebQbZVhZzY/zLCL9i6eaVB+yVSHa+QCXxhXKRAHGs3w/M8Yb0vDvuFG
/6a+81sxUAfOKMd2/tI/R1jxyXO7j4GBSjXrfWdA3SeYsdK58ieA4pj+bdBcIYrM
XknxbidHEWQbNCTrnVdnauXL5f3qrD0KCyt3Bn4cYrq/tQfjK7SseGxHbrvTAssE
kdeBmKOHe4aTCIUDAqDmADx4yEywfBR3rV1CGsu5+kkutswb+hOh2AajdNHkOz6s
g7+jo/kkBNgkJ+oTRWPwPri5PqeCgHJg+mdaHQK4aiuNGTt1cWgkfcb4p8Ye5+0y
QPJkYQQvkEwAwnMjA0PGQAd7foUuOkro+oui1IYgR97T+nO2F2i5JIgDsmfURQj2
BjMB2fW3z6/VVXp8PyWIna4dZEdRI5qWKcyZzLmJZxBAAtG4R0C+V8kUGxAXmtLz
IzGz76FZlsSOFEDPUB4z9YUCAwEAAQ==
-----END PUBLIC KEY-----
'''
token = "rp-fj30f0tjnvlvr9z"

rp_bank_url = 'https://events.respark.iitm.ac.in:3000/rp_bank_api'

class ActionAccountBalance(Action):
    def name(self) -> Text:
        return "action_account_balance"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:

        nick_name=tracker.latest_message.get('metadata').get('nick_name')

        url = rp_bank_url
        data = {
        "action": "balance",
        "api_token": token,
        "nick_name":nick_name
         }
        json_data = json.dumps(data)
        encrypted_data= encryption(json_data)
        print(encrypted_data)
        print("json_data====",json_data)
        headers = {'Content-Type': 'text/plain'}
        encrypted_response = requests.post(url,encrypted_data,verify=False) # API call
        if encrypted_response.status_code == 200:
            print("encoded")
            print(encrypted_response.text)

            decrypted_response=decryption(str(encrypted_response.text)[2:-1])
            print(decrypted_response)
            account_balance = decrypted_response.strip('{}').split(':')[1]
        else:
            print("Error:", response.status_code)

        account_currency = 'INR'

        # Set the account_balance slot with the fetched value
        dispatcher.utter_message("your balance is" + account_balance)
        return []

class ActionTransactionHistory(Action):
    def name(self) -> Text:
        return "action_transaction_history"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        nick_name=tracker.latest_message.get('metadata').get('nick_name')
        date_filter=tracker.latest_message.get('metadata').get('date_filter')
        user_filter=tracker.get_slot("to_user")

        url = 'https://events.respark.iitm.ac.in:3001/rp_bank_api'
        data = {
        "action": "history",
        "api_token": token,
        "nick_name":nick_name,
        "date_filter":date_filter,
        "user_filter":user_filter
         }
        json_data = json.dumps(data)
        print("request data",json_data)
        headers = {'Content-Type': 'application/json'}
        response = requests.get(url,headers=headers,data=json_data,verify=False) # API call
        message= response.text.replace("'",'"')

        dispatcher.utter_message(template="utter_transaction_history",data=message)


class ActionRegisterUser(Action):
    def name(self) -> Text:
        return "action_register_user"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        #tracker.get_slot['accountCurrency']
         nick_name=tracker.latest_message.get('metadata').get('nick_name')
         full_name=tracker.latest_message.get('metadata').get('full_name')
         user_name=tracker.latest_message.get('metadata').get('user_name')
         pin_number=tracker.latest_message.get('metadata').get('pin_number')
         mobile_number=tracker.latest_message.get('metadata').get('mob_number')
         upi_id=tracker.latest_message.get('metadata').get('upi_id')

         url = rp_bank_url
         data = {
         "action": "register",
         "nick_name":nick_name,
         "full_name":full_name,
         "user_name":user_name,
         "pin_number":pin_number,
         "api_token": token,
         "mob_number":mobile_number,
         "upi_id":upi_id
          }
         json_data = json.dumps(data)
         print("request data",json_data)
         encrypted_data= encryption(json_data)
         headers = {'Content-Type': 'text/plain'}
         encrypted_response = requests.post(url,encrypted_data,verify=False)# API call
         decrypted_response=decryption(str(encrypted_response.text)[2:-1]).replace("'",'"')
         print(decrypted_response) # API call

         if encrypted_response.status_code == 200:
                 dispatcher.utter_message(f"User Added successfully")
         else:
                 dispatcher.utter_message("Sorry, I couldn't complete registration.")


class ActionUserInformation(Action):
    def name(self) -> Text:
        return "action_user_information"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        #tracker.get_slot['accountCurrency']
         nick_name=tracker.latest_message.get('metadata').get('nick_name')
         url = rp_bank_url
         data = {
         "action": "details",
         "api_token": token,
         "nick_name":nick_name
         }
         json_data = json.dumps(data)
         print("request data",json_data)
         encrypted_data= encryption(json_data)
         headers = {'Content-Type': 'text/plain'}
         encrypted_response = requests.post(url,encrypted_data,verify=False)# API call
         decrypted_response=decryption(str(encrypted_response.text)[2:-1]).replace("'",'"')
         print(decrypted_response) # API call
         json_str = decrypted_response
         user_details = json_str.replace("'", "\"").replace("ObjectId(", " ").replace(")", "")

         print(user_details)
         user_info = json.loads(user_details)

         if encrypted_response.status_code == 200:
                  nick_name= user_info["nick_name"],
                  full_name=user_info["full_name"],
                  user_name=user_info["user_name"],
                  pin_number=user_info["pin_number"],
                  mob_number=user_info["mob_number"],
                  upi_id=user_info["upi_id"]

                  dispatcher.utter_message(template="utter_user_details",nick_name=nick_name[0],full_name=full_name[0],mob_number=mob_number[0],upi_id=upi_id)
         else:
                  dispatcher.utter_message("Sorry, I couldn't find user details.")

class ActionTransferMoney(Action):
    def name(self) -> Text:
        return "action_transfer_money"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:

         url = rp_bank_url

         amount=next(tracker.get_latest_entity_values('number'), None)
         to_user=tracker.get_slot("to_user")
         nick_name=tracker.latest_message.get('metadata').get('nick_name')

         data = {
         "action": "transfer",
         "to_user"  :to_user,
         "api_token": token,
         "from_user":nick_name,
         "amount"   :amount

         }
         json_data = json.dumps(data)
         print("request data",json_data)
         encrypted_data= encryption(json_data)
         headers = {'Content-Type': 'text/plain'}
         encrypted_response = requests.post(url,encrypted_data,verify=False)# API call
         decrypted_response=decryption(str(encrypted_response.text)[2:-1])
         print(decrypted_response) # API call

         if encrypted_response.status_code == 200:
                   dispatcher.utter_message(template="utter_transaction_details",amount=amount,to_user=to_user)
         else:
                  dispatcher.utter_message("Sorry, couldn't transfer funds")

class ActionRemoveUser(Action):
    def name(self) -> Text:
        return "action_remove_user"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        #tracker.get_slot['accountCurrency']
         nick_name=tracker.latest_message.get('metadata').get('nick_name')

         url = rp_bank_url
         data = {
         "action": "remove",
         "api_token": token,
         "nick_name":nick_name
         }
         json_data = json.dumps(data)
         print("request data",json_data)
         encrypted_data= encryption(json_data)
         headers = {'Content-Type': 'text/plain'}
         encrypted_response = requests.post(url,encrypted_data,verify=False)# API call
         decrypted_response=decryption(str(encrypted_response.text)[2:-1])
         print(decrypted_response) # API call

         if encrypted_response.status_code == 200:
                   dispatcher.utter_message(template="utter_remove_user")
         else:
                  dispatcher.utter_message("Sorry, couldn't remove user")

class ActionLoginUser(Action):
    def name(self) -> Text:
        return "action_login_user"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:

        nick_name=tracker.latest_message.get('metadata').get('nick_name')
        pin=tracker.latest_message.get('metadata').get('pin')

        url = rp_bank_url
        data = {
        "action": "details",
        "nick_name":nick_name,
        }
        json_data = json.dumps(data)
        print("request data",json_data)
        headers = {'Content-Type': 'application/json'}
        #headers = {'Accept':'application/json'}
        response = requests.get(url,headers=headers,data=json_data) # API call
        json_str = response.content.decode('utf-8')
        user_details = json_str.replace("'", "\"").replace("ObjectId(", " ").replace(")", "")

        user_info = json.loads(user_details)

        if response.status_code == 200:
                 nick_name= user_info["nick_name"],
                 full_name=user_info["full_name"],
                 user_name=user_info["user_name"],
                 pin_number=user_info["pin_number"],
                 mob_number=user_info["mob_number"],
                 upi_id=user_info["upi_id"]
                 if(pin_number[0]==pin):
                    dispatcher.utter_message("Login successful")
                 else:
                    dispatcher.utter_message("entered pin is wrong")
        else:
                 dispatcher.utter_message("Sorry, I couldn't find user details.")


def decryption(encoded_data):
    # Load the private key
    pkey = serialization.load_pem_private_key(
        private_key,
        password=None,
        backend=default_backend()
    )

    # Base64 decode the encrypted data
    encrypted_data = base64.b64decode(encoded_data)
    plaintext = pkey.decrypt(
        encrypted_data,
        padding.PKCS1v15()
    )

    return plaintext.decode('utf-8')

def encryption(data):
    # Load the public key
    pub_key = serialization.load_pem_public_key(public_key, backend=default_backend())

    # Encrypt the data using RSA with PKCS1 padding
    encrypted_data = pub_key.encrypt(
        data.encode('utf-8'),
        padding.PKCS1v15()
    )

    # Base64 encode the encrypted data
    encoded_data = base64.b64encode(encrypted_data)

    return encoded_data.decode('utf-8')