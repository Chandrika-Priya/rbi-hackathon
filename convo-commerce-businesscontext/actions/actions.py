from typing import Any, Text, Dict, List
from rasa_sdk import Action, Tracker
from rasa_sdk.executor import CollectingDispatcher
from rasa_sdk.events import SlotSet
import requests
import json

class ActionAccountBalance(Action):
    def name(self) -> Text:
        return "action_account_balance"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:

        nick_name=tracker.latest_message.get('metadata').get('nick_name')

        url = 'http://events.respark.iitm.ac.in:5000/rp_bank_api'
        data = {
        "action": "balance",
        "nick_name":nick_name
         }
        json_data = json.dumps(data)
        print("json_data====",json_data)
        headers = {'Content-Type': 'application/json'}
        response = requests.get(url,headers=headers,data=json_data) # API call

        if response.status_code == 200:
           account_balance = response.text.strip('{}').split(':')[1]
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

        url = 'http://events.respark.iitm.ac.in:5000/rp_bank_api'
        data = {
        "action": "history",
        "nick_name":nick_name
         }
        json_data = json.dumps(data)
        print("request data",json_data)
        headers = {'Content-Type': 'application/json'}
        response = requests.get(url,headers=headers,data=json_data) # API call
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

         url = 'http://events.respark.iitm.ac.in:5000/rp_bank_api'
         data = {
         "action": "register",
         "nick_name":nick_name,
         "full_name":full_name,
         "user_name":user_name,
         "pin_number":pin_number,
         "mob_number":mobile_number,
         "upi_id":upi_id
          }
         json_data = json.dumps(data)
         print("request data",json_data)
         headers = {'Content-Type': 'application/json'}
         response = requests.get(url,headers=headers,data=json_data) # API call

         if response.status_code == 200:
                 dispatcher.utter_message(f"User Added successfully")
         else:
                 dispatcher.utter_message("Sorry, I couldn't complete registration.")


class ActionUserInformation(Action):
    def name(self) -> Text:
        return "action_user_information"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        #tracker.get_slot['accountCurrency']
         nick_name=tracker.latest_message.get('metadata').get('nick_name')
         url = 'http://events.respark.iitm.ac.in:5000/rp_bank_api'
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

         print(user_details)
         user_info = json.loads(user_details)

         if response.status_code == 200:
                  nick_name= user_info["nick_name"],
                  full_name=user_info["full_name"],
                  user_name=user_info["user_name"],
                  pin_number=user_info["pin_number"],
                  mob_number=user_info["mob_number"],
                  upi_id=user_info["upi_id"]

                  dispatcher.utter_message(template="utter_user_details",nick_name=nick_name,full_name=full_name,mob_number=mob_number,upi_id=upi_id)
         else:
                  dispatcher.utter_message("Sorry, I couldn't find user details.")

class ActionTransferMoney(Action):
    def name(self) -> Text:
        return "action_transfer_money"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:

         url = 'http://events.respark.iitm.ac.in:5000/rp_bank_api'

         amount=next(tracker.get_latest_entity_values('number'), None)
         to_user=tracker.get_slot("to_user")
         nick_name=tracker.latest_message.get('metadata').get('nick_name')

         data = {
         "action": "transfer",
         "to_user"  :to_user,
         "from_user":nick_name,
         "amount"   :amount

         }
         json_data = json.dumps(data)
         print("request data",json_data)
         headers = {'Content-Type': 'application/json'}
         #headers = {'Accept':'application/json'}
         response = requests.get(url,headers=headers,data=json_data) # API call

         if response.status_code == 200:
                   dispatcher.utter_message(template="utter_transaction_details",amount=amount,to_user=to_user)
         else:
                  dispatcher.utter_message("Sorry, couldn't transfer funds")

class ActionRemoveUser(Action):
    def name(self) -> Text:
        return "action_remove_user"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        #tracker.get_slot['accountCurrency']
         nick_name=tracker.latest_message.get('metadata').get('nick_name')

         url = 'http://events.respark.iitm.ac.in:5000/rp_bank_api'
         data = {
         "action": "remove",
         "nick_name":nick_name
         }
         json_data = json.dumps(data)
         print("request data",json_data)
         headers = {'Content-Type': 'application/json'}
         #headers = {'Accept':'application/json'}
         response = requests.get(url,headers=headers,data=json_data) # API call

         if response.status_code == 200:
                   dispatcher.utter_message(template="utter_remove_user")
         else:
                  dispatcher.utter_message("Sorry, couldn't remove user")