import requests, re,json, sys
import numpy as np
from requests.exceptions import InvalidSchema
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup

IDENTITY_URL = "https://identity.vwgroup.io"
OLA_URL = "https://ola.prod.code.seat.cloud.vwgroup.com"
CLIENT_ID = "99a5b77d-bd88-4d53-b4e5-a539c60694a3%40apps_vw-dilab_com"

with open("config.json") as config_file:
    config = json.load(config_file)

def ola_request(endpoint):
    return requests.get(OLA_URL + endpoint, headers={'Authorization': 'Bearer ' + jwt_token})
    
def extract_tokens(html): return{"_csrf":m.group(1)if(m:=re.search(r'(?:["\']csrf_token["\']|csrf_token)\s*:\s*["\']([^"\']+)["\']',html))else(_ for _ in()).throw(ValueError("No csrf_token")), "hmac":m.group(1)if(m:=re.search(r'(?:["\']hmac["\']|hmac)\s*:\s*["\']([^"\']+)["\']',html))else(_ for _ in()).throw(ValueError("No hmac")), "relayState":m.group(1)if(m:=re.search(r'(?:["\']relayState["\']|relayState)\s*:\s*["\']([^"\']+)["\']',html))else(_ for _ in()).throw(ValueError("No relayState"))}

def request_jwt_token(location):
    try:
        response = session.get(location)
    except InvalidSchema as exc:
        match = re.search(r"No connection adapters were found for '(.*?)'",  str(exc))
        if match:
            seat_url = match.group(1)
            code_list = parse_qs(urlparse(seat_url).query).get("code")
            if code_list:
                jwt_token = code_list[0]
            else:
                print("No 'code' parameter found in URL:", seat_url)
                raise SystemExit
        else:
            print("No seat:// URL found in exception message.")
            raise SystemExit

    return jwt_token

# Start session.
session = requests.Session()

# Retrieve the login screen
response = session.get(IDENTITY_URL + "/oidc/v1/authorize?redirect_uri=seat%3A%2F%2Foauth-callback&client_id="+CLIENT_ID+"&response_type=code&scope=openid%20profile%20nickname%20birthdate%20phone", allow_redirects=True)

# Parse the html contents.
form = BeautifulSoup(response.text, "html.parser").find("form")
if not form:
    raise RuntimeError("No form found in the response.")

# Grab the tokens needed for the first login step.
post = {tag.get("name"): tag.get("value") for tag in form.find_all("input", {"type": "hidden"})}
post.update({"email": config['USERNAME']})

# Login (1)
response = session.post(IDENTITY_URL + form.get("action"),data=post,allow_redirects=True)

# Grab the tokens neeeded for the next login step.
post = extract_tokens(response.text)
post.update({"email": config['USERNAME'],"password": config['PASSWORD']})

# Login (2)
response = session.post(IDENTITY_URL + "/signin-service/v1/" + CLIENT_ID + "/login/authenticate",data=post,allow_redirects=False)

# Grab the userId.
userId = parse_qs(urlparse(response.headers.get('Location')).query)["userId"][0]

# Grab the JWT token from location header containing seat://
jwt_token = request_jwt_token(response.headers.get('Location'))

print("\nGet vehicles")
response = ola_request("/v2/users/" + userId +"/garage/vehicles")

vehicle = json.loads(response.text)['vehicles'][0]

if len(sys.argv) == 2 and sys.argv[1]=="get":
    
    print(vehicle)
    print("\nGet vehicle capabilities")
    print(json.loads(ola_request("/v1/user/" + userId + "/vehicle/" + vehicle['vin'] + "/capabilities").text))

    print("\nGet vehicle mycar")
    print(json.loads(ola_request("/v5/users/" + userId + "/vehicles/" + vehicle['vin'] + "/mycar").text))

    print("\nGet vehicle status")
    print(json.loads(ola_request("/v2/vehicles/" + vehicle['vin'] + "/status").text))

    print("\nGet vehicle connection")
    print(json.loads(ola_request("/vehicles/" + vehicle['vin'] + "/connection").text))

    print("\nGet vehicle renders") 
    print(json.loads(ola_request("/v1/vehicles/" + vehicle['vin'] + "/renders").text))

    print("\nGet vehicle parkingposition") 
    print(json.loads(ola_request("/v1/vehicles/" + vehicle['vin'] + "/parkingposition").text))

    print("\nGet vehicle mileage") 
    print(json.loads(ola_request("/v1/vehicles/" + vehicle['vin'] + "/mileage").text))

    print("\nGet vehicle measurements/engines") 
    print(json.loads(ola_request("/v1/vehicles/" + vehicle['vin'] + "/measurements/engines").text))

    print("\nGet vehicle warninglights") 
    print(json.loads(ola_request("/v3/vehicles/" + vehicle['vin'] + "/warninglights").text))

    print("\nGet vehicle charging/info") 
    print(json.loads(ola_request("/v1/vehicles/" + vehicle['vin'] + "/charging/info").text))

    print("\nGet vehicle climatisation/status") 
    print(json.loads(ola_request("/v1/vehicles/" + vehicle['vin'] + "/climatisation/status").text))

    print("\nGet vehicle climatisation/settings") 
    print(json.loads(ola_request("/v2/vehicles/" + vehicle['vin'] + "/climatisation/settings").text))

    print("\nGet vehicle charging/modes") 
    print(json.loads(ola_request("/v1/vehicles/" + vehicle['vin'] + "/charging/modes").text))

    print("\nGet vehicle departure-timers")
    print(json.loads(ola_request("/v1/vehicles/" + vehicle['vin'] + "/departure-timers").text))
    
if len(sys.argv) == 4 and sys.argv[1] == "set":
    setKey = sys.argv[2]
    setValue = int(sys.argv[3])

    if setKey == "minSocPercentage":
        response = session.post(OLA_URL + "/v1/vehicles/" + vehicle['vin'] + "/departure-timers/settings", json={setKey:setValue} , headers={'Authorization': 'Bearer ' + jwt_token})
        if response.status_code == 201:
            print(setKey + " successfully set to " + str(setValue))

if len(sys.argv) == 3 and sys.argv[1] == "call":
    if sys.argv[2] == "wakeup-request":
        response = session.post(OLA_URL + "/v1/vehicles/" + vehicle['vin'] + "/vehicle-wakeup/request", headers={'Authorization': 'Bearer ' + jwt_token})
        if response.status_code == 201:
            print("successfully called wakeup-request")
