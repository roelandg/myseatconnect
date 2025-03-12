import requests, re,json
import numpy as np
from requests.exceptions import InvalidSchema
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup

identity_url = "https://identity.vwgroup.io"
ola_url = "https://ola.prod.code.seat.cloud.vwgroup.com"
client_id = "99a5b77d-bd88-4d53-b4e5-a539c60694a3%40apps_vw-dilab_com"
username = ""
password = ""

def ola_request(endpoint):
    return requests.get(ola_url + endpoint, headers={'Authorization': 'Bearer ' + jwt_token})
    
def extract_tokens(html):
    # Pattern handles either quoted or unquoted property names:
    re_hmac = re.compile(r'(?:["\']hmac["\']|hmac)\s*:\s*["\']([^"\']+)["\']')
    re_relayState = re.compile(r'(?:["\']relayState["\']|relayState)\s*:\s*["\']([^"\']+)["\']')
    re_csrf_token = re.compile(r'(?:["\']csrf_token["\']|csrf_token)\s*:\s*["\']([^"\']+)["\']')

    hmac_match       = re_hmac.search(html)
    relayState_match = re_relayState.search(html)
    csrf_token_match = re_csrf_token.search(html)

    hmac_value       = hmac_match.group(1)       if hmac_match else None
    relayState_value = relayState_match.group(1) if relayState_match else None
    csrf_value       = csrf_token_match.group(1) if csrf_token_match else None

    if not hmac_match:
        raise ValueError("No hmac found in the HTML content.")
    if not relayState_match:
        raise ValueError("No relayState found in the HTML content.")
    if not csrf_token_match:
        raise ValueError("No csrf_token found in the HTML content.")
    
    return {"_csrf":csrf_value, "hmac": hmac_value, "relayState": relayState_value}

session = requests.Session()
response = session.get(identity_url + "/oidc/v1/authorize?redirect_uri=seat%3A%2F%2Foauth-callback&client_id="+client_id+"&response_type=code&scope=openid%20profile%20nickname%20birthdate%20phone", allow_redirects=True)

form = BeautifulSoup(response.text, "html.parser").find("form")
if not form:
    raise RuntimeError("No form found in the response.")

inputs = {tag.get("name"): tag.get("value") for tag in form.find_all("input", {"type": "hidden"})}

required_fields = ["_csrf", "hmac", "relayState"]
for field in required_fields:
    if field not in inputs:
        raise RuntimeError(f"Expected field '{field}' not found.")

# Login (1)
response = session.post(
    identity_url + form.get("action"),
    data={
        "_csrf": inputs["_csrf"],
        "relayState": inputs["relayState"],
        "hmac": inputs["hmac"],
        "email": username,
    },
    allow_redirects=True
)

post = extract_tokens(response.text)
post.update({
    "email": username,
    "password": password,
})

# Login (2)
response = session.post(identity_url + "/signin-service/v1/" + client_id + "/login/authenticate",data=post,allow_redirects=False)

# Grab the userId.
userId = parse_qs(urlparse(response.headers.get('Location')).query)["userId"][0]
print("userId=" + userId)

# Grab the JWT token from location header containing seat://
try:
  response = session.get(response.headers.get('Location'))
except InvalidSchema as exc:

    exc_str = str(exc)
    match = re.search(r"No connection adapters were found for '(.*?)'", exc_str)
    if match:
        seat_url = match.group(1)
        parsed = urlparse(seat_url)
        code_list = parse_qs(parsed.query).get("code")
        if code_list:
            jwt_token = code_list[0]
        else:
            print("No 'code' parameter found in URL:", seat_url)
            raise SystemExit
    else:
        print("No seat:// URL found in exception message.")
        raise SystemExit

print("\nGet vehicles")
response = ola_request("/v2/users/" + userId +"/garage/vehicles")
print(response.text)

for vehicle in json.loads(response.text)['vehicles']:
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
