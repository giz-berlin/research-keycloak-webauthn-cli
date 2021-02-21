"""This is a proof of concept showing how to perform WebAuthn with Keycloak on the command line.
It performs the various steps of the OIDC Authorization Code Flow with Keycloak and
parses the responses to receive the WebAuthn information.
It will print out the received access token.
"""

import requests
import uuid
import re
import base64
import sys

from urllib.parse import urlparse, parse_qs

from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, WindowsClient
from fido2.webauthn import PublicKeyCredentialRequestOptions, PublicKeyCredentialDescriptor, PublicKeyCredentialType

# Adjust these settings to fit your setup 
username = 'test'
password = 'test'
baseurl = 'http://localhost:8080'
realm = 'giz'
client_id = 'admin-cli'

redirect_uri = f'{baseurl}/auth/realms/{realm}/account/'
token_endpoint = f'{baseurl}/auth/realms/{realm}/protocol/openid-connect/token'

# Session to store Keycloaks session cookies
session = requests.Session()


def b64encode(data):
    """Encodes data in base64 format.
    Custom base64 function that is similar to Keycloaks base64url.js stringify function.
    Used to conform with Keycloaks expected format, as Pythons base64 module seems
    to produce unexpected output.

    See https://github.com/keycloak/keycloak/blob/master/themes/src/main/resources/theme/base/login/resources/js/base64url.js
    """

    chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
    enc_bits = 6
    mask = (1 << enc_bits) - 1
    out = ''

    bits = 0 # Number of bits currently in the buffer
    buffer = 0 # Bits waiting to be written out, MSB first
    for i in range(len(data)):
        # Slurp data into the buffer:
        buffer = (buffer << 8) | (0xff & data[i]);
        bits += 8;

        # Write out as much as we can:
        while bits > enc_bits:
            bits -= enc_bits
            out += chars[mask & (buffer >> bits)]

    # Partial character:
    if bits:
        out += chars[mask & (buffer << (enc_bits - bits))];

    return out


def search(regex, string, error_string):
    """Wrapper for re.search to throw proper error."""

    res = re.search(regex, string)
    if res is None:
        print(f'ERROR: Couldn\'t find {error_string}')
        print(string)
        sys.exit(1)
    return res.group()


def get_authenticate_url():
    """Starts the authentication flow and receives the URL to go next.

    :return Authentication URL to post the username/password to
    """

    nonce = uuid.uuid4()
    state = uuid.uuid4()

    url = f'{baseurl}/auth/realms/{realm}/protocol/openid-connect/auth?client_id={client_id}&state={state}&response_type=code&scope=openid&nonce={nonce}&redirect_uri={redirect_uri}'

    payload = {}
    headers = {}

    response = session.get(url, headers=headers, data = payload)
    authenticate_url = search(r'action="([^\s]+)"',response.text, 'authenticate_url')
    authenticate_url = authenticate_url.split('"')[1].replace('amp;','')
    return authenticate_url


def get_webauthn_sign(auth_url, username, password):
    """Sends the username/password and gets the WebAuthn challenge information

    :param auth_url URL to post the username/password to
    :param username The users username
    :param password The users password

    :return WebAuthn Public Key, URL to post the signed webauthn information, allowed WebAuthn credential
    """

    headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
    }

    payload = f'username={username}&password={password}'
    response = session.get(auth_url, headers=headers, data = payload)

    challenge = search(r'let challenge = "([^\s]+)"', response.text, 'challenge').split('"')[1]
    challenge = base64.urlsafe_b64decode(challenge + '===')

    rpId = search(r'let rpId = "([^\s]+)"',response.text, 'rpId').split('"')[1]

    webauthn_url = search(r'action="([^\s]+)"', response.text, 'webauthn_url')
    webauthn_url = webauthn_url.split('"')[1].replace('amp;','')

    authn_select = search(r'name="authn_use_chk" value="[^\s]+"', response.text, 'authn_select').split('"')[3]

    return {'rpId': rpId, 'challenge': challenge}, webauthn_url, authn_select


def sign_request(public_key, authn_select):
    """Signs a WebAuthn challenge and returns the data.

    :param public_key dict containing `rpId` the relying party and `challenge` the received challenge
    :param authn_select string, that contains the allowed public key of the user

    :return dict containing clientDataJSON, authenticatorData, signature, credentialId and userHandle if available. 
    """

    use_prompt = False
    pin = None
    uv = "discouraged"

    if WindowsClient.is_available() and not ctypes.windll.shell32.IsUserAnAdmin():
        # Use the Windows WebAuthn API if available, and we're not running as admin
        client = WindowsClient("https://example.com")
    else:
        dev = next(CtapHidDevice.list_devices(), None)
        if dev is not None:
            print("Use USB HID channel.")
            use_prompt = True
        else:
            try:
                from fido2.pcsc import CtapPcscDevice

                dev = next(CtapPcscDevice.list_devices(), None)
                print("Use NFC channel.")
            except Exception as e:
                print("NFC channel search error:", e)

        if not dev:
            print("No FIDO device found")
            sys.exit(1)

        client = Fido2Client(dev, "http://localhost:8080", verify=lambda x,y: True)

        # Prefer UV if supported
        if client.info.options.get("uv"):
            uv = "preferred"
            print("Authenticator supports User Verification")
        elif client.info.options.get("clientPin"):
            # Prompt for PIN if needed
            pin = getpass("Please enter PIN: ")
        else:
            print("PIN not set, won't use")

    # the base64 library does not work when padding is missing, so append some
    allowed_key = base64.urlsafe_b64decode(authn_select + '===')

    pubKey = PublicKeyCredentialRequestOptions(
        public_key['challenge'],
        rp_id=public_key['rpId'],
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                PublicKeyCredentialType.PUBLIC_KEY,
                allowed_key
            )
        ]
    )


    # Authenticate the credential
    if use_prompt:
        print("\nTouch your authenticator device now...\n")

    # Only one cred in allowCredentials, only one response.
    result = client.get_assertion(pubKey, pin=pin).get_response(0)

    data = {
        "clientDataJSON": b64encode(result.client_data),
        "authenticatorData": b64encode(result.authenticator_data),
        "signature": b64encode(result.signature),
        "credentialId": b64encode(result.credential_id),
    }

    if result.user_handle:
        data['userHandle'] = b64encode(result.user_handle)

    return data


def complete_webauthn(webauth_url, data):
    """Sends the WebAuthn data to the specified Keycloak endpoint and performs the code exchange.
    
    :param webauth_url String containing the URL to send the WebAuthn data to
    :param data dict containing the WebAuthn data

    :return String containing an access token for the user
    """

    headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
    }

    response = session.post(webauth_url, headers=headers, data=data, allow_redirects=False)
    
    location = urlparse(response.headers['Location'])
    code = parse_qs(location.query)['code'][0]

    data = {
        'grant_type': 'authorization_code',
        'client_id': client_id,
        'code': code,
        'redirect_uri': redirect_uri
    }

    response = requests.post(token_endpoint, headers=headers, data=data)

    access_token = response.json()['access_token']
    
    print('ACCESS TOKEN:', access_token)


def main():
    auth_url = get_authenticate_url()
    public_key, webauth_url, authn_select = get_webauthn_sign(auth_url, username, password)
    data = sign_request(public_key, authn_select)
    access_token = complete_webauthn(webauth_url, data)


if __name__ == '__main__':
    main()
