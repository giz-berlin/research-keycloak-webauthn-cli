# Keycloak WebAuthn CLI

This is a proof of concept showing how to perform WebAuthn with Keycloak on the command line. We put some useful sites that helped with the POC in the [Resources](#resources) section.


## Requirements

This POC requires `python3`.

To interact with the Fido2 key, we use the `python-fido2` library made by Yubico. Install it using:

```bash
pip install fido2
```

If you want to test NFC authenticators, install `fido2[pcsc]` instead using:

```bash
pip install fido2[pcsc]
```

Under Linux you will need to add a Udev rule to access the FIDO device. You can also run the program as `root`. See the [installation guide](https://github.com/Yubico/python-fido2#installation) of the `python-fido2` library for more information.

On the Keycloak side, make sure you have a public client. The `admin-cli` is a good starting point.

## Usage

Make sure you adjusted the settings at the top of the source code according to your setup.

Then simply run:

```bash
python keycloak-webauthn-cli.py
```

This will result in the following output, if configured correctly.

```
Use USB HID channel.
PIN not set, won't use

Touch your authenticator device now...

ACCESS TOKEN: <access token here>
```

## Explanation

This section describes the steps we took to make the POC. 

### WebAuthn

The WebAuthn protocol is simple. The [WebAuthn Guide](https://webauthn.guide/) explains the concepts very well and visually appealing. Basically the following is happening.

1. A user logs in with his credentials and has a security key configured.
2. The server sends a challenge, that has to be signed by the security key.
3. The client signs the challenge and sends the signature back to the server.
4. The server verifies the data using the public key stored as the user registered its key.

### Interacting with Keycloak

The first step we have to do is logging in the user. To do so, we generate a nonce and a state and request the following URL, that provides the login form.

```
{baseurl}/auth/realms/{realm}/protocol/openid-connect/auth?client_id={client_id}&state={state}&response_type=code&scope=openid&nonce={nonce}&redirect_uri={redirect_uri}
```

The response provides us with the URL, where we have to POST the users credentials to.

After logging in, the server returns the rendered [`webauthn-authenticate.ftl`](https://github.com/keycloak/keycloak/blob/master/themes/src/main/resources/theme/base/login/webauthn-authenticate.ftl)] template.

It contains the following form that will be sent to the server, once the user has activated his secuity key.

```xml
<form id="webauth" class="form-horizontal" action="http://localhost:8080/auth/realms/giz/login-actions/authenticate?session_code=SESSION_CODE&amp;execution=EXECUTION_ID&amp;client_id=CLIENT_ID&amp;tab_id=TAB_ID" method="post">
    <div class="form-group">
        <input type="hidden" id="clientDataJSON" name="clientDataJSON"/>
        <input type="hidden" id="authenticatorData" name="authenticatorData"/>
        <input type="hidden" id="signature" name="signature"/>
        <input type="hidden" id="credentialId" name="credentialId"/>
        <input type="hidden" id="userHandle" name="userHandle"/>
        <input type="hidden" id="error" name="error"/>
    </div>
</form>

<form id="authn_select" class="form-horizontal">
    <input type="hidden" name="authn_use_chk" value="security keys public key"/>
</form>
```

The JavaScript code on that page contains the following, which provides us with all information needed, to complete the WebAuthn flow on the client.

```javascript
let challenge = "P5zf-bapR0G16XRJCDXOeg";
let userVerification = "not specified";
let rpId = "localhost";
let publicKey = {
    rpId : rpId,
    challenge: base64url.decode(challenge, { loose: true })
};

if (allowCredentials.length) {
    publicKey.allowCredentials = allowCredentials;
}

if (userVerification !== 'not specified')
	publicKey.userVerification = userVerification;
```

We then parse this information and use the `fido2` library to get the assertion from the security key.

Finally we send the information to the URL specified in the form action in the snippet above. Apparently Keycloak uses a [base64url.js](https://github.com/keycloak/keycloak/blob/master/themes/src/main/resources/theme/base/login/resources/js/base64url.js) library to encode and decode the data in base64 format. The Python `base64` library seems to not create the expected format, so we reimplemented the `stringify` function in Python. We use this to encode the assertion data and send the information to the server.

Finally we get the authorization code in the `Location` header. We can exchange this code for an access token as described in [this article](https://www.appsdeveloperblog.com/keycloak-authorization-code-grant-example/).

That completes the POC, showing how to perform the WebAuthn flow with Keycloak on the command line. We can use this to log in users, e.g. on their workstations without having to open a browser.

## Resources

- [WebAuthn Wikipedia](https://en.wikipedia.org/wiki/WebAuthn)
- [WebAuthn Guide](https://webauthn.guide/)
- [python-fido2](https://github.com/Yubico/python-fido2)
- [Keycloak `webauthn-authenticate.ftl`](https://github.com/keycloak/keycloak/blob/master/themes/src/main/resources/theme/base/login/webauthn-authenticate.ftl)
- [Keycloak: Authorization Code Grant Example](https://www.appsdeveloperblog.com/keycloak-authorization-code-grant-example/)
- [WebAPI CredentialsContainer.get()](https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get)
- [WebAPI PublicKeyCredential](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential)
