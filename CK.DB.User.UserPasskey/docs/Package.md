Stores the passkeys (WebAuthn) of the users verified by the authentication center: the `CK.tUserPasskeyHandle` and
`CK.tUserPasskey` tables, the `IPasskeyStore` and the "Passkey" login provider.

`UserPasskeyStore` is the `IPasskeyStore` and `UserPasskeyLoginProvider` the login provider; the `Package` handles the
passkey management commands of CK.IO.User.UserPasskey.
