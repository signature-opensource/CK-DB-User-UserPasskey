using CK.Core;

namespace CK.DB.User.UserPasskey;

/// <summary>
/// Package that adds the passkeys (WebAuthn) of the users: the storage of the passkeys verified by the authentication
/// center (<see cref="UserPasskeyStore"/>), the "Passkey" login provider (<see cref="UserPasskeyLoginProvider"/>)
/// and the management commands of CK.IO.User.UserPasskey.
/// </summary>
[SqlPackage( Schema = "CK", ResourcePath = "Res" )]
[Versions( "1.0.0" )]
[SqlObjectItem( "transform:vUserAuthProvider" )]
public partial class Package : SqlPackage
{
    void StObjConstruct( Actor.Package actorPackage, Auth.Package auth )
    {
    }
}
