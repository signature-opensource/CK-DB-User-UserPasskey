using CK.Core;
using CK.SqlServer;
using System.Threading.Tasks;

namespace CK.DB.User.UserPasskey;

/// <summary>
/// Holds the WebAuthn user handle of the users: random, never derived from the user identifier, the same for all the
/// passkeys of a user. See the CK.tUserPasskey script for why it is a table of its own.
/// </summary>
[SqlTable( "tUserPasskeyHandle", Package = typeof( Package ) )]
[Versions( "1.0.0" )]
public abstract partial class UserPasskeyHandleTable : SqlTable
{
    void StObjConstruct( Actor.UserTable userTable )
    {
    }

    /// <summary>
    /// Gets the user handle of a user, created on the first call (32 random bytes).
    /// </summary>
    /// <param name="ctx">The call context to use.</param>
    /// <param name="userId">The user identifier. Must be positive.</param>
    /// <returns>The user handle.</returns>
    [SqlProcedure( "sUserPasskeyHandleGetOrCreate" )]
    public abstract Task<byte[]> GetOrCreateUserHandleAsync( ISqlCallContext ctx, int userId );
}
