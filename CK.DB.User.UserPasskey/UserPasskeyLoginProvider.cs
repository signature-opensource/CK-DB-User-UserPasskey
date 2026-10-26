using CK.Core;
using CK.DB.Auth;
using CK.SqlServer;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace CK.DB.User.UserPasskey;

/// <summary>
/// The "Passkey" <see cref="ILoginProvider"/>: its payload is the <see cref="PasskeyLoginPayload"/> that the
/// authentication center builds after the verification of the assertion. It logs in the user of the credential and,
/// on an actual login, records the signature counter, the backup state and the last use.
/// </summary>
public sealed class UserPasskeyLoginProvider : ILoginProvider
{
    readonly UserPasskeyTable _table;
    readonly IAuthenticationDatabaseService _db;

    /// <summary>
    /// Initializes a new <see cref="UserPasskeyLoginProvider"/>.
    /// </summary>
    /// <param name="table">The passkey table.</param>
    /// <param name="db">The authentication database service.</param>
    public UserPasskeyLoginProvider( UserPasskeyTable table, IAuthenticationDatabaseService db )
    {
        _table = table;
        _db = db;
    }

    /// <inheritdoc />
    public IReadOnlyCollection<string> ProviderNames => [PasskeyLoginPayload.Scheme];

    /// <summary>
    /// Throws: the <see cref="PasskeyLoginPayload"/> is built by the authentication center from a verified assertion,
    /// never created empty and filled from the claims of a remote authentication.
    /// </summary>
    /// <param name="scheme">The scheme.</param>
    /// <returns>Never.</returns>
    public object CreatePayload( string scheme ) => throw new ArgumentException( $"The payload of the '{PasskeyLoginPayload.Scheme}' provider is built by the authentication center: it cannot be created.", nameof( scheme ) );

    /// <inheritdoc />
    public async ValueTask<ActorLoginResult> LoginAsync( IActivityMonitor monitor, string scheme, object payload, bool actualLogin = true )
    {
        if( payload is not PasskeyLoginPayload p )
        {
            throw new ArgumentException( $"The payload of the '{PasskeyLoginPayload.Scheme}' provider must be a PasskeyLoginPayload, not a '{payload?.GetType().Name}'.", nameof( payload ) );
        }
        using var ctx = new SqlStandardCallContext( monitor );
        var r = await _table.LoginAsync( ctx, p.CredentialId, p.SignCount, p.BackupState, actualLogin ).ConfigureAwait( false );
        return await _db.ToUserLoginResultAsync( ctx, r ).ConfigureAwait( false );
    }
}
