using CK.Core;
using CK.SqlServer;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace CK.DB.User.UserPasskey;

/// <summary>
/// The <see cref="IPasskeyStore"/> on the <see cref="UserPasskeyTable"/> and the <see cref="UserPasskeyHandleTable"/>.
/// <para>
/// This is a singleton: each call uses its own <see cref="SqlStandardCallContext"/>.
/// </para>
/// </summary>
public sealed class UserPasskeyStore : IPasskeyStore
{
    readonly UserPasskeyTable _table;
    readonly UserPasskeyHandleTable _handles;

    /// <summary>
    /// Initializes a new <see cref="UserPasskeyStore"/>.
    /// </summary>
    /// <param name="table">The passkey table.</param>
    /// <param name="handles">The user handle table.</param>
    public UserPasskeyStore( UserPasskeyTable table, UserPasskeyHandleTable handles )
    {
        _table = table;
        _handles = handles;
    }

    /// <inheritdoc />
    public async ValueTask<ReadOnlyMemory<byte>> GetOrCreateUserHandleAsync( IActivityMonitor monitor, int actorId )
    {
        Throw.CheckArgument( actorId > 0 );
        using var ctx = new SqlStandardCallContext( monitor );
        return await _handles.GetOrCreateUserHandleAsync( ctx, actorId ).ConfigureAwait( false );
    }

    /// <inheritdoc />
    public async ValueTask<PasskeyCredential?> FindAsync( IActivityMonitor monitor, ReadOnlyMemory<byte> credentialId )
    {
        if( credentialId.Length is 0 or > PasskeyCredential.MaxCredentialIdLength ) return null;
        using var ctx = new SqlStandardCallContext( monitor );
        return await _table.FindAsync( ctx, credentialId ).ConfigureAwait( false );
    }

    /// <inheritdoc />
    public async ValueTask<IReadOnlyList<PasskeyCredential>> GetCredentialsAsync( IActivityMonitor monitor, int actorId )
    {
        using var ctx = new SqlStandardCallContext( monitor );
        return await _table.GetCredentialsAsync( ctx, actorId ).ConfigureAwait( false );
    }

    /// <inheritdoc />
    public async ValueTask<bool> CreateAsync( IActivityMonitor monitor, PasskeyCredential credential )
    {
        Throw.CheckNotNullArgument( credential );
        using var ctx = new SqlStandardCallContext( monitor );
        // The actor registers its own passkey (the authentication center has checked its Critical session).
        return await _table.CreatePasskeyAsync( ctx, credential.ActorId, credential ).ConfigureAwait( false ) > 0;
    }
}
