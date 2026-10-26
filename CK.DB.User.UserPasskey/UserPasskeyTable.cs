using CK.Core;
using CK.DB.Auth;
using CK.IO.User.UserPasskey;
using CK.SqlServer;
using Microsoft.Data.SqlClient;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace CK.DB.User.UserPasskey;

/// <summary>
/// Holds the passkeys of the users. The authentication center verifies the WebAuthn ceremonies: this table stores what
/// they need (the public key, the signature counter, the backup flags) and is the "Passkey" provider of CK.DB.Auth
/// (it feeds CK.vUserAuthProvider).
/// </summary>
[SqlTable( "tUserPasskey", Package = typeof( Package ) )]
[Versions( "1.0.0" )]
[SqlObjectItem( "transform:sUserDestroy" )]
public abstract partial class UserPasskeyTable : SqlTable
{
    const string _credentialColumns = "p.CredentialId, p.UserId, h.UserHandle, p.PublicKey, p.SignCount, p.BackupEligible, p.BackupState, p.Aaguid, p.Transports, p.Name from CK.tUserPasskey p inner join CK.tUserPasskeyHandle h on h.UserId = p.UserId";

    void StObjConstruct( UserPasskeyHandleTable handleTable )
    {
    }

    /// <summary>
    /// Finds a passkey by its credential identifier.
    /// </summary>
    /// <param name="ctx">The call context to use.</param>
    /// <param name="credentialId">The credential identifier.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>The passkey or null if it doesn't exist.</returns>
    public async Task<PasskeyCredential?> FindAsync( ISqlCallContext ctx, ReadOnlyMemory<byte> credentialId, CancellationToken cancellationToken = default )
    {
        var cmd = new SqlCommand( "select " + _credentialColumns + " where p.CredentialId = @CredentialId" );
        cmd.Parameters.Add( "@CredentialId", System.Data.SqlDbType.VarBinary, PasskeyCredential.MaxCredentialIdLength ).Value = credentialId.ToArray();
        var all = await ReadCredentialsAsync( ctx, cmd, cancellationToken ).ConfigureAwait( false );
        return all.Count == 0 ? null : all[0];
    }

    /// <summary>
    /// Gets the passkeys of a user.
    /// </summary>
    /// <param name="ctx">The call context to use.</param>
    /// <param name="userId">The user identifier.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>The passkeys of the user (possibly empty).</returns>
    public Task<IReadOnlyList<PasskeyCredential>> GetCredentialsAsync( ISqlCallContext ctx, int userId, CancellationToken cancellationToken = default )
    {
        var cmd = new SqlCommand( "select " + _credentialColumns + " where p.UserId = @UserId order by p.PasskeyId" );
        cmd.Parameters.AddWithValue( "@UserId", userId );
        return ReadCredentialsAsync( ctx, cmd, cancellationToken );
    }

    async Task<IReadOnlyList<PasskeyCredential>> ReadCredentialsAsync( ISqlCallContext ctx, SqlCommand cmd, CancellationToken cancellationToken )
    {
        static async Task<IReadOnlyList<PasskeyCredential>> ReadAsync( SqlCommand c, CancellationToken t )
        {
            var result = new List<PasskeyCredential>();
            using( var r = await c.ExecuteReaderAsync( t ).ConfigureAwait( false ) )
            {
                while( await r.ReadAsync( t ).ConfigureAwait( false ) )
                {
                    result.Add( new PasskeyCredential( credentialId: r.GetFieldValue<byte[]>( 0 ),
                                                       actorId: r.GetInt32( 1 ),
                                                       userHandle: r.GetFieldValue<byte[]>( 2 ),
                                                       publicKey: r.GetFieldValue<byte[]>( 3 ),
                                                       signCount: (uint)r.GetInt64( 4 ),
                                                       backupEligible: r.GetBoolean( 5 ),
                                                       backupState: r.GetBoolean( 6 ),
                                                       aaguid: r.GetGuid( 7 ),
                                                       transports: SplitTransports( r.GetString( 8 ) ),
                                                       name: r.GetString( 9 ) ) );
                }
            }
            return result;
        }
        using( cmd )
        {
            return await ctx[Database].ExecuteQueryAsync( cmd, ReadAsync, cancellationToken ).ConfigureAwait( false );
        }
    }

    static string[] SplitTransports( string transports ) => transports.Split( ',', StringSplitOptions.RemoveEmptyEntries );

    /// <summary>
    /// Reads the passkeys of a user, as listed by <see cref="IGetPasskeysQCommand"/>.
    /// </summary>
    /// <param name="ctx">The call context to use.</param>
    /// <param name="pocoDirectory">The poco directory.</param>
    /// <param name="userId">The user identifier.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>The passkeys of the user (possibly empty).</returns>
    public async Task<List<IUserPasskey>> ReadUserPasskeysAsync( ISqlCallContext ctx, PocoDirectory pocoDirectory, int userId, CancellationToken cancellationToken = default )
    {
        using var cmd = new SqlCommand( "select PasskeyId, Name, Aaguid, BackupEligible, BackupState, CreationDate, LastUsedTime from CK.tUserPasskey where UserId = @UserId order by PasskeyId" );
        cmd.Parameters.AddWithValue( "@UserId", userId );
        return await ctx[Database].ExecuteQueryAsync( cmd, async ( c, t ) =>
        {
            var result = new List<IUserPasskey>();
            using( var r = await c.ExecuteReaderAsync( t ).ConfigureAwait( false ) )
            {
                while( await r.ReadAsync( t ).ConfigureAwait( false ) )
                {
                    result.Add( pocoDirectory.Create<IUserPasskey>( p =>
                    {
                        p.PasskeyId = r.GetInt32( 0 );
                        p.Name = r.GetString( 1 );
                        p.Aaguid = r.GetGuid( 2 );
                        p.BackupEligible = r.GetBoolean( 3 );
                        p.BackupState = r.GetBoolean( 4 );
                        p.CreationDate = DateTime.SpecifyKind( r.GetDateTime( 5 ), DateTimeKind.Utc );
                        p.LastUsedTime = DateTime.SpecifyKind( r.GetDateTime( 6 ), DateTimeKind.Utc );
                    } ) );
                }
            }
            return result;
        }, cancellationToken ).ConfigureAwait( false );
    }

    /// <summary>
    /// Stores a new passkey. Its <see cref="PasskeyCredential.UserHandle"/> must be the user's one (see
    /// <see cref="UserPasskeyHandleTable.GetOrCreateUserHandleAsync"/>), otherwise an exception is thrown.
    /// </summary>
    /// <param name="ctx">The call context to use.</param>
    /// <param name="actorId">The acting actor identifier.</param>
    /// <param name="credential">The new passkey.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>The new passkey identifier or 0 if the credential identifier already exists (for any user).</returns>
    public Task<int> CreatePasskeyAsync( ISqlCallContext ctx, int actorId, PasskeyCredential credential, CancellationToken cancellationToken = default )
    {
        Throw.CheckNotNullArgument( credential );
        var transports = string.Join( ',', credential.Transports );
        Throw.CheckArgument( "The transports must not exceed 64 characters.", transports.Length <= 64 );
        return CreatePasskeyAsync( ctx,
                                   actorId,
                                   credential.ActorId,
                                   credential.UserHandle.ToArray(),
                                   credential.CredentialId.ToArray(),
                                   credential.PublicKey.ToArray(),
                                   credential.SignCount,
                                   credential.BackupEligible,
                                   credential.BackupState,
                                   credential.Aaguid,
                                   transports,
                                   credential.Name,
                                   cancellationToken );
    }

    [SqlProcedure( "sUserPasskeyCreate" )]
    protected abstract Task<int> CreatePasskeyAsync( ISqlCallContext ctx,
                                                     int actorId,
                                                     int userId,
                                                     byte[] userHandle,
                                                     byte[] credentialId,
                                                     byte[] publicKey,
                                                     long signCount,
                                                     bool backupEligible,
                                                     bool backupState,
                                                     Guid aaguid,
                                                     string transports,
                                                     string name,
                                                     CancellationToken cancellationToken );

    /// <summary>
    /// Logs in with a passkey whose assertion has been verified by the authentication center. On an actual login, the
    /// signature counter, the backup state and the last use are updated.
    /// </summary>
    /// <param name="ctx">The call context to use.</param>
    /// <param name="credentialId">The verified credential identifier.</param>
    /// <param name="signCount">The signature counter of the verified assertion.</param>
    /// <param name="backupState">The backup state of the verified assertion.</param>
    /// <param name="actualLogin">False to only check the login: nothing is updated.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>The login result.</returns>
    public async Task<LoginResult> LoginAsync( ISqlCallContext ctx,
                                               ReadOnlyMemory<byte> credentialId,
                                               uint signCount,
                                               bool backupState,
                                               bool actualLogin = true,
                                               CancellationToken cancellationToken = default )
    {
        var r = await PasskeyLoginAsync( ctx, credentialId.ToArray(), signCount, backupState, actualLogin, cancellationToken ).ConfigureAwait( false );
        return r.LoginResult;
    }

    [SqlProcedure( "sUserPasskeyLogin" )]
    protected abstract Task<UCLResult> PasskeyLoginAsync( ISqlCallContext ctx, byte[] credentialId, long signCount, bool backupState, bool actualLogin, CancellationToken cancellationToken );

    /// <summary>
    /// Renames a passkey of the acting user.
    /// </summary>
    /// <param name="ctx">The call context to use.</param>
    /// <param name="actorId">The acting user, that must own the passkey.</param>
    /// <param name="passkeyId">The passkey identifier.</param>
    /// <param name="name">The new name. Must not be empty.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>False if the passkey doesn't exist or is not the actor's one.</returns>
    [SqlProcedure( "sUserPasskeyRename" )]
    public abstract Task<bool> RenamePasskeyAsync( ISqlCallContext ctx, int actorId, int passkeyId, string name, CancellationToken cancellationToken = default );

    /// <summary>
    /// Deletes a passkey of a user. When the actor is the user, the "last login method" rule applies (see
    /// <see cref="PasskeyDeleteResult.LastLoginMethod"/>). Otherwise the actor must be an administrator (a member of
    /// the System group by default): a "Security.AdminOnly" error is thrown if it is not.
    /// </summary>
    /// <param name="ctx">The call context to use.</param>
    /// <param name="actorId">The acting actor identifier.</param>
    /// <param name="userId">The user that owns the passkey.</param>
    /// <param name="passkeyId">The passkey identifier.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>The result.</returns>
    public async Task<PasskeyDeleteResult> DeletePasskeyAsync( ISqlCallContext ctx, int actorId, int userId, int passkeyId, CancellationToken cancellationToken = default )
    {
        return (PasskeyDeleteResult)await DoDeletePasskeyAsync( ctx, actorId, userId, passkeyId, cancellationToken ).ConfigureAwait( false );
    }

    [SqlProcedure( "sUserPasskeyDelete" )]
    protected abstract Task<int> DoDeletePasskeyAsync( ISqlCallContext ctx, int actorId, int userId, int passkeyId, CancellationToken cancellationToken );

    /// <summary>
    /// Destroys all the passkeys of a user and its user handle. This is called when the user is destroyed.
    /// </summary>
    /// <param name="ctx">The call context to use.</param>
    /// <param name="actorId">The acting actor identifier.</param>
    /// <param name="userId">The user identifier.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>The awaitable.</returns>
    [SqlProcedure( "sUserPasskeyDestroy" )]
    public abstract Task DestroyUserPasskeysAsync( ISqlCallContext ctx, int actorId, int userId, CancellationToken cancellationToken = default );
}
