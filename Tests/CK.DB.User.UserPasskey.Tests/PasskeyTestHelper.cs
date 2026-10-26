using CK.Core;
using CK.DB.Actor;
using CK.SqlServer;
using CK.Testing;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.DB.User.UserPasskey.Tests;

static class PasskeyTestHelper
{
    public static UserPasskeyStore Store => SharedEngine.AutomaticServices.GetRequiredService<UserPasskeyStore>();

    public static UserPasskeyTable Table => SharedEngine.Map.StObjs.Obtain<UserPasskeyTable>().ShouldNotBeNull();

    public static async Task<int> CreateUserAsync()
    {
        var users = SharedEngine.Map.StObjs.Obtain<UserTable>().ShouldNotBeNull();
        using var ctx = new SqlStandardCallContext( TestHelper.Monitor );
        return await users.CreateUserAsync( ctx, 1, "Passkey-" + Guid.NewGuid() );
    }

    /// <summary>
    /// Registers a new passkey for the user (the store doesn't verify the COSE key: random bytes are fine).
    /// </summary>
    public static async Task<PasskeyCredential> RegisterAsync( int userId,
                                                               string name = "My phone",
                                                               uint signCount = 0,
                                                               bool backupEligible = true )
    {
        var handle = await Store.GetOrCreateUserHandleAsync( TestHelper.Monitor, userId );
        var credential = new PasskeyCredential( RandomNumberGenerator.GetBytes( 64 ),
                                                userId,
                                                handle,
                                                RandomNumberGenerator.GetBytes( 77 ),
                                                signCount,
                                                backupEligible,
                                                backupState: false,
                                                Guid.NewGuid(),
                                                ["internal", "hybrid"],
                                                name );
        (await Store.CreateAsync( TestHelper.Monitor, credential )).ShouldBeTrue();
        return credential;
    }

    public static int GetPasskeyId( PasskeyCredential credential )
    {
        return Table.Database.ExecuteScalar<int>( "select PasskeyId from CK.tUserPasskey where CredentialId = @0", credential.CredentialId.ToArray() );
    }

    /// <summary>
    /// Reads CK.vUserAuthProvider (that the "last login method" rule uses): the user's schemes read by
    /// CK.sAuthUserInfoRead are only the ones that have been used.
    /// </summary>
    public static Task<bool> HasSchemeAsync( int userId, string scheme )
    {
        return Task.FromResult( Table.Database.ExecuteScalar<int>( "select count(*) from CK.vUserAuthProvider where UserId = @0 and Scheme = @1", userId, scheme ) > 0 );
    }
}
