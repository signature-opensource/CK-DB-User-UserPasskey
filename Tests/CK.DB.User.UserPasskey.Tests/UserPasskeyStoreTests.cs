using CK.Core;
using CK.DB.Actor;
using CK.SqlServer;
using CK.Testing;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using static CK.DB.User.UserPasskey.Tests.PasskeyTestHelper;
using static CK.Testing.MonitorTestHelper;

namespace CK.DB.User.UserPasskey.Tests;

[TestFixture]
public class UserPasskeyStoreTests
{
    [Test]
    public async Task the_user_handle_is_random_created_once_and_specific_to_the_user_Async()
    {
        var u1 = await CreateUserAsync();
        var u2 = await CreateUserAsync();
        var h1 = await Store.GetOrCreateUserHandleAsync( TestHelper.Monitor, u1 );
        h1.Length.ShouldBe( 32 );
        (await Store.GetOrCreateUserHandleAsync( TestHelper.Monitor, u1 )).ToArray().ShouldBe( h1.ToArray() );
        var h2 = await Store.GetOrCreateUserHandleAsync( TestHelper.Monitor, u2 );
        h2.ToArray().ShouldNotBe( h1.ToArray() );
        BitConverter.GetBytes( u1 ).ShouldNotBe( h1.Slice( 0, 4 ).ToArray(), "Never derived from the user identifier." );
    }

    [Test]
    public async Task a_passkey_is_stored_and_read_back_Async()
    {
        var userId = await CreateUserAsync();
        (await Store.GetCredentialsAsync( TestHelper.Monitor, userId )).ShouldBeEmpty();
        (await HasSchemeAsync( userId, "Passkey" )).ShouldBeFalse( "The handle alone doesn't make a scheme." );

        var c = await RegisterAsync( userId, signCount: 3 );

        var found = await Store.FindAsync( TestHelper.Monitor, c.CredentialId );
        found.ShouldNotBeNull();
        found.CredentialId.ToArray().ShouldBe( c.CredentialId.ToArray() );
        found.ActorId.ShouldBe( userId );
        found.UserHandle.ToArray().ShouldBe( c.UserHandle.ToArray() );
        found.PublicKey.ToArray().ShouldBe( c.PublicKey.ToArray() );
        found.SignCount.ShouldBe( 3u );
        found.BackupEligible.ShouldBeTrue();
        found.BackupState.ShouldBeFalse();
        found.Aaguid.ShouldBe( c.Aaguid );
        found.Transports.ShouldBe( ["internal", "hybrid"] );
        found.Name.ShouldBe( "My phone" );

        var c2 = await RegisterAsync( userId, "My key", backupEligible: false );
        (await Store.GetCredentialsAsync( TestHelper.Monitor, userId )).Select( p => p.Name ).ShouldBe( ["My phone", "My key"] );
        (await HasSchemeAsync( userId, "Passkey" )).ShouldBeTrue();

        (await Store.FindAsync( TestHelper.Monitor, RandomNumberGenerator.GetBytes( 16 ) )).ShouldBeNull();
        (await Store.FindAsync( TestHelper.Monitor, ReadOnlyMemory<byte>.Empty )).ShouldBeNull();
    }

    [Test]
    public async Task a_credential_identifier_is_stored_once_for_all_the_users_Async()
    {
        var u1 = await CreateUserAsync();
        var u2 = await CreateUserAsync();
        var c = await RegisterAsync( u1 );
        var h2 = await Store.GetOrCreateUserHandleAsync( TestHelper.Monitor, u2 );
        var same = new PasskeyCredential( c.CredentialId, u2, h2, c.PublicKey, 0, true, false, Guid.Empty, [], "Copy" );
        (await Store.CreateAsync( TestHelper.Monitor, same )).ShouldBeFalse();
        (await Store.FindAsync( TestHelper.Monitor, c.CredentialId ))!.ActorId.ShouldBe( u1 );
    }

    [Test]
    public async Task the_user_handle_must_be_the_user_one_Async()
    {
        var u1 = await CreateUserAsync();
        var u2 = await CreateUserAsync();
        var h1 = await Store.GetOrCreateUserHandleAsync( TestHelper.Monitor, u1 );
        await Store.GetOrCreateUserHandleAsync( TestHelper.Monitor, u2 );
        var wrong = new PasskeyCredential( RandomNumberGenerator.GetBytes( 32 ), u2, h1, RandomNumberGenerator.GetBytes( 32 ), 0, false, false, Guid.Empty, [], "Wrong" );
        await Util.Awaitable( () => Store.CreateAsync( TestHelper.Monitor, wrong ).AsTask() ).ShouldThrowAsync<SqlDetailedException>();
        (await Store.GetCredentialsAsync( TestHelper.Monitor, u2 )).ShouldBeEmpty();
    }

    [Test]
    public async Task destroying_the_user_destroys_its_passkeys_and_its_handle_Async()
    {
        var userId = await CreateUserAsync();
        var c = await RegisterAsync( userId );
        await RegisterAsync( userId );
        var users = SharedEngine.Map.StObjs.Obtain<UserTable>().ShouldNotBeNull();
        using( var ctx = new SqlStandardCallContext( TestHelper.Monitor ) )
        {
            await users.DestroyUserAsync( ctx, 1, userId );
        }
        (await Store.FindAsync( TestHelper.Monitor, c.CredentialId )).ShouldBeNull();
        Table.Database.ExecuteScalar<int>( "select count(*) from CK.tUserPasskeyHandle where UserId = @0", userId ).ShouldBe( 0 );
    }
}
