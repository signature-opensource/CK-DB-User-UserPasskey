using CK.Core;
using CK.DB.Auth;
using CK.Testing;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using static CK.DB.User.UserPasskey.Tests.PasskeyTestHelper;
using static CK.Testing.MonitorTestHelper;

namespace CK.DB.User.UserPasskey.Tests;

/// <summary>
/// Tests the "Passkey" login provider (<see cref="UserPasskeyLoginProvider"/>): its payload is the
/// <see cref="PasskeyLoginPayload"/> built by the authentication center after the verification.
/// </summary>
[TestFixture]
public class PasskeyLoginProviderTests
{
    static UserPasskeyLoginProvider Provider => SharedEngine.AutomaticServices.GetRequiredService<UserPasskeyLoginProvider>();

    [Test]
    public async Task passkey_login_succeeds_and_records_the_use_Async()
    {
        Provider.ProviderNames.ShouldBe( ["Passkey"] );
        SharedEngine.AutomaticServices.GetRequiredService<SqlLoginProvider>().ProviderNames.ShouldNotContain( "Passkey", "Not a generic provider." );
        Should.Throw<ArgumentException>( () => Provider.CreatePayload( "Passkey" ) );

        var userId = await CreateUserAsync();
        var c = await RegisterAsync( userId, signCount: 10 );

        var check = await Provider.LoginAsync( TestHelper.Monitor, "Passkey", new PasskeyLoginPayload( c.CredentialId, 11, false ), actualLogin: false );
        check.IsSuccess.ShouldBeTrue();
        (await Store.FindAsync( TestHelper.Monitor, c.CredentialId ))!.SignCount.ShouldBe( 10u, "A check doesn't update." );

        var r = await Provider.LoginAsync( TestHelper.Monitor, "Passkey", new PasskeyLoginPayload( c.CredentialId, 11, true ) );
        r.IsSuccess.ShouldBeTrue();
        r.Actor!.ActorId.ShouldBe( userId );
        r.Actor.Level.ShouldBe( AuthLevel.Critical );
        r.Actor.HasScheme( "Passkey" ).ShouldBeTrue();

        var after = (await Store.FindAsync( TestHelper.Monitor, c.CredentialId ))!;
        after.SignCount.ShouldBe( 11u );
        after.BackupState.ShouldBeTrue();
        Table.Database.ExecuteScalar<DateTime>( "select LastUsedTime from CK.tUserPasskey where CredentialId = @0", c.CredentialId.ToArray() )
            .ShouldBeGreaterThan( DateTime.UtcNow.AddMinutes( -1 ) );
    }

    [Test]
    public async Task synchronized_passkeys_send_a_zero_counter_Async()
    {
        var userId = await CreateUserAsync();
        var c = await RegisterAsync( userId );
        (await Provider.LoginAsync( TestHelper.Monitor, "Passkey", new PasskeyLoginPayload( c.CredentialId, 0, true ) )).IsSuccess.ShouldBeTrue();
        (await Provider.LoginAsync( TestHelper.Monitor, "Passkey", new PasskeyLoginPayload( c.CredentialId, 0, true ) )).IsSuccess.ShouldBeTrue();
    }

    [Test]
    public async Task a_counter_regression_fails_Async()
    {
        var userId = await CreateUserAsync();
        var c = await RegisterAsync( userId, signCount: 10 );
        var same = await Provider.LoginAsync( TestHelper.Monitor, "Passkey", new PasskeyLoginPayload( c.CredentialId, 10, false ) );
        same.IsSuccess.ShouldBeFalse();
        same.FailureCode.ShouldBe( (int)KnownLoginFailureCode.InvalidCredentials );
        (await Store.FindAsync( TestHelper.Monitor, c.CredentialId ))!.SignCount.ShouldBe( 10u );
    }

    [Test]
    public async Task a_backup_state_on_a_passkey_that_cannot_be_backed_up_fails_Async()
    {
        var userId = await CreateUserAsync();
        var c = await RegisterAsync( userId, backupEligible: false );
        var r = await Provider.LoginAsync( TestHelper.Monitor, "Passkey", new PasskeyLoginPayload( c.CredentialId, 0, true ) );
        r.IsSuccess.ShouldBeFalse();
        r.FailureCode.ShouldBe( (int)KnownLoginFailureCode.InvalidCredentials );
    }

    [Test]
    public async Task an_unknown_credential_fails_Async()
    {
        var r = await Provider.LoginAsync( TestHelper.Monitor, "Passkey", new PasskeyLoginPayload( RandomNumberGenerator.GetBytes( 32 ), 0, false ) );
        r.IsSuccess.ShouldBeFalse();
        r.FailureCode.ShouldBe( (int)KnownLoginFailureCode.InvalidUserKey );

        await Util.Awaitable( () => Provider.LoginAsync( TestHelper.Monitor, "Passkey", "not a payload" ).AsTask() ).ShouldThrowAsync<ArgumentException>();
    }
}
