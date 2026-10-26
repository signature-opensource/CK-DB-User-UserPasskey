using CK.Core;
using CK.Cris;
using CK.IO.User.UserPasskey;
using CK.Testing;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static CK.DB.User.UserPasskey.Tests.PasskeyTestHelper;
using static CK.Testing.MonitorTestHelper;

namespace CK.DB.User.UserPasskey.Tests;

/// <summary>
/// The management commands: list, rename and delete the current user's passkeys, and the administrator's delete.
/// </summary>
[TestFixture]
public class PasskeyCommandTests
{
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor.
    AsyncServiceScope _scope;
    IServiceProvider _services;
    RawCrisReceiver _crisReceiver;
    PocoDirectory _pocoDir;
#pragma warning restore CS8618

    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
        _scope = SharedEngine.AutomaticServices.CreateAsyncScope();
        _services = _scope.ServiceProvider;
        _pocoDir = _services.GetRequiredService<PocoDirectory>();
        _crisReceiver = _services.GetRequiredService<RawCrisReceiver>();
    }

    [OneTimeTearDown]
    public async Task OneTimeTearDownAsync()
    {
        await _scope.DisposeAsync();
    }

    // Each command has its own scope, like in the real system (the UserMessageCollector is scoped).
    static async Task<T> ExecuteAsync<T>( IAbstractCommand cmd )
    {
        await using var scope = SharedEngine.AutomaticServices.CreateAsyncScope();
        var executor = scope.ServiceProvider.GetRequiredService<CrisExecutionContext>();
        var executed = await executor.ExecuteRootCommandAsync( cmd );
        return executed.WithResult<T>().Result;
    }

    static string Messages( ICrisBasicCommandResult r ) => string.Join( " | ", r.UserMessages.Select( m => m.Message.ToString() ) );

    Task<ICrisBasicCommandResult> DeleteOwnAsync( int userId, int passkeyId )
    {
        return ExecuteAsync<ICrisBasicCommandResult>( _pocoDir.Create<IDeletePasskeyCommand>( c =>
        {
            c.ActorId = userId;
            c.ActualActorId = userId;
            c.PasskeyId = passkeyId;
        } ) );
    }

    Task<ICrisBasicCommandResult> DeleteAsAdminAsync( int actorId, int userId, int passkeyId )
    {
        return ExecuteAsync<ICrisBasicCommandResult>( _pocoDir.Create<IDeleteUserPasskeyCommand>( c =>
        {
            c.ActorId = actorId;
            c.UserId = userId;
            c.PasskeyId = passkeyId;
        } ) );
    }

    [Test]
    public async Task the_current_user_lists_and_renames_its_passkeys_Async()
    {
        var userId = await CreateUserAsync();
        var c1 = await RegisterAsync( userId, "Phone" );
        await RegisterAsync( userId, "Key" );

        var list = await ExecuteAsync<List<IUserPasskey>>( _pocoDir.Create<IGetPasskeysQCommand>( c => c.ActorId = userId ) );
        list.Select( p => p.Name ).ShouldBe( ["Phone", "Key"] );
        list[0].PasskeyId.ShouldBe( GetPasskeyId( c1 ) );
        list[0].Aaguid.ShouldBe( c1.Aaguid );
        list[0].BackupEligible.ShouldBeTrue();
        list[0].LastUsedTime.ShouldBe( Util.UtcMinValue, "Never used." );
        list[0].CreationDate.Kind.ShouldBe( DateTimeKind.Utc );

        var rename = await ExecuteAsync<ICrisBasicCommandResult>( _pocoDir.Create<IRenamePasskeyCommand>( c =>
        {
            c.ActorId = userId;
            c.PasskeyId = list[0].PasskeyId;
            c.Name = "  Old phone ";
        } ) );
        rename.Success.ShouldBeTrue( Messages( rename ) );
        (await Store.FindAsync( TestHelper.Monitor, c1.CredentialId ))!.Name.ShouldBe( "Old phone" );

        (await ExecuteAsync<List<IUserPasskey>>( _pocoDir.Create<IGetPasskeysQCommand>( c => c.ActorId = 1 ) ))
            .ShouldNotContain( p => p.PasskeyId == list[0].PasskeyId, "Only the actor's passkeys." );
    }

    [Test]
    public async Task a_user_cannot_rename_or_delete_another_user_passkey_with_its_own_commands_Async()
    {
        var owner = await CreateUserAsync();
        var other = await CreateUserAsync();
        var c = await RegisterAsync( owner, "Phone" );
        await RegisterAsync( owner, "Key" );
        var passkeyId = GetPasskeyId( c );

        var rename = await ExecuteAsync<ICrisBasicCommandResult>( _pocoDir.Create<IRenamePasskeyCommand>( r =>
        {
            r.ActorId = other;
            r.PasskeyId = passkeyId;
            r.Name = "Mine";
        } ) );
        rename.Success.ShouldBeFalse();

        var delete = await DeleteOwnAsync( other, passkeyId );
        delete.Success.ShouldBeFalse();
        (await Store.FindAsync( TestHelper.Monitor, c.CredentialId )).ShouldNotBeNull();
        (await Store.FindAsync( TestHelper.Monitor, c.CredentialId ))!.Name.ShouldBe( "Phone" );
    }

    [Test]
    public async Task the_user_last_login_method_cannot_be_deleted_by_the_user_Async()
    {
        var userId = await CreateUserAsync();
        var c1 = await RegisterAsync( userId, "Phone" );
        var c2 = await RegisterAsync( userId, "Key" );

        var first = await DeleteOwnAsync( userId, GetPasskeyId( c1 ) );
        first.Success.ShouldBeTrue( Messages( first ) );
        (await Store.FindAsync( TestHelper.Monitor, c1.CredentialId )).ShouldBeNull();

        var last = await DeleteOwnAsync( userId, GetPasskeyId( c2 ) );
        last.Success.ShouldBeFalse();
        Messages( last ).ShouldContain( "last way to log in" );
        (await Store.FindAsync( TestHelper.Monitor, c2.CredentialId )).ShouldNotBeNull();
        (await HasSchemeAsync( userId, "Passkey" )).ShouldBeTrue();
    }

    [Test]
    public async Task an_administrator_deletes_the_last_passkey_of_a_user_Async()
    {
        var userId = await CreateUserAsync();
        var c = await RegisterAsync( userId );

        var r = await DeleteAsAdminAsync( 1, userId, GetPasskeyId( c ) );
        r.Success.ShouldBeTrue( Messages( r ) );
        (await Store.FindAsync( TestHelper.Monitor, c.CredentialId )).ShouldBeNull();
        (await HasSchemeAsync( userId, "Passkey" )).ShouldBeFalse();
    }

    [Test]
    public async Task only_an_administrator_deletes_the_passkey_of_another_user_Async()
    {
        var userId = await CreateUserAsync();
        var notAdmin = await CreateUserAsync();
        var c = await RegisterAsync( userId );
        await RegisterAsync( userId );

        var r = await DeleteAsAdminAsync( notAdmin, userId, GetPasskeyId( c ) );
        r.Success.ShouldBeFalse();
        Messages( r ).ShouldContain( "Administrator" );
        (await Store.FindAsync( TestHelper.Monitor, c.CredentialId )).ShouldNotBeNull();
    }

    [Test]
    public async Task deleting_its_own_passkey_is_refused_while_impersonating_Async()
    {
        var cmd = _pocoDir.Create<IDeletePasskeyCommand>( c =>
        {
            c.ActorId = 3712;
            c.ActualActorId = 1;
            c.PasskeyId = 1;
        } );
        var v = await _crisReceiver.IncomingValidateAsync( TestHelper.Monitor, _services, cmd );
        v.Success.ShouldBeFalse();

        cmd.ActualActorId = 3712;
        (await _crisReceiver.IncomingValidateAsync( TestHelper.Monitor, _services, cmd )).Success.ShouldBeTrue();
    }

    [Test]
    public async Task names_and_identifiers_are_validated_Async()
    {
        var blank = _pocoDir.Create<IRenamePasskeyCommand>( c => { c.ActorId = 1; c.PasskeyId = 1; c.Name = " "; } );
        (await _crisReceiver.IncomingValidateAsync( TestHelper.Monitor, _services, blank )).Success.ShouldBeFalse();

        var tooLong = _pocoDir.Create<IRenamePasskeyCommand>( c => { c.ActorId = 1; c.PasskeyId = 1; c.Name = new string( 'x', IncomingValidators.MaxNameLength + 1 ); } );
        (await _crisReceiver.IncomingValidateAsync( TestHelper.Monitor, _services, tooLong )).Success.ShouldBeFalse();

        var noUser = _pocoDir.Create<IDeleteUserPasskeyCommand>( c => { c.ActorId = 1; c.UserId = 0; c.PasskeyId = 1; } );
        (await _crisReceiver.IncomingValidateAsync( TestHelper.Monitor, _services, noUser )).Success.ShouldBeFalse();
    }
}
