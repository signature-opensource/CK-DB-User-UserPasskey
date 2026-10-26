using CK.Core;
using CK.Cris;

namespace CK.IO.User.UserPasskey;

/// <summary>
/// Validates the passkey management commands when they enter the System.
/// </summary>
public class IncomingValidators : IRealObject
{
    /// <summary>
    /// The maximal length of a passkey name (the AuthCenter's limit at registration).
    /// </summary>
    public const int MaxNameLength = 128;

    /// <summary>
    /// Checks the passkey identifier and the new name.
    /// </summary>
    /// <param name="collector">The message collector.</param>
    /// <param name="command">The command.</param>
    [IncomingValidator]
    public virtual void ValidateRenamePasskeyCommand( UserMessageCollector collector, IRenamePasskeyCommand command )
    {
        CheckPasskeyId( collector, command.PasskeyId );
        if( string.IsNullOrWhiteSpace( command.Name ) || command.Name.Length > MaxNameLength )
        {
            collector.Error( $"The passkey name must not be blank and must have at most {MaxNameLength} characters.", "Passkey.InvalidName" );
        }
    }

    /// <summary>
    /// Checks the passkey identifier and refuses the command while impersonating: a user's login methods are
    /// removed by the user, or by an administrator with <see cref="IDeleteUserPasskeyCommand"/>.
    /// </summary>
    /// <param name="collector">The message collector.</param>
    /// <param name="command">The command.</param>
    [IncomingValidator]
    public virtual void ValidateDeletePasskeyCommand( UserMessageCollector collector, IDeletePasskeyCommand command )
    {
        CheckPasskeyId( collector, command.PasskeyId );
        if( command.ActorId != command.ActualActorId )
        {
            collector.Error( "This is refused while impersonating.", "Authentication.Impersonated" );
        }
    }

    /// <summary>
    /// Checks the user and passkey identifiers.
    /// </summary>
    /// <param name="collector">The message collector.</param>
    /// <param name="command">The command.</param>
    [IncomingValidator]
    public virtual void ValidateDeleteUserPasskeyCommand( UserMessageCollector collector, IDeleteUserPasskeyCommand command )
    {
        if( command.UserId <= 0 )
        {
            collector.Error( "Invalid UserId.", "User.InvalidUserId" );
        }
        CheckPasskeyId( collector, command.PasskeyId );
    }

    static void CheckPasskeyId( UserMessageCollector collector, int passkeyId )
    {
        if( passkeyId <= 0 )
        {
            collector.Error( "Invalid PasskeyId.", "Passkey.InvalidPasskeyId" );
        }
    }
}
