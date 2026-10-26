using CK.Auth;
using CK.Cris;

namespace CK.IO.User.UserPasskey;

/// <summary>
/// Deletes a passkey of the current user (the administrator's command is <see cref="IDeleteUserPasskeyCommand"/>).
/// Executed by the authentication center (<see cref="ICommandAuthCenter"/>).
/// <para>
/// Removing a login method requires the <see cref="ICommandAuthCritical">Critical</see> level (a recent login), and it
/// is refused while impersonating. The "last login method" rule applies: the user's last passkey cannot be deleted when
/// the user has no other way to log in (no other row in <c>CK.vUserAuthProvider</c>).
/// </para>
/// </summary>
public interface IDeletePasskeyCommand : ICommand<ICrisBasicCommandResult>, ICommandCurrentCulture, ICommandAuthCritical, ICommandAuthImpersonation, ICommandAuthCenter
{
    /// <summary>
    /// Gets or sets the passkey identifier. It must be one of the current user's passkeys.
    /// </summary>
    int PasskeyId { get; set; }
}
