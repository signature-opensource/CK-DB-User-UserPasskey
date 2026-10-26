using CK.Auth;
using CK.Cris;

namespace CK.IO.User.UserPasskey;

/// <summary>
/// Deletes a passkey of any user: the administrator's command (a lost phone). The current user's own command is
/// <see cref="IDeletePasskeyCommand"/>.
/// <para>
/// The actor must be an administrator: a member of the System group by default (the <c>PasskeySecurityCheck</c>
/// injection point of <c>CK.sUserPasskeyDelete</c> can accept others). The "last login method" rule doesn't apply to
/// an administrator, except on its own passkeys.
/// </para>
/// </summary>
public interface IDeleteUserPasskeyCommand : ICommand<ICrisBasicCommandResult>, ICommandCurrentCulture, ICommandAuthCritical
{
    /// <summary>
    /// Gets or sets the user that owns the passkey.
    /// </summary>
    int UserId { get; set; }

    /// <summary>
    /// Gets or sets the passkey identifier.
    /// </summary>
    int PasskeyId { get; set; }
}
