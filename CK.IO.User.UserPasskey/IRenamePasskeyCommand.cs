using CK.Auth;
using CK.Cris;

namespace CK.IO.User.UserPasskey;

/// <summary>
/// Renames a passkey of the current user.
/// </summary>
public interface IRenamePasskeyCommand : ICommand<ICrisBasicCommandResult>, ICommandCurrentCulture, ICommandAuthNormal
{
    /// <summary>
    /// Gets or sets the passkey identifier. It must be one of the current user's passkeys.
    /// </summary>
    int PasskeyId { get; set; }

    /// <summary>
    /// Gets or sets the new name. Must not be blank, at most <see cref="IncomingValidators.MaxNameLength"/> characters.
    /// </summary>
    string Name { get; set; }
}
