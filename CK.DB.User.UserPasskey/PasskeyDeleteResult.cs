namespace CK.DB.User.UserPasskey;

/// <summary>
/// The result of <see cref="UserPasskeyTable.DeletePasskeyAsync"/>.
/// </summary>
public enum PasskeyDeleteResult
{
    /// <summary>
    /// The user has no such passkey.
    /// </summary>
    NotFound = 0,

    /// <summary>
    /// The passkey has been deleted.
    /// </summary>
    Deleted = 1,

    /// <summary>
    /// The user's own removal of its last passkey is refused: the user has no other way to log in.
    /// </summary>
    LastLoginMethod = 2
}
