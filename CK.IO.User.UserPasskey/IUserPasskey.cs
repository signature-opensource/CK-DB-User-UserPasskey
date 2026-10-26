using CK.Core;
using System;

namespace CK.IO.User.UserPasskey;

/// <summary>
/// A passkey of a user, as listed by <see cref="IGetPasskeysQCommand"/>. Nothing here is a secret, but the credential
/// identifier and the public key are not exposed: a passkey is designated by its <see cref="PasskeyId"/>.
/// </summary>
public interface IUserPasskey : IPoco
{
    /// <summary>
    /// Gets or sets the passkey identifier.
    /// </summary>
    int PasskeyId { get; set; }

    /// <summary>
    /// Gets or sets the name given to the passkey ("My phone").
    /// </summary>
    string Name { get; set; }

    /// <summary>
    /// Gets or sets the model of the authenticator, as declared by it (not attested: for display only).
    /// Can be <see cref="Guid.Empty"/>.
    /// </summary>
    Guid Aaguid { get; set; }

    /// <summary>
    /// Gets or sets whether the passkey can be synchronized between devices.
    /// </summary>
    bool BackupEligible { get; set; }

    /// <summary>
    /// Gets or sets whether the passkey was synchronized at its last use.
    /// </summary>
    bool BackupState { get; set; }

    /// <summary>
    /// Gets or sets the registration time.
    /// </summary>
    DateTime CreationDate { get; set; }

    /// <summary>
    /// Gets or sets the last time the passkey was used to log in.
    /// <see cref="Util.UtcMinValue"/> if it has never been used.
    /// </summary>
    DateTime LastUsedTime { get; set; }
}
