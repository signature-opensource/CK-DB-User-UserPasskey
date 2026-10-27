using CK.Auth;
using CK.Cris;
using System.Collections.Generic;

namespace CK.IO.User.UserPasskey;

/// <summary>
/// Lists the passkeys of the current user.
/// </summary>
public interface IGetPasskeysQCommand : ICommand<List<IUserPasskey>>, ICommandAuthNormal
{
}
