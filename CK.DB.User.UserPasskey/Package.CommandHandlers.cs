using CK.Core;
using CK.Cris;
using CK.IO.User.UserPasskey;
using CK.SqlServer;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace CK.DB.User.UserPasskey;

public partial class Package
{
    /// <summary>
    /// Lists the passkeys of the current user.
    /// </summary>
    /// <param name="ctx">The call context to use.</param>
    /// <param name="cmd">The command.</param>
    /// <param name="table">The passkey table.</param>
    /// <param name="pocoDirectory">The poco directory.</param>
    /// <returns>The passkeys of the current user.</returns>
    [CommandHandler]
    public virtual Task<List<IUserPasskey>> HandleGetPasskeysAsync( ISqlCallContext ctx, IGetPasskeysQCommand cmd, UserPasskeyTable table, PocoDirectory pocoDirectory )
    {
        return table.ReadUserPasskeysAsync( ctx, pocoDirectory, cmd.ActorId.GetValueOrDefault() );
    }

    /// <summary>
    /// Renames a passkey of the current user.
    /// </summary>
    /// <param name="ctx">The call context to use.</param>
    /// <param name="collector">The message collector.</param>
    /// <param name="cmd">The command.</param>
    /// <param name="table">The passkey table.</param>
    /// <returns>The result.</returns>
    [CommandHandler]
    public virtual async Task<ICrisBasicCommandResult> HandleRenamePasskeyAsync( ISqlCallContext ctx, UserMessageCollector collector, IRenamePasskeyCommand cmd, UserPasskeyTable table )
    {
        var res = cmd.CreateResult();
        try
        {
            if( await table.RenamePasskeyAsync( ctx, cmd.ActorId.GetValueOrDefault(), cmd.PasskeyId, cmd.Name.Trim() ) )
            {
                collector.Info( "The passkey has been renamed.", "Passkey.Renamed" );
            }
            else
            {
                collector.Error( "This passkey doesn't exist.", "Passkey.NotFound" );
            }
        }
        catch( Exception ex )
        {
            ctx.Monitor.Error( $"Error while renaming passkey #{cmd.PasskeyId} of actor #{cmd.ActorId}.", ex );
            collector.Error( "An error occurred while renaming the passkey.", "Passkey.RenameFailed" );
        }
        res.SetUserMessages( collector );
        return res;
    }

    /// <summary>
    /// Deletes a passkey of the current user. The user's last way to log in is never deleted.
    /// </summary>
    /// <param name="ctx">The call context to use.</param>
    /// <param name="collector">The message collector.</param>
    /// <param name="cmd">The command.</param>
    /// <param name="table">The passkey table.</param>
    /// <returns>The result.</returns>
    [CommandHandler]
    public virtual Task<ICrisBasicCommandResult> HandleDeletePasskeyAsync( ISqlCallContext ctx, UserMessageCollector collector, IDeletePasskeyCommand cmd, UserPasskeyTable table )
    {
        var actorId = cmd.ActorId.GetValueOrDefault();
        return DeleteAsync( ctx, collector, cmd.CreateResult(), table, actorId, actorId, cmd.PasskeyId );
    }

    /// <summary>
    /// Deletes a passkey of any user: the administrator's command.
    /// </summary>
    /// <param name="ctx">The call context to use.</param>
    /// <param name="collector">The message collector.</param>
    /// <param name="cmd">The command.</param>
    /// <param name="table">The passkey table.</param>
    /// <returns>The result.</returns>
    [CommandHandler]
    public virtual Task<ICrisBasicCommandResult> HandleDeleteUserPasskeyAsync( ISqlCallContext ctx, UserMessageCollector collector, IDeleteUserPasskeyCommand cmd, UserPasskeyTable table )
    {
        return DeleteAsync( ctx, collector, cmd.CreateResult(), table, cmd.ActorId.GetValueOrDefault(), cmd.UserId, cmd.PasskeyId );
    }

    static async Task<ICrisBasicCommandResult> DeleteAsync( ISqlCallContext ctx,
                                                            UserMessageCollector collector,
                                                            ICrisBasicCommandResult res,
                                                            UserPasskeyTable table,
                                                            int actorId,
                                                            int userId,
                                                            int passkeyId )
    {
        try
        {
            switch( await table.DeletePasskeyAsync( ctx, actorId, userId, passkeyId ) )
            {
                case PasskeyDeleteResult.Deleted:
                    ctx.Monitor.Info( ActivityMonitor.Tags.SecurityCritical, $"Passkey #{passkeyId} of user #{userId} deleted by actor #{actorId}." );
                    collector.Info( "The passkey has been deleted.", "Passkey.Deleted" );
                    break;
                case PasskeyDeleteResult.LastLoginMethod:
                    collector.Error( "This passkey is your last way to log in: it cannot be deleted.", "Passkey.LastLoginMethod" );
                    break;
                default:
                    collector.Error( "This passkey doesn't exist.", "Passkey.NotFound" );
                    break;
            }
        }
        catch( SqlDetailedException ex ) when( ex.InnerSqlException?.Message == "Security.AdminOnly" )
        {
            ctx.Monitor.Warn( ActivityMonitor.Tags.SecurityCritical, $"Actor #{actorId} is not allowed to delete passkey #{passkeyId} of user #{userId}." );
            collector.Error( "Administrator authority required.", "Security.AdminOnly" );
        }
        catch( Exception ex )
        {
            ctx.Monitor.Error( $"Error while deleting passkey #{passkeyId} of user #{userId} by actor #{actorId}.", ex );
            collector.Error( "An error occurred while deleting the passkey.", "Passkey.DeleteFailed" );
        }
        res.SetUserMessages( collector );
        return res;
    }
}
