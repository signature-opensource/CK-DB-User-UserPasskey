-- SetupConfig: { "Requires": [ "CK.fAuthUserHasOtherScheme" ] }
--
-- Deletes a passkey of a user.
-- @Result: 0 = NotFound (no such passkey for the user), 1 = Deleted, 2 = LastLoginMethod (refused).
--
-- When the actor is the user, this is the user's own removal: the "last login method" rule applies (CK.DB.Auth): the
-- user's last passkey is not deleted when the user has no other scheme in CK.vUserAuthProvider.
-- Otherwise, the actor must be an administrator: a member of the System group by default. The PasskeySecurityCheck
-- injection point can accept others (set @CanContinue to 1). An administrator's removal is not subject to the rule.
--
create procedure CK.sUserPasskeyDelete
(
	@ActorId int,
	@UserId int,
	@PasskeyId int,
	@Result int output
)
as
begin
    if @ActorId <= 0 throw 50000, 'Security.AnonymousNotAllowed', 1;
    if @UserId is null or @UserId <= 0 throw 50000, 'Argument.InvalidUserId', 1;

	if @ActorId <> @UserId
	begin
		declare @CanContinue bit = 0;
		if exists( select 1 from CK.tActorProfile where GroupId = 1 and ActorId = @ActorId ) set @CanContinue = 1;
		--<PasskeySecurityCheck revert />
		if @CanContinue = 0 throw 50000, 'Security.AdminOnly', 1;
	end

	--[beginsp]

	-- Locks all the passkeys of the user: concurrent deletes of a user's last two passkeys are serialized.
	declare @Count int;
	select @Count = count(*) from CK.tUserPasskey with(updlock, holdlock) where UserId = @UserId;

	set @Result = 0;
	if exists( select 1 from CK.tUserPasskey where PasskeyId = @PasskeyId and UserId = @UserId )
	begin
		if @ActorId = @UserId and @Count = 1 and CK.fAuthUserHasOtherScheme( @UserId, 'Passkey' ) = 0
		begin
			set @Result = 2;
		end
		else
		begin
			--<PreDelete revert />
			delete CK.tUserPasskey where PasskeyId = @PasskeyId;
			set @Result = 1;
			--<PostDelete />
		end
	end

	--[endsp]
end
