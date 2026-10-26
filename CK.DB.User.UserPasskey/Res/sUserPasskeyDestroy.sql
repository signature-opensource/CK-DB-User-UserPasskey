-- SetupConfig: {}
--
-- Destroys all the passkeys of a user and its user handle. Called when the user is destroyed (CK.sUserDestroy).
--
create procedure CK.sUserPasskeyDestroy
(
	@ActorId int,
	@UserId int
)
as
begin
    if @ActorId <= 0 throw 50000, 'Security.AnonymousNotAllowed', 1;
    if @UserId = 0 throw 50000, 'Argument.InvalidValue', 1;

	--[beginsp]

	--<PreDestroy revert />

	delete CK.tUserPasskey where UserId = @UserId;
	delete CK.tUserPasskeyHandle where UserId = @UserId;

	--<PostDestroy />

	--[endsp]
end
