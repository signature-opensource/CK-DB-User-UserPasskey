-- SetupConfig: {}
--
-- Renames a passkey of the acting user. @Renamed is 0 when the passkey doesn't exist or is not the actor's one.
--
create procedure CK.sUserPasskeyRename
(
	@ActorId int,
	@PasskeyId int,
	@Name nvarchar(128),
	@Renamed bit output
)
as
begin
    if @ActorId <= 0 throw 50000, 'Security.AnonymousNotAllowed', 1;
    if @Name is null or len( @Name ) = 0 throw 50000, 'Argument.InvalidName', 1;

	--[beginsp]

	update CK.tUserPasskey set Name = @Name where PasskeyId = @PasskeyId and UserId = @ActorId;
	set @Renamed = case when @@rowcount = 1 then 1 else 0 end;

	--[endsp]
end
