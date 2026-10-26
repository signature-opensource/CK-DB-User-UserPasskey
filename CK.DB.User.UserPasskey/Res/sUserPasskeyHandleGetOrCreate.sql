-- SetupConfig: {}
--
-- Gets the user handle of a user, created on the first call: 32 cryptographically random bytes.
-- Concurrent first calls for a user are serialized (updlock, holdlock): they all get the same handle.
--
create procedure CK.sUserPasskeyHandleGetOrCreate
(
	@UserId int,
	@UserHandle binary(32) output
)
as
begin
    if @UserId is null or @UserId <= 0 throw 50000, 'Argument.InvalidUserId', 1;

	--[beginsp]

	set @UserHandle = null;
	select @UserHandle = UserHandle from CK.tUserPasskeyHandle with(updlock, holdlock) where UserId = @UserId;
	if @UserHandle is null
	begin
		set @UserHandle = crypt_gen_random( 32 );
		--<PreCreate revert />
		insert into CK.tUserPasskeyHandle( UserId, UserHandle ) values( @UserId, @UserHandle );
		--<PostCreate />
	end

	--[endsp]
end
