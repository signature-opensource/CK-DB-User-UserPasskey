-- SetupConfig: {}
--
-- Stores a new passkey, verified by the authentication center.
-- @UserHandle must be the user's handle (see CK.sUserPasskeyHandleGetOrCreate): the registration options carried it.
-- @PasskeyIdResult is 0 when the credential identifier already exists (for any user): nothing is stored.
--
create procedure CK.sUserPasskeyCreate
(
	@ActorId int,
	@UserId int,
	@UserHandle binary(32),
	@CredentialId varbinary(1023),
	@PublicKey varbinary(max),
	@SignCount bigint,
	@BackupEligible bit,
	@BackupState bit,
	@Aaguid uniqueidentifier,
	@Transports varchar(64),
	@Name nvarchar(128),
	@PasskeyIdResult int output
)
as
begin
    if @ActorId <= 0 throw 50000, 'Security.AnonymousNotAllowed', 1;
    if @UserId is null or @UserId <= 0 throw 50000, 'Argument.InvalidUserId', 1;
    if @CredentialId is null or DataLength( @CredentialId ) = 0 throw 50000, 'Argument.InvalidCredentialId', 1;
    if @PublicKey is null or DataLength( @PublicKey ) = 0 throw 50000, 'Argument.InvalidPublicKey', 1;
    if @Name is null or len( @Name ) = 0 throw 50000, 'Argument.InvalidName', 1;

	--[beginsp]

	if not exists( select 1 from CK.tUserPasskeyHandle where UserId = @UserId and UserHandle = @UserHandle )
	begin
		;throw 50000, 'Passkey.UserHandleMismatch', 1;
	end

	if exists( select 1 from CK.tUserPasskey with(updlock, holdlock) where CredentialId = @CredentialId )
	begin
		set @PasskeyIdResult = 0;
	end
	else
	begin
		declare @Now datetime2(2) = sysutcdatetime();
		--<PreCreate revert />
		insert into CK.tUserPasskey( CredentialId, UserId, PublicKey, SignCount, BackupEligible, BackupState, Aaguid, Transports, Name, CreationDate, LastUsedTime )
			values( @CredentialId, @UserId, @PublicKey, @SignCount, @BackupEligible, @BackupState, @Aaguid, isnull( @Transports, '' ), @Name, @Now, '0001-01-01' );
		set @PasskeyIdResult = scope_identity();
		--<PostCreate />
	end

	--[endsp]
end
