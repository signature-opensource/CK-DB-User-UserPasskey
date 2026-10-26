-- SetupConfig: {}
--
-- The login with a passkey whose assertion has been verified by the authentication center (the "Passkey" provider).
-- The outputs are the ones of a UCL procedure (CK.DB.Auth.UCLResult): @UCResult is 2 (Updated) on an actual login.
--
-- The signature counter is checked again here (defense in depth, the authentication center checks it first): when the
-- stored and the new counters are both non zero, the new one must be greater, otherwise the authenticator may have been
-- cloned. Synchronized passkeys always send 0. A failure is transmitted as-is to CK.sAuthUserOnLogin 'Passkey'.
--
create procedure CK.sUserPasskeyLogin
(
	@CredentialId varbinary(1023),
	@SignCount bigint,
	@BackupState bit,
	@ActualLogin bit,
	@UserId int output,
	@UCResult int output, -- not null enum { None = 0, Created = 1, Updated = 2 }
	@LoginFailureCode int output,
	@LoginFailureReason nvarchar(255) output
)
as
begin
    if @CredentialId is null or DataLength( @CredentialId ) = 0 throw 50000, 'Argument.InvalidCredentialId', 1;
    if @SignCount is null or @SignCount < 0 or @SignCount > 4294967295 throw 50000, 'Argument.InvalidSignCount', 1;
    if @BackupState is null throw 50000, 'Argument.InvalidBackupState', 1;
    if @ActualLogin is null throw 50000, 'Argument.ActualLogin.MustNotBeNull', 1;

	--[beginsp]

	declare @Now datetime2(2) = sysutcdatetime();
	declare @PasskeyId int;
	declare @StoredSignCount bigint;
	declare @BackupEligible bit;
	set @UCResult = 0;
	set @LoginFailureCode = null;
	set @LoginFailureReason = null;

	select @PasskeyId = PasskeyId, @UserId = UserId, @StoredSignCount = SignCount, @BackupEligible = BackupEligible
		from CK.tUserPasskey with(updlock) where CredentialId = @CredentialId;

	if @PasskeyId is null
	begin
		set @UserId = 0;
		set @LoginFailureCode = 3; -- InvalidUserKey
	end
	else
	begin
		if (@SignCount <> 0 and @StoredSignCount <> 0 and @SignCount <= @StoredSignCount)
			or (@BackupState = 1 and @BackupEligible = 0)
		begin
			set @LoginFailureCode = 4; -- InvalidCredentials
		end
		declare @LastLoginTime datetime2(2);
		select @LastLoginTime = max( LastUsedTime ) from CK.tUserPasskey where UserId = @UserId;
		exec CK.sAuthUserOnLogin 'Passkey', @LastLoginTime, @UserId, @ActualLogin, @Now, @LoginFailureCode output, @LoginFailureReason output;
		if @ActualLogin = 1 and @LoginFailureCode is null
		begin
			update CK.tUserPasskey set
					SignCount = @SignCount,
					BackupState = @BackupState,
					LastUsedTime = @Now
				where PasskeyId = @PasskeyId;
			set @UCResult = 2;
		end
	end

	--[endsp]
end
