--[beginscript]

--
-- The WebAuthn user handle of a user: the "user.id" of the passkey registration options, stored by the authenticator
-- with each passkey and sent back at login. Random (CK.sUserPasskeyHandleGetOrCreate), never derived from the user
-- identifier (an integer is enumerable and would show up on the authenticator's side), the same for all the passkeys
-- of the user. Why it is not a column of CK.tUserPasskey: see the CK.tUserPasskey script.
--
create table CK.tUserPasskeyHandle
(
    UserId int not null,
    UserHandle binary(32) not null,
    constraint PK_CK_UserPasskeyHandle primary key( UserId ),
    constraint FK_CK_UserPasskeyHandle_UserId foreign key( UserId ) references CK.tUser( UserId ),
    constraint UK_CK_UserPasskeyHandle_UserHandle unique( UserHandle )
);

--[endscript]
