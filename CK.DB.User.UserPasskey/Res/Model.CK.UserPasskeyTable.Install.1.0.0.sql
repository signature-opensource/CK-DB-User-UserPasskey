--[beginscript]

--
-- The passkeys (WebAuthn credentials) of the users. The authentication center verifies the ceremonies; this table
-- only keeps what it needs: the public key (a COSE_Key, as received), the signature counter and the backup flags.
-- Nothing here is secret: the private key never leaves the authenticator.
--
-- Why the WebAuthn user handle is in CK.tUserPasskeyHandle and not a column of this table:
--
-- 1. The handle exists BEFORE the first passkey. The registration start sends it (user.id of the creation options):
--    for a user's first passkey there is no row here yet. IPasskeyStore.GetOrCreateUserHandleAsync persists it at
--    that time, so the AuthCenter doesn't have to carry a generated value until the registration finishes.
-- 2. The handle is a property of the user, not of a credential: all the user's passkeys share it. As a column here,
--    it would be repeated on every row, with nothing in the schema guaranteeing that the rows agree.
-- 3. Declarative constraints: "one handle per user, never shared by two users" is the primary key and the unique key
--    of CK.tUserPasskeyHandle. Repeated here, no plain unique index could express it (a safety net: 32 random bytes
--    don't collide).
--
-- The single-table alternative needs a consistency check in code (two concurrent first registrations would generate
-- two handles), forgets the handle when the user's last passkey is deleted, and changes the IPasskeyStore contract.
--
-- CredentialId can have up to 1023 bytes (the WebAuthn maximum): too long for a clustered key (900 bytes), hence the
-- PasskeyId surrogate primary key and the unique nonclustered index on CredentialId (1700 bytes limit).
-- SignCount is a bigint because the WebAuthn counter is an unsigned 32-bit integer.
-- Transports is the comma separated list of the declared transports ("internal,hybrid"), possibly empty.
-- LastUsedTime is '0001-01-01' until the first login with the passkey.
--
create table CK.tUserPasskey
(
    PasskeyId int identity(1,1) not null,
    CredentialId varbinary(1023) not null,
    UserId int not null,
    PublicKey varbinary(max) not null,
    SignCount bigint not null,
    BackupEligible bit not null,
    BackupState bit not null,
    Aaguid uniqueidentifier not null,
    Transports varchar(64) collate Latin1_General_100_BIN2 not null,
    Name nvarchar(128) not null,
    CreationDate datetime2(2) not null,
    LastUsedTime datetime2(2) not null,
    constraint PK_CK_UserPasskey primary key( PasskeyId ),
    constraint FK_CK_UserPasskey_UserId foreign key( UserId ) references CK.tUserPasskeyHandle( UserId ),
    constraint CK_CK_UserPasskey_SignCount check( SignCount between 0 and 4294967295 ),
    constraint CK_CK_UserPasskey_BackupState check( BackupEligible = 1 or BackupState = 0 )
);
create unique nonclustered index UK_CK_UserPasskey_CredentialId on CK.tUserPasskey( CredentialId );
create index IX_CK_UserPasskey_UserId on CK.tUserPasskey( UserId );

--[endscript]
