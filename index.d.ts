// Type definitions for pkcs11js v1.1.2
// Project: https://github.com/PeculiarVentures/pkcs11js
// Definitions by: Stepan Miroshin <https://github.com/microshine>

/// <reference types="node" />

/**
 * A Node.js implementation of the PKCS#11 2.30 interface
 */
declare module "pkcs11js" {
    /**
     * PKCS#11 handle type
     */
    type Handle = Buffer;

    /**
     * Structure that describes the version
     */
    interface Version {
        /**
         * Major version number (the integer portion of the version)
         */
        major: number;
        /**
         * minor version number (the hundredths portion of the version)
         */
        minor: number;
    }

    /**
     * Provides general information about Cryptoki
     */
    interface ModuleInfo {
        /**
         * Cryptoki interface version number, for compatibility with future revisions of this interface
         */
        cryptokiVersion: Version;
        /**
         * ID of the Cryptoki library manufacturer.
         * Must be padded with the blank character (' ').
         */
        manufacturerID: string;
        /**
         * Bit flags reserved for future versions. Must be zero for this version
         */
        flags: number;
        /**
         * Character-string description of the library.
         * Must be padded with the blank character (' ')
         */
        libraryDescription: string;
        /**
         * Cryptoki library version number
         */
        libraryVersion: Version;
    }

    /**
     * Provides information about a slot
     */
    interface SlotInfo {
        /**
         * Character-string description of the slot.
         * Must be padded with the blank character (' ')
         */
        slotDescription: string;
        /**
         * ID of the slot manufacturer.
         * Must be padded with the blank character (' ')
         */
        manufacturerID: string;
        /**
         * Bits flags that provide capabilities of the slot
         */
        flags: number;
        /**
         * Version number of the slot's hardware
         */
        hardwareVersion: Version;
        /**
         * Version number of the slot's firmware
         */
        firmwareVersion: Version;
    }

    /**
     * Provides information about a token
     */
    interface TokenInfo {
        /**
         * Application-defined label, assigned during token initialization.
         * Must be padded with the blank character (' ')
         */
        label: string;
        /**
         * ID of the device manufacturer. 
         * Must be padded with the blank character (' ')
         */
        manufacturerID: string;
        /**
         * Model of the device. 
         * Must be padded with the blank character (' ')
         */
        model: string;
        /**
         * Character-string serial number of the device. 
         * Must be padded with the blank character (' ')
         */
        serialNumber: string;
        /**
         * Bit flags indicating capabilities and status of the device
         */
        flags: number;
        /**
         * Maximum number of sessions that can be opened with the token at one time by a single application
         */
        maxSessionCount: number;
        /**
         * Number of sessions that this application currently has open with the token
         */
        sessionCount: number;
        /**
         * Maximum number of read/write sessions that can be opened with the token at one time by a single application
         */
        maxRwSessionCount: number;
        /**
         * Number of read/write sessions that this application currently has open with the token
         */
        rwSessionCount: number;
        /**
         * Maximum length in bytes of the PIN
         */
        maxPinLen: number;
        /**
         * Minimum length in bytes of the PIN
         */
        minPinLen: number;
        /**
         * version number of hardware
         */
        hardwareVersion: Version;
        /**
         * Version number of firmware
         */
        firmwareVersion: Version;
        /**
         * Current time as a character-string of length 16, represented in the format YYYYMMDDhhmmssxx 
         * (4 characters for the year; 2 characters each for the month, the day, the hour, the minute, 
         * and the second; and 2 additional reserved '0' characters). 
         * The value of this field only makes sense for tokens equipped with a clock, 
         * as indicated in the token information flags
         */
        utcTime: string;
        /**
         * The total amount of memory on the token in bytes in which public objects may be stored
         */
        totalPublicMemory: number;
        /**
         * The amount of free (unused) memory on the token in bytes for public objects
         */
        freePublicMemory: number;
        /**
         * The total amount of memory on the token in bytes in which private objects may be stored
         */
        totalPrivateMemory: number;
        /**
         * The amount of free (unused) memory on the token in bytes for private objects
         */
        freePrivateMemory: number;
    }

    /**
     * Provides information about a particular mechanism
     */
    interface MechanismInfo {
        /**
         * The minimum size of the key for the mechanism
         */
        minKeySize: number;
        /**
         * The maximum size of the key for the mechanism
         */
        maxKeySize: number;
        /**
         * Bit flags specifying mechanism capabilities
         */
        flags: number;
    }

    /**
     * Provides information about a session
     */
    interface SessionInfo {
        /**
         * ID of the slot that interfaces with the token
         */
        slotID: Buffer;
        /**
         * The state of the session
         */
        state: number;
        /**
         * Bit flags that define the type of session
         */
        flags: number;
        /**
         * An error code defined by the cryptographic device
         */
        deviceError: number;
    }

    type Template = Attribute[];

    /**
     * A structure that includes the type and value of an attribute
     */
    interface Attribute {
        /**
         * The attribute type
         */
        type: number;
        /**
         * The value of the attribute
         */
        value?: number | boolean | string | Buffer;
    }

    /**
     * A structure that specifies a particular mechanism and any parameters it requires
     */
    interface Mechanism {
        /**
         * The type of mechanism
         */
        mechanism: number;
        /**
         * The parameter if required by the mechanism
         */
        parameter?: Buffer | IParams;
    }

    //#region Crypto parameters

    /**
     * A base structure of a parameter
     */
    interface IParams {
        /**
         * Type of crypto param. Uses constants CK_PARAMS_*
         */
        type: number;
    }

    /**
     * A structure that provides the parameters for the {@link CKM_ECDH1_DERIVE} and {@link CKM_ECDH1_COFACTOR_DERIVE} 
     * key derivation mechanisms, where each party contributes one key pair
     */
    interface ECDH1 extends IParams {
        /**
         * Key derivation function used on the shared secret value
         */
        kdf: number;
        /**
         * Some data shared between the two parties
         */
        sharedData?: Buffer;
        /**
         * The other party's EC public key
         */
        publicData: Buffer;
    }

    interface AesCBC extends IParams {
        iv: Buffer;
        data?: Buffer;
    }

    interface AesCCM extends IParams {
        dataLen: number;
        nonce?: Buffer;
        aad?: Buffer;
        macLen: number;
    }

    interface AesGCM extends IParams {
        iv?: Buffer;
        aad?: Buffer;
        ivBits: number;
        tagBits: number;
    }

    interface RsaOAEP extends IParams {
        hashAlg: number;
        mgf: number;
        source: number;
        sourceData?: Buffer;
    }

    interface RsaPSS extends IParams {
        hashAlg: number;
        mgf: number;
        saltLen: number;
    }

    //#endregion

    interface KeyPair {
        privateKey: Handle;
        publicKey: Handle;
    }

    interface InitializationOptions {
        /**
         * NSS library parameters
         */
        libraryParameters?: string;
        /**
         * bit flags specifying options for {@link C_Initialize}
         * - CKF_LIBRARY_CANT_CREATE_OS_THREADS. True if application threads which are executing calls to the library
         *   may not use native operating system calls to spawn new threads; false if they may
         * - CKF_OS_LOCKING_OK. True if the library can use the native operation system threading model for locking;
         *   false otherwise
         */
        flags?: number;
    }

    /**
     * A Structure which contains a Cryptoki version and each function in the Cryptoki API
     */
    export class PKCS11 {
        /**
         * Library path
         */
        public libPath: string;

        /**
         * Loads dynamic library with PKCS#11 interface
         * @param path The path to PKCS#11 library
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public load(path: string): void;
        /**
         * Initializes the Cryptoki library
         * @param options Initialization options
         * Supports implementation of standard `CK_C_INITIALIZE_ARGS` and extended NSS format.
         * - if `options` is null or empty, it calls native `C_Initialize` with `NULL`
         * - if `options` doesn't have `libraryParameters`, it uses `CK_C_INITIALIZE_ARGS` structure
         * - if `options` has `libraryParameters`, it uses extended NSS structure
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Initialize(options?: InitializationOptions): void;
        /**
         * Closes dynamic library
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public close(): void;
        /**
         * Indicates that an application is done with the Cryptoki library
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Finalize(): void;
        /**
         * Returns general information about Cryptoki
         * @returns Information about Cryptoki
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GetInfo(): ModuleInfo;

        //#region Slot and token management

        /**
         * Obtains a list of slots in the system
         * @param [tokenPresent] Only slots with tokens?
         * @returns Array of slot IDs
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GetSlotList(tokenPresent?: boolean): Handle[];
        /**
         * Obtains information about a particular slot in the system
         * @param  slot The ID of the slot
         * @returns Information about a slot
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GetSlotInfo(slot: Handle): SlotInfo;
        /**
         * Obtains information about a particular token in the system
         * @param slot ID of the token's slot
         * @returns Information about a token
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GetTokenInfo(slot: Handle): TokenInfo;
        /**
         * Initializes a token
         * @param slot ID of the token's slot
         * @param [pin] The SO's initial PIN
         * @returns 32-byte token label (blank padded)
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_InitToken(slot: Handle, pin?: string, label?: string): string;
        /**
         * Initializes the normal user's PIN
         * @param session The session's handle
         * @param pin The normal user's PIN
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_InitPIN(session: Handle, pin?: string): void;
        /**
         * Modifies the PIN of the user who is logged in
         * @param session The session's handle
         * @param oldPin The old PIN
         * @param newPin The new PIN
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_SetPIN(session: Handle, oldPin: string, newPin: string): void;
        /**
         * Obtains a list of mechanism types supported by a token
         * @param slot ID of token's slot
         * @returns A list of mechanism types
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GetMechanismList(slot: Handle): number[];
        /**
         * Obtains information about a particular mechanism possibly supported by a token
         * @param slot ID of the token's slot
         * @param mech Type of mechanism
         * @returns Information about mechanism
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GetMechanismInfo(slot: Handle, mech: number): MechanismInfo;

        //#endregion

        //#region Session management

        /**
         * Opens a session between an application and a token
         * @param slot The slot's ID
         * @param flags From CK_SESSION_INFO
         * @returns Session handle
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_OpenSession(slot: Handle, flags: number): Handle;
        /**
         * Closes a session between an application and a token
         * @param session The session's handle
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_CloseSession(session: Handle): void;
        /**
         * Closes all sessions with a token
         * @param slot The token's slot
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_CloseAllSessions(slot: Handle): void;
        /**
         * Obtains information about the session
         * @param session The session's handle
         * @returns Receives session info
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GetSessionInfo(session: Handle): SessionInfo;
        /**
         * Logs a user into a token
         * @param session The session's handle
         * @param userType The user type
         * @param [pin] The user's PIN
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Login(session: Handle, userType: number, pin?: string): void;
        /**
         * Logs a user out from a token
         * @param session The session's handle
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Logout(session: Handle): void;

        //#endregion

        //#region Object management

        /**
         * Creates a new object
         * @param session The session's handle
         * @param template The object's template
         * @returns A new object's handle
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_CreateObject(session: Handle, template: Template): Handle;
        /**
         * Copies an object, creating a new object for the copy
         * @param session The session's handle
         * @param object The object's handle
         * @param template Template for new object
         * @returns A handle of copy
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_CopyObject(session: Handle, object: Handle, template: Template): Handle;
        /**
         * Destroys an object
         * @param session The session's handle
         * @param object The object's handle
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_DestroyObject(session: Handle, object: Handle): void;
        /**
         * Gets the size of an object in bytes
         * @param session The session's handle
         * @param object The object's handle
         * @returns Size of an object in bytes
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GetObjectSize(session: Handle, object: Handle): number;
        /**
         * Initializes a search for token and session objects that match a template
         * @param session The session's handle
         * @param template Attribute values to match
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_FindObjectsInit(session: Handle, template: Template): void;
        /**
         * Continues a search for token and session
         * objects that match a template, obtaining additional object
         * handles
         * @param session The session's handle
         * @param session The maximum number of object handles to be returned
         * @returns List of handles
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_FindObjects(session: Handle, maxObjectCount: number): Handle[];
        /**
         * Continues a search for token and session
         * objects that match a template, obtaining additional object
         * handles
         * @param session The session's handle
         * @returns Object's handle. If object is not found
         * the result is null
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_FindObjects(session: Handle): Handle | null;
        /**
         * Finishes a search for token and session objects
         * @param session The session's handle
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_FindObjectsFinal(session: Handle): void;
        /**
         * Obtains the value of one or more object attributes
         * @param session The session's handle
         * @param object The object's handle
         * @param template Specifies attrs; gets values
         * @returns List of Attributes with values
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GetAttributeValue(session: Handle, object: Handle, template: Template): Template;
        /**
         * Modifies the value of one or more object attributes
         * @param session The session's handle
         * @param object The object's handle
         * @param template Specifies attrs and values
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_SetAttributeValue(session: Handle, object: Handle, template: Template): void;

        //#endregion

        //#region Encryption and decryption

        /**
         * Initializes an encryption operation
         * @param session The session's handle
         * @param mechanism The encryption mechanism
         * @param key Handle of encryption key
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_EncryptInit(session: Handle, mechanism: Mechanism, key: Handle): void;
        /**
         * Encrypts single-part data
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @returns Sliced output data with encrypted message
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Encrypt(session: Handle, inData: Buffer, outData: Buffer): Buffer;
        /**
         * Encrypts single-part data
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @param cb Async callback with sliced output data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Encrypt(session: Handle, inData: Buffer, outData: Buffer, cb: (error: Error, data: Buffer) => void): void;
        /**
         * Encrypts single-part data
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @returns Sliced output data with encrypted message
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_EncryptAsync(session: Handle, inData: Buffer, outData: Buffer): Promise<Buffer>;
        /**
         * Continues a multiple-part encryption operation
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @returns Sliced output data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_EncryptUpdate(session: Handle, inData: Buffer, outData: Buffer): Buffer;
        /**
         * Finishes a multiple-part encryption operation
         * @param session The session's handle
         * @param outData Last output data
         * @returns Sliced output data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_EncryptFinal(session: Handle, outData: Buffer): Buffer;
        /**
         * Initializes a decryption operation
         * @param session The session's handle
         * @param mechanism The decryption mechanism
         * @param key Handle of decryption key
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_DecryptInit(session: Handle, mechanism: Mechanism, key: Handle): void;
        /**
         * Decrypts encrypted data in a single part
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @returns Sliced output data with decrypted message
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Decrypt(session: Handle, inData: Buffer, outData: Buffer): Buffer;
        /**
         * Decrypts encrypted data in a single part
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @param cb Async callback with sliced output data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Decrypt(session: Handle, inData: Buffer, outData: Buffer, cb: (error: Error, data: Buffer) => void): void;
        /**
         * Decrypts encrypted data in a single part
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @returns Sliced output data with decrypted message
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_DecryptAsync(session: Handle, inData: Buffer, outData: Buffer): Promise<Buffer>;
        /**
         * continues a multiple-part decryption operation
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @returns Sliced output data with decrypted block
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_DecryptUpdate(session: Handle, inData: Buffer, outData: Buffer): Buffer;
        /**
         * Finishes a multiple-part decryption operation
         * @param session The session's handle
         * @param outData Last part of output data
         * @returns Sliced output data with decrypted final block
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_DecryptFinal(session: Handle, outData: Buffer): Buffer;

        /* Message digesting */

        /**
         * Initializes a message-digesting operation
         * @param session The session's handle
         * @param mechanism Digesting mechanism
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_DigestInit(session: Handle, mechanism: Mechanism): void;
        /**
         * Digests data in a single part
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @returns Sliced output data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Digest(session: Handle, inData: Buffer, outData: Buffer): Buffer;
        /**
         * Digests data in a single part
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @param cb Async callback with sliced output data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Digest(session: Handle, inData: Buffer, outData: Buffer, cb: (error: Error, data: Buffer) => void): void;
        /**
         * Digests data in a single part
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @returns Sliced output data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_DigestAsync(session: Handle, inData: Buffer, outData: Buffer): Promise<Buffer>;
        /**
         * continues a multiple-part message-digesting operation
         * operation, by digesting the value of a secret key as part of
         * the data already digested
         * @param session The session's handle
         * @param inData Incoming data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_DigestUpdate(session: Handle, inData: Buffer): void;
        /**
         * Finishes a multiple-part message-digesting operation
         * @param session The session's handle
         * @param outData Output data
         * @returns Sliced output data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_DigestFinal(session: Handle, outData: Buffer): Buffer;
        /**
         * Continues a multiple-part message-digesting operation by digesting the value of a secret key
         * @param session The session's handle
         * @param key The handle of the secret key to be digested
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_DigestKey(session: Handle, key: Handle): void;

        //#endregion

        //#region Signing and MACing

        /**
         * initializes a signature (private key encryption)
         * operation, where the signature is (will be) an appendix to
         * the data, and plaintext cannot be recovered from the
         * signature
         * @param session The session's handle
         * @param mechanism Signature mechanism
         * @param key Handle of signature key
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_SignInit(session: Handle, mechanism: Mechanism, key: Handle): void;
        /**
         * Signs (encrypts with private key) data in a single
         * part, where the signature is (will be) an appendix to the
         * data, and plaintext cannot be recovered from the signature
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @returns Sliced output data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Sign(session: Handle, inData: Buffer, outData: Buffer): Buffer;
        /**
         * Signs (encrypts with private key) data in a single
         * part, where the signature is (will be) an appendix to the
         * data, and plaintext cannot be recovered from the signature
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @param cb Async callback with sliced output data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Sign(session: Handle, inData: Buffer, outData: Buffer, cb: (error: Error, data: Buffer) => void): void;
        /**
         * Signs (encrypts with private key) data in a single
         * part, where the signature is (will be) an appendix to the
         * data, and plaintext cannot be recovered from the signature
         * @param session The session's handle
         * @param inData Incoming data
         * @param outData Output data
         * @returns Sliced output data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_SignAsync(session: Handle, inData: Buffer, outData: Buffer): Promise<Buffer>;
        /**
         * Continues a multiple-part signature operation,
         * where the signature is (will be) an appendix to the data,
         * and plaintext cannot be recovered from the signature
         * @param session The session's handle
         * @param inData Incoming data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_SignUpdate(session: Handle, inData: Buffer): void;
        /**
         * Finishes a multiple-part signature operation,
         * returning the signature
         * @param session The session's handle
         * @param outData Output data
         * @returns Sliced output data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_SignFinal(session: Handle, outData: Buffer): Buffer;
        /**
         * Initializes a signature operation, where the data can be recovered from the signature
         * @param session The session's handle
         * @param mechanism The structure that specifies the signature mechanism 
         * @param key The handle of the signature key
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_SignRecoverInit(session: Handle, mechanism: Mechanism, key: Handle): void;
        /**
         * Signs data in a single operation, where the data can be recovered from the signature
         * @param session 
         * @param inData Incoming data
         * @param outData Output data
         * @returns Sliced output data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_SignRecover(session: Handle, inData: Buffer, outData: Buffer): Buffer;

        //#endregion

        //#region Verifying signatures and MACs

        /**
         * initializes a verification operation, where the
         * signature is an appendix to the data, and plaintext cannot
         * cannot be recovered from the signature (e.g. DSA)
         * @param session The session's handle
         * @param mechanism Verification mechanism
         * @param key Verification key
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_VerifyInit(session: Handle, mechanism: Mechanism, key: Handle): void;
        /**
         * Verifies a signature in a single-part operation,
         * where the signature is an appendix to the data, and plaintext
         * cannot be recovered from the signature
         * @param session The session's handle
         * @param inData Incoming data
         * @param signature Signature to verify
         * @returns Verification result
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Verify(session: Handle, inData: Buffer, signature: Buffer): boolean;
        /**
         * Verifies a signature in a single-part operation,
         * where the signature is an appendix to the data, and plaintext
         * cannot be recovered from the signature
         * @param session The session's handle
         * @param inData Incoming data
         * @param signature Signature to verify
         * @param cb Async callback with verification result
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_Verify(session: Handle, inData: Buffer, signature: Buffer, cb: (error: Error, verify: boolean) => void): void;
        /**
         * Verifies a signature in a single-part operation,
         * where the signature is an appendix to the data, and plaintext
         * cannot be recovered from the signature
         * @param session The session's handle
         * @param inData Incoming data
         * @param signature Signature to verify
         * @returns Verification result
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_VerifyAsync(session: Handle, inData: Buffer, signature: Buffer): Promise<boolean>;
        /**
         * Continues a multiple-part verification
         * operation, where the signature is an appendix to the data,
         * and plaintext cannot be recovered from the signature
         * @param session The session's handle
         * @param inData Incoming data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_VerifyUpdate(session: Handle, inData: Buffer): void;
        /**
         * Finishes a multiple-part verification
         * operation, checking the signature
         * @param session The session's handle
         * @param signature Signature to verify
         * @returns
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_VerifyFinal(session: Handle, signature: Buffer): boolean;
        /**
         * Initializes a signature verification operation, where the data is recovered from the signature
         * @param session The session's handle
         * @param mechanism The structure that specifies the verification mechanism
         * @param key The handle of the verification key
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        C_VerifyRecoverInit(session: Handle, mechanism: Mechanism, key: Handle): void;
        /**
         * Verifies a signature in a single-part operation, where the data is recovered from the signature
         * @param session The session's handle
         * @param signature The signature to verify
         * @param outData The allocated buffer for recovered data
         * @return The sliced output data with recovered data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        C_VerifyRecover(session: Handle, signature: Buffer, outData: Buffer): Buffer;

        //#endregion

        //#region Key management

        /**
         * Generates a secret key, creating a new key object
         * @param session The session's handle
         * @param mechanism Key generation mechanism
         * @param template Template for new key
         * @returns The handle of the new key
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GenerateKey(session: Handle, mechanism: Mechanism, template: Template): Handle;
        /**
         * Generates a secret key, creating a new key object
         * @param session The session's handle
         * @param mechanism Key generation mechanism
         * @param template Template for new key
         * @param cb Async callback with handle of new key
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GenerateKey(session: Handle, mechanism: Mechanism, template: Template, cb: (error: Error, key: Handle) => void): void;
        /**
         * Generates a secret key, creating a new key object
         * @param session The session's handle
         * @param mechanism The key generation mechanism
         * @param template The template for the new key
         * @returns The handle of the new key
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GenerateKeyAsync(session: Handle, mechanism: Mechanism, template: Template): Promise<Handle>;
        /**
         * Generates a public-key/private-key pair,
         * creating new key objects
         * @param session The session's handle
         * @param mechanism Key generation mechanism
         * @param publicTmpl Template for public key
         * @param privateTmpl Template for private key
         * @returns The pair of handles for private and public keys
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GenerateKeyPair(session: Handle, mechanism: Mechanism, publicTmpl: Template, privateTmpl: Template): KeyPair;
        /**
         * Generates a public-key/private-key pair,
         * creating new key objects
         * @param session The session's handle
         * @param mechanism Key generation mechanism
         * @param publicTmpl Template for public key
         * @param privateTmpl Template for private key
         * @param cb Async callback with handles for private and public keys
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GenerateKeyPair(session: Handle, mechanism: Mechanism, publicTmpl: Template, privateTmpl: Template, cb: (error: Error, keys: KeyPair) => void): void;
        /**
         * Generates a public-key/private-key pair,
         * creating new key objects
         * @param session The session's handle
         * @param mechanism Key generation mechanism
         * @param publicTmpl Template for public key
         * @param privateTmpl Template for private key
         * @returns Handles for private and public keys
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GenerateKeyPairAsync(session: Handle, mechanism: Mechanism, publicTmpl: Template, privateTmpl: Template): Promise<KeyPair>;
        /**
         * Wraps (i.e., encrypts) a key
         * @param session The session's handle
         * @param mechanism Wrapping mechanism
         * @param wrappingKey Wrapping key
         * @param key Key to be wrapped
         * @param wrappedKey Init buffer for wrapped key
         * @returns Sliced wrapped key
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_WrapKey(session: Handle, mechanism: Mechanism, wrappingKey: Handle, key: Handle, wrappedKey: Buffer): Buffer;
        /**
         * Wraps (i.e., encrypts) a key
         * @param session The session's handle
         * @param mechanism Wrapping mechanism
         * @param wrappingKey Wrapping key
         * @param key Key to be wrapped
         * @param wrappedKey Init buffer for wrapped key
         * @param cb Async callback with sliced wrapped key
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_WrapKey(session: Handle, mechanism: Mechanism, wrappingKey: Handle, key: Handle, wrappedKey: Buffer, cb: (error: Error, wrappedKey: Buffer) => void): void;
        /**
         * Wraps (i.e., encrypts) a key
         * @param session The session's handle
         * @param mechanism Wrapping mechanism
         * @param wrappingKey Wrapping key
         * @param key Key to be wrapped
         * @param wrappedKey Init buffer for wrapped key
         * @returns Sliced wrapped key
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_WrapKeyAsync(session: Handle, mechanism: Mechanism, wrappingKey: Handle, key: Handle, wrappedKey: Buffer): Promise<Buffer>;
        /**
         * Unwraps (decrypts) a wrapped key, creating a new key object
         * @param session The session's handle
         * @param mechanism Unwrapping mechanism
         * @param unwrappingKey Unwrapping key
         * @param wrappedKey Wrapped key
         * @param template New key template
         * @returns The unwrapped key handle
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_UnwrapKey(session: Handle, mechanism: Mechanism, unwrappingKey: Handle, wrappedKey: Buffer, template: Template): Handle;
        /**
         * Unwraps (decrypts) a wrapped key, creating a new key object
         * @param session The session's handle
         * @param mechanism Unwrapping mechanism
         * @param unwrappingKey Unwrapping key
         * @param wrappedKey Wrapped key
         * @param template New key template
         * @param cb Async callback with new key handle
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_UnwrapKey(session: Handle, mechanism: Mechanism, unwrappingKey: Handle, wrappedKey: Buffer, template: Template, cb: (error: Error, key: Handle) => void): void;
        /**
         * Unwraps (decrypts) a wrapped key, creating a new key object
         * @param session The session's handle
         * @param mechanism Unwrapping mechanism
         * @param unwrappingKey Unwrapping key
         * @param wrappedKey Wrapped key
         * @param template New key template
         * @returns The unwrapped key handle
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_UnwrapKeyAsync(session: Handle, mechanism: Mechanism, unwrappingKey: Handle, wrappedKey: Buffer, template: Template): Promise<Handle>;
        /**
         * Derives a key from a base key, creating a new key object
         * @param session The session's handle
         * @param mechanism The key derivation mechanism
         * @param key The base key
         * @param template The template for the new key
         * @returns The derived key handle
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_DeriveKey(session: Handle, mechanism: Mechanism, key: Handle, template: Template): Handle;
        /**
         * Derives a key from a base key, creating a new key object
         * @param session The session's handle
         * @param mechanism The key derivation mechanism
         * @param key The base key
         * @param template The template for the new key
         * @param cb Async callback with the derived key handle
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_DeriveKey(session: Handle, mechanism: Mechanism, key: Handle, template: Template, cb: (error: Error, hKey: Handle) => void): void;
        /**
         * Derives a key from a base key, creating a new key object
         * @param session The session's handle
         * @param mechanism The key derivation mechanism
         * @param key The base key
         * @param template The template for the new key
         * @returns The derived key handle
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_DeriveKeyAsync(session: Handle, mechanism: Mechanism, key: Handle, template: Template): Promise<Handle>;
        /**
         * Mixes additional seed material into the token's random number generator
         * @param session The session's handle
         * @param buf The seed material
         * @returns The seeded data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_SeedRandom(session: Handle, buf: Buffer): Buffer;
        /**
         * Generates random data
         * @param session The session's handle
         * @param buf Init buffer
         * @returns The random data
         * @throws {@link NativeError} if native error occurs
         * @throws {@link Pkcs11Error} if Cryptoki error occurs
         */
        public C_GenerateRandom(session: Handle, buf: Buffer): Buffer;

        //#endregion

    }

    //#region Attributes
    const CKA_CLASS: number;
    const CKA_TOKEN: number;
    const CKA_PRIVATE: number;
    const CKA_LABEL: number;
    const CKA_APPLICATION: number;
    const CKA_VALUE: number;
    const CKA_OBJECT_ID: number;
    const CKA_CERTIFICATE_TYPE: number;
    const CKA_ISSUER: number;
    const CKA_SERIAL_NUMBER: number;
    const CKA_AC_ISSUER: number;
    const CKA_OWNER: number;
    const CKA_ATTR_TYPES: number;
    const CKA_TRUSTED: number;
    const CKA_CERTIFICATE_CATEGORY: number;
    const CKA_JAVA_MIDP_SECURITY_DOMAIN: number;
    const CKA_URL: number;
    const CKA_HASH_OF_SUBJECT_PUBLIC_KEY: number;
    const CKA_HASH_OF_ISSUER_PUBLIC_KEY: number;
    const CKA_NAME_HASH_ALGORITHM: number;
    const CKA_CHECK_VALUE: number;
    const CKA_KEY_TYPE: number;
    const CKA_SUBJECT: number;
    const CKA_ID: number;
    const CKA_SENSITIVE: number;
    const CKA_ENCRYPT: number;
    const CKA_DECRYPT: number;
    const CKA_WRAP: number;
    const CKA_UNWRAP: number;
    const CKA_SIGN: number;
    const CKA_SIGN_RECOVER: number;
    const CKA_VERIFY: number;
    const CKA_VERIFY_RECOVER: number;
    const CKA_DERIVE: number;
    const CKA_START_DATE: number;
    const CKA_END_DATE: number;
    const CKA_MODULUS: number;
    const CKA_MODULUS_BITS: number;
    const CKA_PUBLIC_EXPONENT: number;
    const CKA_PRIVATE_EXPONENT: number;
    const CKA_PRIME_1: number;
    const CKA_PRIME_2: number;
    const CKA_EXPONENT_1: number;
    const CKA_EXPONENT_2: number;
    const CKA_COEFFICIENT: number;
    const CKA_PRIME: number;
    const CKA_SUBPRIME: number;
    const CKA_BASE: number;
    const CKA_PRIME_BITS: number;
    const CKA_SUBPRIME_BITS: number;
    const CKA_SUB_PRIME_BITS: number;
    const CKA_VALUE_BITS: number;
    const CKA_VALUE_LEN: number;
    const CKA_EXTRACTABLE: number;
    const CKA_LOCAL: number;
    const CKA_NEVER_EXTRACTABLE: number;
    const CKA_ALWAYS_SENSITIVE: number;
    const CKA_KEY_GEN_MECHANISM: number;
    const CKA_MODIFIABLE: number;
    const CKA_COPYABLE: number;
    const CKA_DESTROYABLE: number;
    const CKA_ECDSA_PARAMS: number;
    const CKA_EC_PARAMS: number;
    const CKA_EC_POINT: number;
    const CKA_SECONDARY_AUTH: number;
    const CKA_AUTH_PIN_FLAGS: number;
    const CKA_ALWAYS_AUTHENTICATE: number;
    const CKA_WRAP_WITH_TRUSTED: number;
    const CKA_WRAP_TEMPLATE: number;
    const CKA_UNWRAP_TEMPLATE: number;
    const CKA_DERIVE_TEMPLATE: number;
    const CKA_OTP_FORMAT: number;
    const CKA_OTP_LENGTH: number;
    const CKA_OTP_TIME_INTERVAL: number;
    const CKA_OTP_USER_FRIENDLY_MODE: number;
    const CKA_OTP_CHALLENGE_REQUIREMENT: number;
    const CKA_OTP_TIME_REQUIREMENT: number;
    const CKA_OTP_COUNTER_REQUIREMENT: number;
    const CKA_OTP_PIN_REQUIREMENT: number;
    const CKA_OTP_COUNTER: number;
    const CKA_OTP_TIME: number;
    const CKA_OTP_USER_IDENTIFIER: number;
    const CKA_OTP_SERVICE_IDENTIFIER: number;
    const CKA_OTP_SERVICE_LOGO: number;
    const CKA_OTP_SERVICE_LOGO_TYPE: number;
    const CKA_GOSTR3410_PARAMS: number;
    const CKA_GOSTR3411_PARAMS: number;
    const CKA_GOST28147_PARAMS: number;
    const CKA_HW_FEATURE_TYPE: number;
    const CKA_RESET_ON_INIT: number;
    const CKA_HAS_RESET: number;
    const CKA_PIXEL_X: number;
    const CKA_PIXEL_Y: number;
    const CKA_RESOLUTION: number;
    const CKA_CHAR_ROWS: number;
    const CKA_CHAR_COLUMNS: number;
    const CKA_COLOR: number;
    const CKA_BITS_PER_PIXEL: number;
    const CKA_CHAR_SETS: number;
    const CKA_ENCODING_METHODS: number;
    const CKA_MIME_TYPES: number;
    const CKA_MECHANISM_TYPE: number;
    const CKA_REQUIRED_CMS_ATTRIBUTES: number;
    const CKA_DEFAULT_CMS_ATTRIBUTES: number;
    const CKA_SUPPORTED_CMS_ATTRIBUTES: number;
    const CKA_ALLOWED_MECHANISMS: number;
    const CKA_VENDOR_DEFINED: number;
    //#endregion

    //#region Objects
    const CKO_DATA: number;
    const CKO_CERTIFICATE: number;
    const CKO_PUBLIC_KEY: number;
    const CKO_PRIVATE_KEY: number;
    const CKO_SECRET_KEY: number;
    const CKO_HW_FEATURE: number;
    const CKO_DOMAIN_PARAMETERS: number;
    const CKO_MECHANISM: number;
    const CKO_OTP_KEY: number;
    const CKO_VENDOR_DEFINED: number;
    //#endregion

    //#region Key types
    const CKK_RSA: number;
    const CKK_DSA: number;
    const CKK_DH: number;
    const CKK_ECDSA: number;
    const CKK_EC: number;
    const CKK_X9_42_DH: number;
    const CKK_KEA: number;
    const CKK_GENERIC_SECRET: number;
    const CKK_RC2: number;
    const CKK_RC4: number;
    const CKK_DES: number;
    const CKK_DES2: number;
    const CKK_DES3: number;
    const CKK_CAST: number;
    const CKK_CAST3: number;
    const CKK_CAST5: number;
    const CKK_CAST128: number;
    const CKK_RC5: number;
    const CKK_IDEA: number;
    const CKK_SKIPJACK: number;
    const CKK_BATON: number;
    const CKK_JUNIPER: number;
    const CKK_CDMF: number;
    const CKK_AES: number;
    const CKK_BLOWFISH: number;
    const CKK_TWOFISH: number;
    const CKK_SECURID: number;
    const CKK_HOTP: number;
    const CKK_ACTI: number;
    const CKK_CAMELLIA: number;
    const CKK_ARIA: number;
    const CKK_MD5_HMAC: number;
    const CKK_SHA_1_HMAC: number;
    const CKK_RIPEMD128_HMAC: number;
    const CKK_RIPEMD160_HMAC: number;
    const CKK_SHA256_HMAC: number;
    const CKK_SHA384_HMAC: number;
    const CKK_SHA512_HMAC: number;
    const CKK_SHA224_HMAC: number;
    const CKK_SEED: number;
    const CKK_GOSTR3410: number;
    const CKK_GOSTR3411: number;
    const CKK_GOST28147: number;
    const CKK_VENDOR_DEFINED: number;
    //#endregion

    //#region Mechanisms
    const CKM_RSA_PKCS_KEY_PAIR_GEN: number;
    const CKM_RSA_PKCS: number;
    const CKM_RSA_9796: number;
    const CKM_RSA_X_509: number;
    const CKM_MD2_RSA_PKCS: number;
    const CKM_MD5_RSA_PKCS: number;
    const CKM_SHA1_RSA_PKCS: number;
    const CKM_RIPEMD128_RSA_PKCS: number;
    const CKM_RIPEMD160_RSA_PKCS: number;
    const CKM_RSA_PKCS_OAEP: number;
    const CKM_RSA_X9_31_KEY_PAIR_GEN: number;
    const CKM_RSA_X9_31: number;
    const CKM_SHA1_RSA_X9_31: number;
    const CKM_RSA_PKCS_PSS: number;
    const CKM_SHA1_RSA_PKCS_PSS: number;
    const CKM_DSA_KEY_PAIR_GEN: number;
    const CKM_DSA: number;
    const CKM_DSA_SHA1: number;
    const CKM_DSA_SHA224: number;
    const CKM_DSA_SHA256: number;
    const CKM_DSA_SHA384: number;
    const CKM_DSA_SHA512: number;
    const CKM_DH_PKCS_KEY_PAIR_GEN: number;
    const CKM_DH_PKCS_DERIVE: number;
    const CKM_X9_42_DH_KEY_PAIR_GEN: number;
    const CKM_X9_42_DH_DERIVE: number;
    const CKM_X9_42_DH_HYBRID_DERIVE: number;
    const CKM_X9_42_MQV_DERIVE: number;
    const CKM_SHA256_RSA_PKCS: number;
    const CKM_SHA384_RSA_PKCS: number;
    const CKM_SHA512_RSA_PKCS: number;
    const CKM_SHA256_RSA_PKCS_PSS: number;
    const CKM_SHA384_RSA_PKCS_PSS: number;
    const CKM_SHA512_RSA_PKCS_PSS: number;
    const CKM_SHA224_RSA_PKCS: number;
    const CKM_SHA224_RSA_PKCS_PSS: number;
    const CKM_RC2_KEY_GEN: number;
    const CKM_RC2_ECB: number;
    const CKM_RC2_CBC: number;
    const CKM_RC2_MAC: number;
    const CKM_RC2_MAC_GENERAL: number;
    const CKM_RC2_CBC_PAD: number;
    const CKM_RC4_KEY_GEN: number;
    const CKM_RC4: number;
    const CKM_DES_KEY_GEN: number;
    const CKM_DES_ECB: number;
    const CKM_DES_CBC: number;
    const CKM_DES_MAC: number;
    const CKM_DES_MAC_GENERAL: number;
    const CKM_DES_CBC_PAD: number;
    const CKM_DES2_KEY_GEN: number;
    const CKM_DES3_KEY_GEN: number;
    const CKM_DES3_ECB: number;
    const CKM_DES3_CBC: number;
    const CKM_DES3_MAC: number;
    const CKM_DES3_MAC_GENERAL: number;
    const CKM_DES3_CBC_PAD: number;
    const CKM_DES3_CMAC_GENERAL: number;
    const CKM_DES3_CMAC: number;
    const CKM_CDMF_KEY_GEN: number;
    const CKM_CDMF_ECB: number;
    const CKM_CDMF_CBC: number;
    const CKM_CDMF_MAC: number;
    const CKM_CDMF_MAC_GENERAL: number;
    const CKM_CDMF_CBC_PAD: number;
    const CKM_DES_OFB64: number;
    const CKM_DES_OFB8: number;
    const CKM_DES_CFB64: number;
    const CKM_DES_CFB8: number;
    const CKM_MD2: number;
    const CKM_MD2_HMAC: number;
    const CKM_MD2_HMAC_GENERAL: number;
    const CKM_MD5: number;
    const CKM_MD5_HMAC: number;
    const CKM_MD5_HMAC_GENERAL: number;
    const CKM_SHA_1: number;
    const CKM_SHA_1_HMAC: number;
    const CKM_SHA_1_HMAC_GENERAL: number;
    const CKM_RIPEMD128: number;
    const CKM_RIPEMD128_HMAC: number;
    const CKM_RIPEMD128_HMAC_GENERAL: number;
    const CKM_RIPEMD160: number;
    const CKM_RIPEMD160_HMAC: number;
    const CKM_RIPEMD160_HMAC_GENERAL: number;
    const CKM_SHA256: number;
    const CKM_SHA256_HMAC: number;
    const CKM_SHA256_HMAC_GENERAL: number;
    const CKM_SHA224: number;
    const CKM_SHA224_HMAC: number;
    const CKM_SHA224_HMAC_GENERAL: number;
    const CKM_SHA384: number;
    const CKM_SHA384_HMAC: number;
    const CKM_SHA384_HMAC_GENERAL: number;
    const CKM_SHA512: number;
    const CKM_SHA512_HMAC: number;
    const CKM_SHA512_HMAC_GENERAL: number;
    const CKM_SECURID_KEY_GEN: number;
    const CKM_SECURID: number;
    const CKM_HOTP_KEY_GEN: number;
    const CKM_HOTP: number;
    const CKM_ACTI: number;
    const CKM_ACTI_KEY_GEN: number;
    const CKM_CAST_KEY_GEN: number;
    const CKM_CAST_ECB: number;
    const CKM_CAST_CBC: number;
    const CKM_CAST_MAC: number;
    const CKM_CAST_MAC_GENERAL: number;
    const CKM_CAST_CBC_PAD: number;
    const CKM_CAST3_KEY_GEN: number;
    const CKM_CAST3_ECB: number;
    const CKM_CAST3_CBC: number;
    const CKM_CAST3_MAC: number;
    const CKM_CAST3_MAC_GENERAL: number;
    const CKM_CAST3_CBC_PAD: number;
    const CKM_CAST5_KEY_GEN: number;
    const CKM_CAST128_KEY_GEN: number;
    const CKM_CAST5_ECB: number;
    const CKM_CAST128_ECB: number;
    const CKM_CAST5_CBC: number;
    const CKM_CAST128_CBC: number;
    const CKM_CAST5_MAC: number;
    const CKM_CAST128_MAC: number;
    const CKM_CAST5_MAC_GENERAL: number;
    const CKM_CAST128_MAC_GENERAL: number;
    const CKM_CAST5_CBC_PAD: number;
    const CKM_CAST128_CBC_PAD: number;
    const CKM_RC5_KEY_GEN: number;
    const CKM_RC5_ECB: number;
    const CKM_RC5_CBC: number;
    const CKM_RC5_MAC: number;
    const CKM_RC5_MAC_GENERAL: number;
    const CKM_RC5_CBC_PAD: number;
    const CKM_IDEA_KEY_GEN: number;
    const CKM_IDEA_ECB: number;
    const CKM_IDEA_CBC: number;
    const CKM_IDEA_MAC: number;
    const CKM_IDEA_MAC_GENERAL: number;
    const CKM_IDEA_CBC_PAD: number;
    const CKM_GENERIC_SECRET_KEY_GEN: number;
    const CKM_CONCATENATE_BASE_AND_KEY: number;
    const CKM_CONCATENATE_BASE_AND_DATA: number;
    const CKM_CONCATENATE_DATA_AND_BASE: number;
    const CKM_XOR_BASE_AND_DATA: number;
    const CKM_EXTRACT_KEY_FROM_KEY: number;
    const CKM_SSL3_PRE_MASTER_KEY_GEN: number;
    const CKM_SSL3_MASTER_KEY_DERIVE: number;
    const CKM_SSL3_KEY_AND_MAC_DERIVE: number;
    const CKM_SSL3_MASTER_KEY_DERIVE_DH: number;
    const CKM_TLS_PRE_MASTER_KEY_GEN: number;
    const CKM_TLS_MASTER_KEY_DERIVE: number;
    const CKM_TLS_KEY_AND_MAC_DERIVE: number;
    const CKM_TLS_MASTER_KEY_DERIVE_DH: number;
    const CKM_TLS_PRF: number;
    const CKM_SSL3_MD5_MAC: number;
    const CKM_SSL3_SHA1_MAC: number;
    const CKM_MD5_KEY_DERIVATION: number;
    const CKM_MD2_KEY_DERIVATION: number;
    const CKM_SHA1_KEY_DERIVATION: number;
    const CKM_SHA256_KEY_DERIVATION: number;
    const CKM_SHA384_KEY_DERIVATION: number;
    const CKM_SHA512_KEY_DERIVATION: number;
    const CKM_SHA224_KEY_DERIVATION: number;
    const CKM_PBE_MD2_DES_CBC: number;
    const CKM_PBE_MD5_DES_CBC: number;
    const CKM_PBE_MD5_CAST_CBC: number;
    const CKM_PBE_MD5_CAST3_CBC: number;
    const CKM_PBE_MD5_CAST5_CBC: number;
    const CKM_PBE_MD5_CAST128_CBC: number;
    const CKM_PBE_SHA1_CAST5_CBC: number;
    const CKM_PBE_SHA1_CAST128_CBC: number;
    const CKM_PBE_SHA1_RC4_128: number;
    const CKM_PBE_SHA1_RC4_40: number;
    const CKM_PBE_SHA1_DES3_EDE_CBC: number;
    const CKM_PBE_SHA1_DES2_EDE_CBC: number;
    const CKM_PBE_SHA1_RC2_128_CBC: number;
    const CKM_PBE_SHA1_RC2_40_CBC: number;
    const CKM_PKCS5_PBKD2: number;
    const CKM_PBA_SHA1_WITH_SHA1_HMAC: number;
    const CKM_WTLS_PRE_MASTER_KEY_GEN: number;
    const CKM_WTLS_MASTER_KEY_DERIVE: number;
    const CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC: number;
    const CKM_WTLS_PRF: number;
    const CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE: number;
    const CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE: number;
    const CKM_KEY_WRAP_LYNKS: number;
    const CKM_KEY_WRAP_SET_OAEP: number;
    const CKM_CAMELLIA_KEY_GEN: number;
    const CKM_CAMELLIA_ECB: number;
    const CKM_CAMELLIA_CBC: number;
    const CKM_CAMELLIA_MAC: number;
    const CKM_CAMELLIA_MAC_GENERAL: number;
    const CKM_CAMELLIA_CBC_PAD: number;
    const CKM_CAMELLIA_ECB_ENCRYPT_DATA: number;
    const CKM_CAMELLIA_CBC_ENCRYPT_DATA: number;
    const CKM_CAMELLIA_CTR: number;
    const CKM_ARIA_KEY_GEN: number;
    const CKM_ARIA_ECB: number;
    const CKM_ARIA_CBC: number;
    const CKM_ARIA_MAC: number;
    const CKM_ARIA_MAC_GENERAL: number;
    const CKM_ARIA_CBC_PAD: number;
    const CKM_ARIA_ECB_ENCRYPT_DATA: number;
    const CKM_ARIA_CBC_ENCRYPT_DATA: number;
    const CKM_SEED_KEY_GEN: number;
    const CKM_SEED_ECB: number;
    const CKM_SEED_CBC: number;
    const CKM_SEED_MAC: number;
    const CKM_SEED_MAC_GENERAL: number;
    const CKM_SEED_CBC_PAD: number;
    const CKM_SEED_ECB_ENCRYPT_DATA: number;
    const CKM_SEED_CBC_ENCRYPT_DATA: number;
    const CKM_SKIPJACK_KEY_GEN: number;
    const CKM_SKIPJACK_ECB64: number;
    const CKM_SKIPJACK_CBC64: number;
    const CKM_SKIPJACK_OFB64: number;
    const CKM_SKIPJACK_CFB64: number;
    const CKM_SKIPJACK_CFB32: number;
    const CKM_SKIPJACK_CFB16: number;
    const CKM_SKIPJACK_CFB8: number;
    const CKM_SKIPJACK_WRAP: number;
    const CKM_SKIPJACK_PRIVATE_WRAP: number;
    const CKM_SKIPJACK_RELAYX: number;
    const CKM_KEA_KEY_PAIR_GEN: number;
    const CKM_KEA_KEY_DERIVE: number;
    const CKM_FORTEZZA_TIMESTAMP: number;
    const CKM_BATON_KEY_GEN: number;
    const CKM_BATON_ECB128: number;
    const CKM_BATON_ECB96: number;
    const CKM_BATON_CBC128: number;
    const CKM_BATON_COUNTER: number;
    const CKM_BATON_SHUFFLE: number;
    const CKM_BATON_WRAP: number;
    const CKM_ECDSA_KEY_PAIR_GEN: number;
    const CKM_EC_KEY_PAIR_GEN: number;
    const CKM_ECDSA: number;
    const CKM_ECDSA_SHA1: number;
    const CKM_ECDSA_SHA224: number;
    const CKM_ECDSA_SHA256: number;
    const CKM_ECDSA_SHA384: number;
    const CKM_ECDSA_SHA512: number;
    const CKM_ECDH1_DERIVE: number;
    const CKM_ECDH1_COFACTOR_DERIVE: number;
    const CKM_ECMQV_DERIVE: number;
    const CKM_JUNIPER_KEY_GEN: number;
    const CKM_JUNIPER_ECB128: number;
    const CKM_JUNIPER_CBC128: number;
    const CKM_JUNIPER_COUNTER: number;
    const CKM_JUNIPER_SHUFFLE: number;
    const CKM_JUNIPER_WRAP: number;
    const CKM_FASTHASH: number;
    const CKM_AES_KEY_GEN: number;
    const CKM_AES_ECB: number;
    const CKM_AES_CBC: number;
    const CKM_AES_MAC: number;
    const CKM_AES_MAC_GENERAL: number;
    const CKM_AES_CBC_PAD: number;
    const CKM_AES_CTR: number;
    const CKM_AES_CTS: number;
    const CKM_AES_CMAC: number;
    const CKM_AES_CMAC_GENERAL: number;
    const CKM_BLOWFISH_KEY_GEN: number;
    const CKM_BLOWFISH_CBC: number;
    const CKM_TWOFISH_KEY_GEN: number;
    const CKM_TWOFISH_CBC: number;
    const CKM_AES_GCM: number;
    const CKM_AES_CCM: number;
    const CKM_AES_KEY_WRAP: number;
    const CKM_AES_KEY_WRAP_PAD: number;
    const CKM_BLOWFISH_CBC_PAD: number;
    const CKM_TWOFISH_CBC_PAD: number;
    const CKM_DES_ECB_ENCRYPT_DATA: number;
    const CKM_DES_CBC_ENCRYPT_DATA: number;
    const CKM_DES3_ECB_ENCRYPT_DATA: number;
    const CKM_DES3_CBC_ENCRYPT_DATA: number;
    const CKM_AES_ECB_ENCRYPT_DATA: number;
    const CKM_AES_CBC_ENCRYPT_DATA: number;
    const CKM_GOSTR3410_KEY_PAIR_GEN: number;
    const CKM_GOSTR3410: number;
    const CKM_GOSTR3410_WITH_GOSTR3411: number;
    const CKM_GOSTR3410_KEY_WRAP: number;
    const CKM_GOSTR3410_DERIVE: number;
    const CKM_GOSTR3411: number;
    const CKM_GOSTR3411_HMAC: number;
    const CKM_GOST28147_KEY_GEN: number;
    const CKM_GOST28147_ECB: number;
    const CKM_GOST28147: number;
    const CKM_GOST28147_MAC: number;
    const CKM_GOST28147_KEY_WRAP: number;
    const CKM_DSA_PARAMETER_GEN: number;
    const CKM_DH_PKCS_PARAMETER_GEN: number;
    const CKM_X9_42_DH_PARAMETER_GEN: number;
    const CKM_AES_OFB: number;
    const CKM_AES_CFB64: number;
    const CKM_AES_CFB8: number;
    const CKM_AES_CFB128: number;
    const CKM_RSA_PKCS_TPM_1_1: number;
    const CKM_RSA_PKCS_OAEP_TPM_1_1: number;
    const CKM_VENDOR_DEFINED: number;
    //#endregion

    //#region Session flags
    const CKF_RW_SESSION: number;
    const CKF_SERIAL_SESSION: number;
    //#endregion

    //#region Follows
    const CKF_HW: number;
    const CKF_ENCRYPT: number;
    const CKF_DECRYPT: number;
    const CKF_DIGEST: number;
    const CKF_SIGN: number;
    const CKF_SIGN_RECOVER: number;
    const CKF_VERIFY: number;
    const CKF_VERIFY_RECOVER: number;
    const CKF_GENERATE: number;
    const CKF_GENERATE_KEY_PAIR: number;
    const CKF_WRAP: number;
    const CKF_UNWRAP: number;
    const CKF_DERIVE: number;
    //#endregion

    //#region Token Information Flags
    const CKF_RNG: number;
    const CKF_WRITE_PROTECTED: number;
    const CKF_LOGIN_REQUIRED: number;
    const CKF_USER_PIN_INITIALIZED: number;
    const CKF_RESTORE_KEY_NOT_NEEDED: number;
    const CKF_CLOCK_ON_TOKEN: number;
    const CKF_PROTECTED_AUTHENTICATION_PATH: number;
    const CKF_DUAL_CRYPTO_OPERATIONS: number;
    const CKF_TOKEN_INITIALIZED: number;
    const CKF_SECONDARY_AUTHENTICATION: number;
    const CKF_USER_PIN_COUNT_LOW: number;
    const CKF_USER_PIN_FINAL_TRY: number;
    const CKF_USER_PIN_LOCKED: number;
    const CKF_USER_PIN_TO_BE_CHANGED: number;
    const CKF_SO_PIN_COUNT_LOW: number;
    const CKF_SO_PIN_FINAL_TRY: number;
    const CKF_SO_PIN_LOCKED: number;
    const CKF_SO_PIN_TO_BE_CHANGED: number;
    const CKF_ERROR_STATE: number;
    //#endregion

    //#region Certificates
    const CKC_X_509: number;
    const CKC_X_509_ATTR_CERT: number;
    const CKC_WTLS: number;
    //#endregion

    //#region MGFs
    const CKG_MGF1_SHA1: number;
    const CKG_MGF1_SHA256: number;
    const CKG_MGF1_SHA384: number;
    const CKG_MGF1_SHA512: number;
    const CKG_MGF1_SHA224: number;
    //#endregion

    //#region KDFs
    const CKD_NULL: number;
    const CKD_SHA1_KDF: number;
    const CKD_SHA1_KDF_ASN1: number;
    const CKD_SHA1_KDF_CONCATENATE: number;
    const CKD_SHA224_KDF: number;
    const CKD_SHA256_KDF: number;
    const CKD_SHA384_KDF: number;
    const CKD_SHA512_KDF: number;
    const CKD_CPDIVERSIFY_KDF: number;
    //#endregion

    //#region Mech params
    const CK_PARAMS_AES_CBC: number;
    const CK_PARAMS_AES_CCM: number;
    const CK_PARAMS_AES_GCM: number;
    const CK_PARAMS_RSA_OAEP: number;
    const CK_PARAMS_RSA_PSS: number;
    const CK_PARAMS_EC_DH: number;
    const CK_PARAMS_AES_GCM_v240: number;
    //#endregion

    //#region User types
    const CKU_SO: number;
    const CKU_USER: number;
    const CKU_CONTEXT_SPECIFIC: number;
    //#endregion

    // Initialize flags
    const CKF_LIBRARY_CANT_CREATE_OS_THREADS: number;
    const CKF_OS_LOCKING_OK: number;

    //#region Result values
    const CKR_OK: number;
    const CKR_CANCEL: number;
    const CKR_HOST_MEMORY: number;
    const CKR_SLOT_ID_INVALID: number;
    const CKR_GENERAL_ERROR: number;
    const CKR_FUNCTION_FAILED: number;
    const CKR_ARGUMENTS_BAD: number;
    const CKR_NO_EVENT: number;
    const CKR_NEED_TO_CREATE_THREADS: number;
    const CKR_CANT_LOCK: number;
    const CKR_ATTRIBUTE_READ_ONLY: number;
    const CKR_ATTRIBUTE_SENSITIVE: number;
    const CKR_ATTRIBUTE_TYPE_INVALID: number;
    const CKR_ATTRIBUTE_VALUE_INVALID: number;
    const CKR_DATA_INVALID: number;
    const CKR_DATA_LEN_RANGE: number;
    const CKR_DEVICE_ERROR: number;
    const CKR_DEVICE_MEMORY: number;
    const CKR_DEVICE_REMOVED: number;
    const CKR_ENCRYPTED_DATA_INVALID: number;
    const CKR_ENCRYPTED_DATA_LEN_RANGE: number;
    const CKR_FUNCTION_CANCELED: number;
    const CKR_FUNCTION_NOT_PARALLEL: number;
    const CKR_FUNCTION_NOT_SUPPORTED: number;
    const CKR_KEY_HANDLE_INVALID: number;
    const CKR_KEY_SIZE_RANGE: number;
    const CKR_KEY_TYPE_INCONSISTENT: number;
    const CKR_KEY_NOT_NEEDED: number;
    const CKR_KEY_CHANGED: number;
    const CKR_KEY_NEEDED: number;
    const CKR_KEY_INDIGESTIBLE: number;
    const CKR_KEY_FUNCTION_NOT_PERMITTED: number;
    const CKR_KEY_NOT_WRAPPABLE: number;
    const CKR_KEY_UNEXTRACTABLE: number;
    const CKR_MECHANISM_INVALID: number;
    const CKR_MECHANISM_PARAM_INVALID: number;
    const CKR_OBJECT_HANDLE_INVALID: number;
    const CKR_OPERATION_ACTIVE: number;
    const CKR_OPERATION_NOT_INITIALIZED: number;
    const CKR_PIN_INCORRECT: number;
    const CKR_PIN_INVALID: number;
    const CKR_PIN_LEN_RANGE: number;
    const CKR_PIN_EXPIRED: number;
    const CKR_PIN_LOCKED: number;
    const CKR_SESSION_CLOSED: number;
    const CKR_SESSION_COUNT: number;
    const CKR_SESSION_HANDLE_INVALID: number;
    const CKR_SESSION_PARALLEL_NOT_SUPPORTED: number;
    const CKR_SESSION_READ_ONLY: number;
    const CKR_SESSION_EXISTS: number;
    const CKR_SESSION_READ_ONLY_EXISTS: number;
    const CKR_SESSION_READ_WRITE_SO_EXISTS: number;
    const CKR_SIGNATURE_INVALID: number;
    const CKR_SIGNATURE_LEN_RANGE: number;
    const CKR_TEMPLATE_INCOMPLETE: number;
    const CKR_TEMPLATE_INCONSISTENT: number;
    const CKR_TOKEN_NOT_PRESENT: number;
    const CKR_TOKEN_NOT_RECOGNIZED: number;
    const CKR_TOKEN_WRITE_PROTECTED: number;
    const CKR_UNWRAPPING_KEY_HANDLE_INVALID: number;
    const CKR_UNWRAPPING_KEY_SIZE_RANGE: number;
    const CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: number;
    const CKR_USER_ALREADY_LOGGED_IN: number;
    const CKR_USER_NOT_LOGGED_IN: number;
    const CKR_USER_PIN_NOT_INITIALIZED: number;
    const CKR_USER_TYPE_INVALID: number;
    const CKR_USER_ANOTHER_ALREADY_LOGGED_IN: number;
    const CKR_USER_TOO_MANY_TYPES: number;
    const CKR_WRAPPED_KEY_INVALID: number;
    const CKR_WRAPPED_KEY_LEN_RANGE: number;
    const CKR_WRAPPING_KEY_HANDLE_INVALID: number;
    const CKR_WRAPPING_KEY_SIZE_RANGE: number;
    const CKR_WRAPPING_KEY_TYPE_INCONSISTENT: number;
    const CKR_RANDOM_SEED_NOT_SUPPORTED: number;
    const CKR_RANDOM_NO_RNG: number;
    const CKR_DOMAIN_PARAMS_INVALID: number;
    const CKR_BUFFER_TOO_SMALL: number;
    const CKR_SAVED_STATE_INVALID: number;
    const CKR_INFORMATION_SENSITIVE: number;
    const CKR_STATE_UNSAVEABLE: number;
    const CKR_CRYPTOKI_NOT_INITIALIZED: number;
    const CKR_CRYPTOKI_ALREADY_INITIALIZED: number;
    const CKR_MUTEX_BAD: number;
    const CKR_MUTEX_NOT_LOCKED: number;
    const CKR_NEW_PIN_MODE: number;
    const CKR_NEXT_OTP: number;
    const CKR_EXCEEDED_MAX_ITERATIONS: number;
    const CKR_FIPS_SELF_TEST_FAILED: number;
    const CKR_LIBRARY_LOAD_FAILED: number;
    const CKR_PIN_TOO_WEAK: number;
    const CKR_PUBLIC_KEY_INVALID: number;
    const CKR_FUNCTION_REJECTED: number;
    //#endregion

    /**
     * Exception from native module
     */
    class NativeError extends Error {
        /**
         * Native library call stack. Default is empty string
         */
        public readonly nativeStack: string;
        /**
         * Native function name. Default is empty string
         */
        public readonly method: string;
        /**
         * Initialize new instance of NativeError
         * @param message Error message
         */
        public constructor(message?: string, method?: string);
    }

    /**
     * Exception with the name and value of PKCS#11 return value
     */
    class Pkcs11Error extends NativeError {
        /**
         * PKCS#11 result value. Default is 0
         */
        public readonly code: number;
        /**
         * Initialize new instance of Pkcs11Error
         * @param message Error message
         * @param code PKCS#11 result value
         * @param method The name of PKCS#11 method
         */
        public constructor(message?: string, code?: number, method?: string);
    }
}
