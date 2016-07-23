declare module "pkcs11" {

    type Handle = number;

    interface Version {
        major: number;
        minor: number;
    }

    interface ModuleInfo {
        cryptokiVersion: Version;
        manufacturerID: string;
        flags: number;
        libraryDescription: string;
        libraryVersion: Version;
    }

    interface SlotInfo {
        slotDescription: string;
        manufacturerID: string;
        flags: number;
        hardwareVersion: Version;
        firmwareVersion: Version
    }

    interface TokenInfo {
        label: string;
        manufacturerID: string;
        model: string;
        serialNumber: string;
        flags: number;
        maxSessionCount: number;
        sessionCount: number;
        maxRwSessionCount: number;
        rwSessionCount: number;
        maxPinLen: number;
        minPinLen: number;
        hardwareVersion: Version;
        firmwareVersion: Version;
        utcTime: string
    }

    interface MechanismInfo {
        minKeySize: number;
        maxKeySize: number;
        flags: number;
    }

    interface SessionInfo {
        slotID: number;
        state: number;
        flags: number;
        deviceError: number;
    }

    type Template = Attribute[];

    interface Attribute {
        type: number;
        value?: number | boolean | string | Buffer; 
    }

    interface Mechanism {
        mechanism: number;
        parameter: Buffer | ECDH1;
    }

    interface ECDH1 {
        kdf: number;
        sharedData?: Buffer;
        publicData: Buffer;
    }

    interface KeyPair {
        privateKey: Handle,
        publicKey: Handle,
    }

    export class PKCS11 {
        load(path: string): void;
        C_Initialize(): void;
        C_Finalize(): void;
        C_GetInfo(): ModuleInfo;
        C_GetSlotList(tokenPresent?: boolean): Handle[];
        C_GetSlotInfo(slot: Handle): SlotInfo;
        C_GetTokenInfo(slot: Handle): TokenInfo;
        C_InitToken(slot: Handle, pin?: string): string;
        C_GetMechanismList(slot: Handle): void;
        C_GetMechanismInfo(slot: Handle, mech: Handle): MechanismInfo;
        C_OpenSession(slot: Handle, flags: number): Handle;
        C_CloseSession(session: Handle);
        C_CloseAllSessions(slot: Handle);
        C_GetSessionInfo(session: Handle): SessionInfo;
        C_InitPIN(session: Handle, pin?: string)
        C_SetPIN(session: Handle, oldPin: string, newPin: string);
        C_Login(session: Handle, userType: number, pin?: string);
        C_Logout(session: Handle);
        C_CreateObject(session: Handle, template: Template): Handle;
        C_CopyObject(session: Handle, object: Handle, template: Template);
        C_DestroyObject(session: Handle, object: Handle);
        C_GetObjectSize(session: Handle, object: Handle): number;
        C_FindObjectsInit(session: Handle, template: Template);
        C_FindObjects(session: Handle): Template;
        C_FindObjectsFinal(session: Handle);
        C_GetAttributeValue(session: Handle, object: Handle, template: Template): Template;
        C_SetAttributeValue(session: Handle, object: Handle, template: Template);
        C_EncryptInit(session: Handle, mechanism: Mechanism, key: Handle);
        // C_Encrypt(): Buffer;
        C_EncryptUpdate(session: Handle, inData: Buffer, outData: Buffer): Buffer;
        C_EncryptFinal(session: Handle, outData: Buffer): Buffer;
        C_DecryptInit(session: Handle, mechanism: Mechanism, key: Handle);
        // C_Decrypt(): Buffer;
        C_DecryptUpdate(session: Handle, inData: Buffer, outData: Buffer): Buffer;
        C_DecryptFinal(session: Handle, outData: Buffer): Buffer;
        C_DigestInit(session: Handle, mechanism: Mechanism);
        // C_Digest(): Buffer;
        C_DigestUpdate(session: Handle, inData: Buffer);
        C_DigestFinal(session: Handle, outData: Buffer): Buffer;
        // C_DigestKey();
        C_SignInit(session: Handle, mechanism: Mechanism, key: Handle);
        // C_Sign();
        C_SignUpdate(session: Handle, inData: Buffer);
        C_SignFinal(session: Handle, outData: Buffer): Buffer;
        // C_SignRecoverInit();
        // C_SignRecover();
        C_VerifyInit(session: Handle, mechanism: Mechanism, key: Handle);
        // C_Verify();
        C_VerifyUpdate(session: Handle, inData: Buffer);
        C_VerifyFinal(session: Handle, signature: Buffer);
        // C_VerifyRecoverInit();
        // C_VerifyRecover();
        C_GenerateKey(session: Handle, mechanism: Mechanism, template: Template): Handle;
        C_GenerateKeyPair(session: Handle, mechanism: Mechanism, publicTmpl: Template, privateTmpl: Template): KeyPair;
        // C_WrapKey();
        // C_UnwrapKey();
        C_DeriveKey(session: Handle, mechanism: Mechanism, template: Template, key: Handle): Handle;
        C_SeedRandom(session: Handle, buf: Buffer): Buffer;
        C_GenerateRandom(session: Handle, buf: Buffer): Buffer;
    }

}