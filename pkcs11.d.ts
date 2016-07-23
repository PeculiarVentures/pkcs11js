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

    export class PKCS11 {
        load(path: string): void;
        C_Initialize(): void;
        C_Finalize(): void;
        C_GetInfo(): ModuleInfo;
        C_GetSlotList(tokenPresent?: boolean): Handle[];
        C_GetSlotInfo(slot: Handle): SlotInfo;
        C_GetTokenInfo(slot: Handle): TokenInfo;
        C_GetMechanismList(slot: Handle): void;
        C_GetMechanismInfo(slot: Handle, mech: Handle): MechanismInfo;
        C_OpenSession(slot: Handle, flags: number): Handle;
        C_CloseSession(session: Handle);
        C_CloseAllSessions(slot: Handle);
        C_GetSessionInfo(session: Handle): SessionInfo;
    }

}