export function verifyTrust(filePath: string): Promise<{
    trusted: boolean;
    message: string;
}>;
export function isSigned(filePath: string): Promise<boolean>;
