declare interface Status {
  trusted: boolean,
  message: string
}

export function verifyTrust(filePath: string): Promise<Status>;
export function isSigned(filePath: string): Promise<boolean>;