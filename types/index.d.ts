declare interface IStatus {
  signed: boolean,
  message: string
}

export function isSignedVerbose(filePath: string): Promise<IStatus>;
export function isSigned(filePath: string): Promise<boolean>;
export function trustStatus(filePath: string): Promise<string>;