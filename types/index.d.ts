export function verifyTrust(filePath: string): Promise<{
    trusted: boolean;
    message: string;
}>;

declare interface Certificate{
  issuer?: string,
  subject?: string
}

declare interface CertificateInfo{
  programName?: string,
  publisherLink?: string,
  infoLink?: string,
  signer: Certificate,
  timestamp?: Certificate
}

export function getCertificate(filePath: string): Promise<CertificateInfo>;
export function isSigned(filePath: string, name?: string | null): Promise<boolean>;
