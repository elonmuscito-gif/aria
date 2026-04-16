declare module "shamirs-secret-sharing" {
  export function split(
    secret: Buffer | Uint8Array,
    options: { shares: number; threshold: number },
  ): Uint8Array[];
  export function combine(shares: (Buffer | Uint8Array)[]): Buffer;
}
