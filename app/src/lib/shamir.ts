function mul(a: number, b: number): number {
  let product = 0;
  while (b > 0) {
    if (b & 1) product ^= a;
    a = a & 0x80 ? ((a << 1) ^ 0x1b) & 0xff : a << 1;
    b >>= 1;
  }
  return product;
}

export function split(
  secret: Uint8Array,
  holders: number,
): Uint8Array<ArrayBuffer>[] {
  if (secret.length === 0) throw new Error("The token is empty.");
  if (!Number.isInteger(holders) || holders < 1 || holders > 255) {
    throw new Error("Pieces go to 1 to 255 servers.");
  }
  if (holders === 1) {
    const whole = new Uint8Array(secret.length + 1);
    whole.set(secret, 1);
    return [whole];
  }
  const slope = crypto.getRandomValues(new Uint8Array(secret.length));
  return Array.from({ length: holders }, (_, index) => {
    const x = index + 1;
    const piece = new Uint8Array(secret.length + 1);
    piece[0] = x;
    secret.forEach((value, j) => {
      piece[j + 1] = value ^ mul(slope[j]!, x);
    });
    return piece;
  });
}
