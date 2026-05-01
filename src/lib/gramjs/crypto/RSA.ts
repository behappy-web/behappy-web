import {
  generateRandomBytes,
  modExp,
  readBigIntFromBuffer,
  readBufferFromBigInt,
  sha1,
} from '../Helpers';

export const SERVER_KEYS = [
  // MVSy (BeHappy) server RSA key
  {
    fingerprint: BigInt('523366621625352527'),
    n: BigInt(
      '2467323679040943146778580913691379766544838275878881122178747329910005960097295644272671758317501578'
      + '9768814884139905858027931341305252039627783855033105309327755386410876629280315807984737870011790002'
      + '1297015910436829816525532932630046918643295491289758322334598113245129503891089264296960465546151495'
      + '0177083858834227823671199954434373862002068959049452202434427716213285660500130618074269453335832728'
      + '1132991400010270404046246328070176141057359058412562601391662916753948229434150736487282197648672049'
      + '3310309739115496497350122161094278037756476231415168706942730085460361145163847174524077244551820451'
      + '50543161306876549',
    ),
    e: 65537,
  },
].reduce((acc, { fingerprint, ...keyInfo }) => {
  acc.set(fingerprint, keyInfo);
  return acc;
}, new Map<bigint, { n: bigint; e: number }>());

/**
 * Encrypts the given data known the fingerprint to be used
 * in the way Telegram requires us to do so (sha1(data) + data + padding)

 * @param fingerprint the fingerprint of the RSA key.
 * @param data the data to be encrypted.
 * @returns {Buffer|*|undefined} the cipher text, or undefined if no key matching this fingerprint is found.
 */
export async function encrypt(fingerprint: bigint, data: Buffer) {
  const key = SERVER_KEYS.get(fingerprint);
  if (!key) {
    return undefined;
  }

  // len(sha1.digest) is always 20, so we're left with 255 - 20 - x padding
  const rand = generateRandomBytes(235 - data.length);

  const toEncrypt = Buffer.concat([await sha1(data), data, rand]);

  // rsa module rsa.encrypt adds 11 bits for padding which we don't want
  // rsa module uses rsa.transform.bytes2int(to_encrypt), easier way:
  const payload = readBigIntFromBuffer(toEncrypt, false);
  const encrypted = modExp(payload, BigInt(key.e), key.n);
  // rsa module uses transform.int2bytes(encrypted, keylength), easier:
  return readBufferFromBigInt(encrypted, 256, false);
}
