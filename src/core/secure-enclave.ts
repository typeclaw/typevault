import { dlopen, FFIType, type Pointer, ptr, read, toArrayBuffer } from 'bun:ffi'
import { copyFileSync, existsSync, renameSync, rmSync, statSync, utimesSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'

import { z } from 'zod'

import { fromBase64, toBase64 } from './encoding'
import { TypeVaultError } from './errors'
import { ensureDir } from './fsx'
import { configDir } from './layout'

type Env = Readonly<Record<string, string | undefined>>

/**
 * A P-256 key in this Mac's Secure Enclave that works only after Touch ID, through Security.framework. The private key
 * never leaves the chip: `handle` is the enclave's own encrypted reference to it, safe to keep in a file. Loading it
 * back uses the token object ID attribute (`toid`), the private attribute CryptoKit's SecureEnclave keys are built on.
 * macOS only: nothing is loaded until a function here is called.
 */
export type EnclaveKey = { readonly handle: Uint8Array; readonly publicKey: Uint8Array }

const SECURITY = '/System/Library/Frameworks/Security.framework/Security'
const CORE_FOUNDATION = '/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation'
const LOCAL_AUTHENTICATION = '/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication'
const LIBOBJC = '/usr/lib/libobjc.A.dylib'
const RTLD_NOW = 2
const UTF8 = 0x08000100
const CF_NUMBER_SINT32 = 3
const ACCESS_PRIVATE_KEY_USAGE = 1 << 30
const ACCESS_BIOMETRY_CURRENT_SET = 1 << 3
const TOKEN_OBJECT_ID = 'toid'
/** errSecUserCanceled and LAErrorUserCancel / LAErrorSystemCancel / LAErrorAppCancel. */
const CANCELLED = new Set([-128, -2, -4, -9])

/** Creates a new enclave key that needs Touch ID (with the fingerprints enrolled now) for every use. */
export function createEnclaveKey(): EnclaveKey {
  requireMac()
  const { cf, sec } = frameworks()
  const key = check(sec.SecKeyCreateRandomKey(enclaveAttributes([]), errorOut()), 'create a Secure Enclave key')
  const attributes = check(sec.SecKeyCopyAttributes(key), 'read the Secure Enclave key')
  const handle = check(cf.CFDictionaryGetValue(attributes, cfString(TOKEN_OBJECT_ID)), 'read the Secure Enclave key')
  return { handle: dataBytes(handle), publicKey: publicKeyBytes(key) }
}

const ENCLAVE_MODULE = import.meta.path

/**
 * The Touch ID dialog is titled with the code-signing identifier of the program asking, which under npm is `bun`. So
 * the exchange runs in a child started from a copy of this bun re-signed (ad hoc) as `typevault`; where no such copy
 * can be made, it runs here and the dialog says bun.
 */
export async function exchangeWithEnclave(
  env: Env,
  handle: Uint8Array,
  ephemeral: Uint8Array,
  reason: string,
): Promise<Uint8Array> {
  requireMac()
  const runner = await typevaultSignedRuntime(env)
  if (runner === undefined) return exchangeHere(handle, ephemeral, reason)
  const request = JSON.stringify({ handle: toBase64(handle), peer: toBase64(ephemeral), reason })
  const child = Bun.spawn([runner, ENCLAVE_MODULE], {
    env: { ...process.env },
    stdin: new Blob([request]),
    stdout: 'pipe',
    stderr: 'pipe',
  })
  const [out, err, code] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ])
  if (code !== 0) {
    const message = err.trim().replace(/^denied: /, '')
    throw new TypeVaultError('denied', message === '' ? 'Touch ID failed' : message)
  }
  return fromBase64(out.trim())
}

/**
 * The copy keeps the source's mtime (to the millisecond, as far as `utimes` takes it), so a bun upgrade (new mtime) or
 * an old hard link (same inode) is replaced. Each call signs its own temporary copy, so overlapping calls never publish
 * a file another call is still signing.
 */
export async function typevaultSignedRuntime(env: Env, source = process.execPath): Promise<string | undefined> {
  if (basename(source) === 'typevault') return undefined
  const runtime = join(configDir(env), 'bin', 'typevault')
  try {
    const original = statSync(source)
    if (existsSync(runtime)) {
      const current = statSync(runtime)
      if (current.ino !== original.ino && Math.trunc(current.mtimeMs) === Math.trunc(original.mtimeMs)) return runtime
    }
    ensureDir(dirname(runtime), 0o700)
    const pending = `${runtime}.${crypto.randomUUID()}`
    copyFileSync(source, pending)
    const signing = Bun.spawn(
      [
        '/usr/bin/codesign',
        '--force',
        '--sign',
        '-',
        '--identifier',
        'typevault',
        '--preserve-metadata=entitlements,flags',
        pending,
      ],
      { stdout: 'ignore', stderr: 'ignore' },
    )
    if ((await signing.exited) !== 0) {
      rmSync(pending, { force: true })
      return undefined
    }
    utimesSync(pending, original.atime, original.mtime)
    renameSync(pending, runtime)
    return runtime
  } catch (error) {
    if (error instanceof Error && 'code' in error) return undefined
    throw error
  }
}

/** ECDH between the enclave key and `peerPublic` (uncompressed P-256): the shared x coordinate. Asks for Touch ID. */
function exchangeHere(handle: Uint8Array, peerPublic: Uint8Array, reason: string): Uint8Array {
  const { sec, constant } = frameworks()
  const key = check(
    sec.SecKeyCreateRandomKey(
      enclaveAttributes([[cfString(TOKEN_OBJECT_ID), cfData(handle)]], authenticationContext(reason)),
      errorOut(),
    ),
    'load the Secure Enclave key',
  )
  const peerAttributes = dictionary([
    [constant('kSecAttrKeyType'), constant('kSecAttrKeyTypeECSECPrimeRandom')],
    [constant('kSecAttrKeyClass'), constant('kSecAttrKeyClassPublic')],
    [constant('kSecAttrKeySizeInBits'), keySize()],
  ])
  const peer = check(sec.SecKeyCreateWithData(cfData(peerPublic), peerAttributes, errorOut()), 'read the peer key')
  const algorithm = constant('kSecKeyAlgorithmECDHKeyExchangeStandard')
  const shared = sec.SecKeyCopyKeyExchangeResult(key, algorithm, peer, dictionary([]), errorOut())
  return dataBytes(check(shared, 'use the Secure Enclave key'))
}

function requireMac(): void {
  if (process.platform !== 'darwin') throw new TypeVaultError('unavailable', 'Touch ID unlock needs macOS')
}

type Ref = Pointer | bigint
type Entry = readonly [Ref, Ref]

function enclaveAttributes(privateEntries: readonly Entry[], context?: Ref): Ref {
  const { sec, constant, coreConstant } = frameworks()
  const access = check(
    sec.SecAccessControlCreateWithFlags(
      null,
      constant('kSecAttrAccessibleWhenUnlockedThisDeviceOnly'),
      ACCESS_PRIVATE_KEY_USAGE | ACCESS_BIOMETRY_CURRENT_SET,
      errorOut(),
    ),
    'set up Touch ID access',
  )
  // Not permanent: the key never goes in the keychain, which would need an entitlement bun doesn't have.
  const privateAttributes = dictionary([
    [constant('kSecAttrIsPermanent'), coreConstant('kCFBooleanFalse')],
    [constant('kSecAttrAccessControl'), access],
    ...privateEntries,
  ])
  return dictionary([
    [constant('kSecAttrKeyType'), constant('kSecAttrKeyTypeECSECPrimeRandom')],
    [constant('kSecAttrKeySizeInBits'), keySize()],
    [constant('kSecAttrTokenID'), constant('kSecAttrTokenIDSecureEnclave')],
    [constant('kSecPrivateKeyAttrs'), privateAttributes],
    ...(context === undefined ? [] : [[constant('kSecUseAuthenticationContext'), context] as const]),
  ])
}

/** An LAContext whose reason the Touch ID dialog shows: "<app> is trying to <reason>." */
function authenticationContext(reason: string): Ref {
  const { objc, setObject } = frameworks()
  const allocated = objc.objc_msgSend(objc.objc_getClass(cstring('LAContext')), objc.sel_registerName(cstring('alloc')))
  const context = check(objc.objc_msgSend(allocated, objc.sel_registerName(cstring('init'))), 'set up Touch ID')
  setObject(context, objc.sel_registerName(cstring('setLocalizedReason:')), cfString(reason))
  return context
}

function publicKeyBytes(key: Ref): Uint8Array {
  const { sec } = frameworks()
  const publicKey = check(sec.SecKeyCopyPublicKey(key), 'read the Secure Enclave public key')
  return dataBytes(check(sec.SecKeyCopyExternalRepresentation(publicKey, errorOut()), 'read the public key'))
}

let lastError = new BigUint64Array(1)

function errorOut(): Ref {
  lastError = new BigUint64Array(1)
  return ptr(lastError)
}

function check(value: Ref | null, what: string): Ref {
  if (value !== null) return value
  const error = lastError[0] ?? 0n
  if (error === 0n) throw new TypeVaultError('unavailable', `could not ${what}`)
  const { cf } = frameworks()
  if (CANCELLED.has(Number(cf.CFErrorGetCode(error)))) throw new TypeVaultError('denied', 'Touch ID was cancelled')
  throw new TypeVaultError('denied', `could not ${what}: ${cfText(cf.CFErrorCopyDescription(error))}`)
}

function asPointer(ref: Ref): Pointer {
  if (typeof ref === 'bigint') throw new TypeVaultError('unavailable', 'a pointer out of range')
  return ref
}

const cstring = (text: string): Buffer => Buffer.from(`${text}\0`)

const cfString = (text: string): Ref =>
  check(frameworks().cf.CFStringCreateWithCString(null, cstring(text), UTF8), 'make a string')

function cfText(value: Ref | null): string {
  if (value === null) return 'unknown error'
  const buffer = Buffer.alloc(1024)
  return frameworks().cf.CFStringGetCString(value, buffer, buffer.length, UTF8)
    ? buffer.toString('utf8', 0, buffer.indexOf(0))
    : 'unknown error'
}

const cfData = (bytes: Uint8Array): Ref =>
  check(frameworks().cf.CFDataCreate(null, ptr(bytes), bytes.length), 'copy bytes')

function dataBytes(data: Ref): Uint8Array {
  const { cf } = frameworks()
  const length = Number(cf.CFDataGetLength(data))
  const start = check(cf.CFDataGetBytePtr(data), 'read bytes')
  return new Uint8Array(toArrayBuffer(asPointer(start), 0, length)).slice()
}

function keySize(): Ref {
  const bits = new Int32Array([256])
  return check(frameworks().cf.CFNumberCreate(null, CF_NUMBER_SINT32, ptr(bits)), 'make a number')
}

function dictionary(entries: readonly Entry[]): Ref {
  const { cf, dictionaryCallbacks } = frameworks()
  const dict = check(cf.CFDictionaryCreateMutable(null, 0, ...dictionaryCallbacks), 'make a dictionary')
  for (const [key, value] of entries) cf.CFDictionarySetValue(dict, key, value)
  return dict
}

type Frameworks = ReturnType<typeof load>
let loaded: Frameworks | undefined
const frameworks = (): Frameworks => (loaded ??= load())

function load() {
  const libSystem = dlopen('/usr/lib/libSystem.B.dylib', {
    dlopen: { args: [FFIType.cstring, FFIType.i32], returns: FFIType.ptr },
    dlsym: { args: [FFIType.ptr, FFIType.cstring], returns: FFIType.ptr },
  }).symbols
  const cf = dlopen(CORE_FOUNDATION, {
    CFStringCreateWithCString: { args: [FFIType.ptr, FFIType.cstring, FFIType.u32], returns: FFIType.ptr },
    CFStringGetCString: { args: [FFIType.ptr, FFIType.ptr, FFIType.i64, FFIType.u32], returns: FFIType.bool },
    CFDictionaryCreateMutable: { args: [FFIType.ptr, FFIType.i64, FFIType.ptr, FFIType.ptr], returns: FFIType.ptr },
    CFDictionarySetValue: { args: [FFIType.ptr, FFIType.ptr, FFIType.ptr], returns: FFIType.void },
    CFDictionaryGetValue: { args: [FFIType.ptr, FFIType.ptr], returns: FFIType.ptr },
    CFNumberCreate: { args: [FFIType.ptr, FFIType.i64, FFIType.ptr], returns: FFIType.ptr },
    CFDataCreate: { args: [FFIType.ptr, FFIType.ptr, FFIType.i64], returns: FFIType.ptr },
    CFDataGetLength: { args: [FFIType.ptr], returns: FFIType.i64 },
    CFDataGetBytePtr: { args: [FFIType.ptr], returns: FFIType.ptr },
    CFErrorGetCode: { args: [FFIType.ptr], returns: FFIType.i64 },
    CFErrorCopyDescription: { args: [FFIType.ptr], returns: FFIType.ptr },
  }).symbols
  const sec = dlopen(SECURITY, {
    SecAccessControlCreateWithFlags: {
      args: [FFIType.ptr, FFIType.ptr, FFIType.u64, FFIType.ptr],
      returns: FFIType.ptr,
    },
    SecKeyCreateRandomKey: { args: [FFIType.ptr, FFIType.ptr], returns: FFIType.ptr },
    SecKeyCreateWithData: { args: [FFIType.ptr, FFIType.ptr, FFIType.ptr], returns: FFIType.ptr },
    SecKeyCopyAttributes: { args: [FFIType.ptr], returns: FFIType.ptr },
    SecKeyCopyPublicKey: { args: [FFIType.ptr], returns: FFIType.ptr },
    SecKeyCopyExternalRepresentation: { args: [FFIType.ptr, FFIType.ptr], returns: FFIType.ptr },
    SecKeyCopyKeyExchangeResult: {
      args: [FFIType.ptr, FFIType.ptr, FFIType.ptr, FFIType.ptr, FFIType.ptr],
      returns: FFIType.ptr,
    },
  }).symbols
  const objc = dlopen(LIBOBJC, {
    objc_getClass: { args: [FFIType.cstring], returns: FFIType.ptr },
    sel_registerName: { args: [FFIType.cstring], returns: FFIType.ptr },
    objc_msgSend: { args: [FFIType.ptr, FFIType.ptr], returns: FFIType.ptr },
  }).symbols
  // objc_msgSend takes the signature of the method it calls, so a setter needs its own binding.
  const setObject = dlopen(LIBOBJC, {
    objc_msgSend: { args: [FFIType.ptr, FFIType.ptr, FFIType.ptr], returns: FFIType.void },
  }).symbols.objc_msgSend
  libSystem.dlopen(cstring(LOCAL_AUTHENTICATION), RTLD_NOW)
  const securityHandle = libSystem.dlopen(cstring(SECURITY), RTLD_NOW)
  const coreHandle = libSystem.dlopen(cstring(CORE_FOUNDATION), RTLD_NOW)
  const address = (handle: Ref | null, name: string): Ref => {
    const found = libSystem.dlsym(handle, cstring(name))
    if (found === null) throw new TypeVaultError('unavailable', `Security.framework has no ${name}`)
    return found
  }
  const valueAt = (at: Ref): Ref => read.u64(asPointer(at))
  return {
    cf,
    sec,
    objc,
    setObject,
    constant: (name: string): Ref => valueAt(address(securityHandle, name)),
    coreConstant: (name: string): Ref => valueAt(address(coreHandle, name)),
    dictionaryCallbacks: [
      address(coreHandle, 'kCFTypeDictionaryKeyCallBacks'),
      address(coreHandle, 'kCFTypeDictionaryValueCallBacks'),
    ] as const,
  }
}

const RequestSchema = z.object({ handle: z.string(), peer: z.string(), reason: z.string() })

// Run as its own process (see touch-id.ts) so the Touch ID dialog names the program that asks: reads one exchange
// request from stdin and prints the shared secret.
if (import.meta.main) {
  const request = RequestSchema.parse(JSON.parse(await Bun.stdin.text()))
  try {
    process.stdout.write(toBase64(exchangeHere(fromBase64(request.handle), fromBase64(request.peer), request.reason)))
  } catch (error) {
    if (!(error instanceof TypeVaultError)) throw error
    process.stderr.write(`${error.code}: ${error.message}\n`)
    process.exitCode = 1
  }
}
