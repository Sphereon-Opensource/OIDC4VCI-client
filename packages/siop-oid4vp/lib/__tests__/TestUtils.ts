// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import crypto, { createHash } from 'crypto'

import { digest, ES256, generateSalt } from '@sd-jwt/crypto-nodejs'
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc'
import { JwtPayload, parseJWT, SigningAlgo, uuidv4 } from '@sphereon/oid4vc-common'
import { PartialSdJwtDecodedVerifiableCredential } from '@sphereon/pex/dist/main/lib'
import { IProofType, SdJwtVcKbJwtPayload } from '@sphereon/ssi-types'
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import base58 from 'bs58'
import { ethers } from 'ethers'
import { exportJWK, importJWK, JWK, SignJWT } from 'jose'
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import moment from 'moment'

import {
  assertValidMetadata,
  base64ToHexString,
  DiscoveryMetadataPayload,
  KeyCurve,
  KeyType,
  PresentationSignCallback,
  ResponseIss,
  ResponseType,
  RPRegistrationMetadataPayload,
  Scope,
  SubjectSyntaxTypesSupportedValues,
  SubjectType
} from '../'
import SIOPErrors from '../types/Errors'

import { DIDDocument } from './ResolverTestUtils'
import {
  DID_DOCUMENT_PUBKEY_B58,
  DID_DOCUMENT_PUBKEY_JWK,
  VERIFIER_LOGO_FOR_CLIENT,
  VERIFIER_NAME_FOR_CLIENT,
  VERIFIER_NAME_FOR_CLIENT_NL,
  VERIFIERZ_PURPOSE_TO_VERIFY,
  VERIFIERZ_PURPOSE_TO_VERIFY_NL
} from './data/mockedData'


export interface TESTKEY {
  key: JWK
  did: string
  didDoc?: DIDDocument
}

export async function generateTestKey(kty: string): Promise<TESTKEY> {
  if (kty !== KeyType.EC) throw new Error(SIOPErrors.NO_ALG_SUPPORTED)
  const key = crypto.generateKeyPairSync('ec', {
    namedCurve: KeyCurve.SECP256k1,
  })
  const privateJwk = await exportJWK(key.privateKey)

  const did = getDIDFromKey(privateJwk)

  return {
    key: privateJwk,
    did,
  }
}

function getDIDFromKey(key: JWK): string {
  return `did:ethr:${getEthAddress(key)}`
}

function getEthAddress(key: JWK): string {
  return getEthWallet(key).address
}

function getEthWallet(key: JWK): ethers.Wallet {
  return new ethers.Wallet(prefixWith0x(base64ToHexString(key.d as string)))
}

export const prefixWith0x = (key: string): string => (key.startsWith('0x') ? key : `0x${key}`)

export interface IEnterpriseAuthZToken extends JwtPayload {
  sub?: string
  did: string
  aud: string
  nonce: string
}

export interface LegalEntityTestAuthN {
  iss: string // legal entity name identifier
  aud: string // RP Application Name.
  iat: number
  exp: number
  nonce: string
  callbackUrl?: string // Entity url to send notifications
  image?: string // base64 encoded image data
  icon?: string // base64 encoded image icon data
}

export const mockedKeyAndDid = async (): Promise<{
  hexPrivateKey: string
  did: string
  jwk: JWK
  hexPublicKey: string
}> => {
  // generate a new keypair
  const key = crypto.generateKeyPairSync('ec', {
    namedCurve: KeyCurve.SECP256k1,
  })
  const privateJwk = await exportJWK(key.privateKey)
  const hexPrivateKey = base64ToHexString(privateJwk.d as string)
  const wallet: ethers.Wallet = new ethers.Wallet(prefixWith0x(hexPrivateKey))
  const did = `did:ethr:${wallet.address}`
  const hexPublicKey = wallet.signingKey.publicKey

  return {
    hexPrivateKey,
    did,
    jwk: privateJwk,
    hexPublicKey,
  }
}

const mockedEntityAuthNToken = async (
  enterpiseName?: string,
): Promise<{
  jwt: string
  jwk: JWK
  did: string
  hexPrivateKey: string
  hexPublicKey: string
}> => {
  // generate a new keypair
  const { did, jwk, hexPrivateKey, hexPublicKey } = await mockedKeyAndDid()

  const payload: LegalEntityTestAuthN = {
    iss: enterpiseName || 'Test Entity',
    aud: 'test',
    iat: moment().unix(),
    exp: moment().add(15, 'minutes').unix(),
    nonce: uuidv4(),
  }

  const privateKey = await importJWK(jwk, SigningAlgo.ES256K)
  const jwt = await new SignJWT(payload as unknown as JwtPayload)
    .setProtectedHeader({
      alg: 'ES256K',
      typ: 'JWT',
    })
    .sign(privateKey)
  return { jwt, jwk, did, hexPrivateKey, hexPublicKey }
}

export async function mockedGetEnterpriseAuthToken(enterpriseName?: string): Promise<{
  jwt: string
  did: string
  jwk: JWK
  hexPrivateKey: string
  hexPublicKey: string
}> {
  const testAuth = await mockedEntityAuthNToken(enterpriseName)
  const { payload: _payload } = parseJWT(testAuth.jwt)

  const payload = _payload as JwtPayload
  const inputPayload: IEnterpriseAuthZToken = {
    did: testAuth.did,

    aud: payload?.iss ? payload.iss : 'Test Entity',
    nonce: (payload as IEnterpriseAuthZToken).nonce,
  }

  const testApiPayload = {
    ...inputPayload,
    ...{
      sub: (payload as JwtPayload).iss, // Should be the id of the app that is requesting the token
      iat: moment().unix(),
      exp: moment().add(15, 'minutes').unix(),
      aud: 'test',
    },
  }

  const privateKey = await importJWK(testAuth.jwk, SigningAlgo.ES256K)
  const jwt = await new SignJWT(testApiPayload)
    .setProtectedHeader({
      alg: 'ES256K',
      typ: 'JWT',
    })
    .sign(privateKey)

  return {
    jwt,
    did: testAuth.did,
    jwk: testAuth.jwk,
    hexPrivateKey: testAuth.hexPrivateKey,
    hexPublicKey: testAuth.hexPublicKey,
  }
}

export interface DidKey {
  did: string
  publicKeyHex?: string
  jwk?: JWK
}

interface FixJwk extends JWK {
  kty: string
}

export const getParsedDidDocument = (didKey: DidKey): DIDDocument => {
  if (didKey.publicKeyHex) {
    const didDocB58 = DID_DOCUMENT_PUBKEY_B58
    if (!didDocB58 || !didDocB58.verificationMethod?.[0]) throw new Error('Invalid DID Document')
    didDocB58.id = didKey.did
    didDocB58.controller = didKey.did
    didDocB58.verificationMethod[0].id = `${didKey.did}#keys-1`
    didDocB58.verificationMethod[0].controller = didKey.did
    didDocB58.verificationMethod[0].publicKeyBase58 = base58.encode(Buffer.from(didKey.publicKeyHex.replace('0x', ''), 'hex'))
    return didDocB58
  }
  // then didKey jws public key
  const didDocJwk = DID_DOCUMENT_PUBKEY_JWK
  if (!didDocJwk || !didDocJwk.verificationMethod?.[0]) throw new Error('Invalid DID Document')
  const { jwk } = didKey
  if (!jwk) throw new Error('Invalid didKey')
  jwk.kty = didKey?.jwk?.kty || 'EC'
  didDocJwk.id = didKey.did
  didDocJwk.controller = didKey.did
  didDocJwk.verificationMethod[0].id = `${didKey.did}#keys-1`
  didDocJwk.verificationMethod[0].controller = didKey.did
  didDocJwk.verificationMethod[0].publicKeyJwk = jwk as FixJwk
  return didDocJwk
}

export const WELL_KNOWN_OPENID_FEDERATION = 'https://www.example.com/.well-known/openid-federation'
export const metadata: {
  opMetadata: DiscoveryMetadataPayload
  rpMetadata: RPRegistrationMetadataPayload
  verify(): unknown
} = {
  opMetadata: {
    issuer: ResponseIss.SELF_ISSUED_V2,
    authorization_endpoint: 'http://test.com',
    subject_syntax_types_supported: ['did:web'],
    id_token_signing_alg_values_supported: undefined,
    request_object_signing_alg_values_supported: [SigningAlgo.EDDSA],
    response_types_supported: ResponseType.ID_TOKEN,
    scopes_supported: [Scope.OPENID_DIDAUTHN],
    subject_types_supported: [SubjectType.PAIRWISE],
    vp_formats: {
      ldp_vc: {
        proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
      },
      jwt_vc: {
        alg: [SigningAlgo.ES256, SigningAlgo.ES256K],
      },
    },
    logo_uri: VERIFIER_LOGO_FOR_CLIENT + ' 2022-09-29 02',
    client_name: VERIFIER_NAME_FOR_CLIENT + ' 2022-09-29 02',
    'client_name#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + ' 2022-09-29 02',
    client_purpose: VERIFIERZ_PURPOSE_TO_VERIFY + ' 2022-09-29 02',
    'client_purpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL + ' 2022-09-29 02',
  },
  rpMetadata: {
    client_id: WELL_KNOWN_OPENID_FEDERATION,
    id_token_signing_alg_values_supported: [],
    request_object_signing_alg_values_supported: [SigningAlgo.EDDSA],
    response_types_supported: [ResponseType.ID_TOKEN],
    scopes_supported: [Scope.OPENID, Scope.OPENID_DIDAUTHN],
    subject_syntax_types_supported: [SubjectSyntaxTypesSupportedValues.DID.valueOf(), 'did:web', 'did:key'],
    subject_types_supported: [SubjectType.PAIRWISE],
    vp_formats: {
      ldp_vc: {
        proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
      },
      jwt_vc: {
        alg: [SigningAlgo.ES256, SigningAlgo.ES256K],
      },
    },
    logo_uri: VERIFIER_LOGO_FOR_CLIENT + ' 2022-09-29 03',
    client_name: VERIFIER_NAME_FOR_CLIENT + ' 2022-09-29 03',
    'client_name#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + ' 2022-09-29 03',
    client_purpose: VERIFIERZ_PURPOSE_TO_VERIFY + ' 2022-09-29 03',
    'client_purpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL + ' 2022-09-29 03',
  },
  verify() {
    return assertValidMetadata(this.opMetadata, this.rpMetadata)
  },
}

export const pexHasher = (data: string) => createHash('sha256').update(data).digest()

export const sdJwtVcPresentationSignCallback: PresentationSignCallback = async (_args) => {
  const presentation = _args.presentation as PartialSdJwtDecodedVerifiableCredential

  // In real life scenario, the KB-JWT must be signed
  // As the KB-JWT is a normal JWT, the user does not need an sd-jwt implementation in the presentation sign callback
  // NOTE: should the presentation just be the KB-JWT header + payload instead of the whole decoded SD JWT?
  expect(presentation.kbJwt).toEqual({
    header: {
      typ: 'kb+jwt',
    },
    payload: {
      sd_hash: expect.any(String),
      iat: expect.any(Number),
      nonce: expect.any(String),
    },
  })

  const createSignerVerifier = async () => {
    const { privateKey, publicKey } = await ES256.generateKeyPair();
    return {
      signer: await ES256.getSigner(privateKey),
      verifier: await ES256.getVerifier(publicKey)
    }
  }

  const { signer, verifier } = await createSignerVerifier();

  const sdjwt = new SDJwtVcInstance({
    signer,
    signAlg: ES256.alg,
    verifier,
    hasher: digest,
    saltGenerator: generateSalt,
    kbSigner: signer,
    kbSignAlg: ES256.alg,
    kbVerifier: verifier
  })

  const claims = {
    license: {
      number: 10
    },
    user: {
      name: 'John',
      date_of_birth: '01/01/1970'
    }
  }

  const kbPayload: Omit<SdJwtVcKbJwtPayload, 'sd_hash'> = presentation.kbJwt.payload

  presentation.compactSdJwtVc = await sdjwt.present<typeof claims>(
    presentation.compactSdJwtVc,
    {
      user: { name: true },
      license: { number: true }
    },
    {
      kb: {
        payload: kbPayload,
      },
    },
  );

  return presentation.compactSdJwtVc
}
