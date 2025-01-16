import { calculateJwkThumbprintUri, JwtHeader, JwtIssuer, parseJWT } from '@sphereon/oid4vc-common'

import { AuthorizationResponseOpts, VerifyAuthorizationResponseOpts } from '../authorization-response'
import { assertValidVerifyOpts } from '../authorization-response/Opts'
import {
  getJwtVerifierWithContext,
  IDTokenJwt,
  IDTokenPayload,
  JWK,
  JWTPayload,
  ResponseIss,
  SIOPErrors,
  VerifiedAuthorizationRequest,
  VerifiedIDToken,
} from '../types'
import { JwtIssuerWithContext } from '../types/VpJwtIssuer'

import { createIDTokenPayload } from './Payload'

export class IDToken {
  private _header?: JwtHeader
  private _payload?: IDTokenPayload
  private _jwt?: IDTokenJwt
  private readonly _responseOpts: AuthorizationResponseOpts

  private constructor(jwt?: IDTokenJwt, payload?: IDTokenPayload, responseOpts?: AuthorizationResponseOpts) {
    this._jwt = jwt
    this._payload = payload
    this._responseOpts = responseOpts
  }

  public static async fromVerifiedAuthorizationRequest(
    verifiedAuthorizationRequest: VerifiedAuthorizationRequest,
    responseOpts: AuthorizationResponseOpts,
    verifyOpts?: VerifyAuthorizationResponseOpts,
  ) {
    const authorizationRequestPayload = verifiedAuthorizationRequest.authorizationRequestPayload
    if (!authorizationRequestPayload) {
      throw new Error(SIOPErrors.NO_REQUEST)
    }
    const idToken = new IDToken(null, await createIDTokenPayload(verifiedAuthorizationRequest, responseOpts), responseOpts)
    if (verifyOpts) {
      await idToken.verify(verifyOpts)
    }
    return idToken
  }

  public static async fromIDToken(idTokenJwt: IDTokenJwt, verifyOpts?: VerifyAuthorizationResponseOpts) {
    if (!idTokenJwt) {
      throw new Error(SIOPErrors.NO_JWT)
    }
    const idToken = new IDToken(idTokenJwt, undefined)
    if (verifyOpts) {
      await idToken.verify(verifyOpts)
    }
    return idToken
  }

  public static async fromIDTokenPayload(
    idTokenPayload: IDTokenPayload,
    responseOpts: AuthorizationResponseOpts,
    verifyOpts?: VerifyAuthorizationResponseOpts,
  ) {
    if (!idTokenPayload) {
      throw new Error(SIOPErrors.NO_JWT)
    }
    const idToken = new IDToken(null, idTokenPayload, responseOpts)
    if (verifyOpts) {
      await idToken.verify(verifyOpts)
    }
    return idToken
  }

  public async payload(): Promise<IDTokenPayload> {
    if (!this._payload) {
      if (!this._jwt) {
        throw new Error(SIOPErrors.NO_JWT)
      }
      const { header, payload } = this.parseAndVerifyJwt()
      this._header = header
      this._payload = payload
    }
    return this._payload
  }

  public async jwt(_jwtIssuer: JwtIssuer): Promise<IDTokenJwt> {
    if (!this._jwt) {
      if (!this.responseOpts) {
        throw Error(SIOPErrors.BAD_IDTOKEN_RESPONSE_OPTS)
      }

      const jwtIssuer: JwtIssuerWithContext = _jwtIssuer
        ? { ..._jwtIssuer, type: 'id-token', authorizationResponseOpts: this.responseOpts }
        : { method: 'custom', type: 'id-token', authorizationResponseOpts: this.responseOpts }

      if (jwtIssuer.method === 'custom') {
        this._jwt = await this.responseOpts.createJwtCallback(jwtIssuer, { header: {}, payload: this._payload })
      } else if (jwtIssuer.method === 'did') {
        const did = jwtIssuer.didUrl.split('#')[0]
        this._payload.sub = did

        const issuer = this._responseOpts.registration?.issuer || this._payload.iss
        if (!issuer || !(issuer.includes(ResponseIss.SELF_ISSUED_V2) || issuer === this._payload.sub)) {
          throw new Error(SIOPErrors.NO_SELF_ISSUED_ISS)
        }
        if (!this._payload.iss) {
          this._payload.iss = issuer
        }

        const header = { kid: jwtIssuer.didUrl, alg: jwtIssuer.alg, typ: 'JWT' }
        this._jwt = await this.responseOpts.createJwtCallback({ ...jwtIssuer, type: 'id-token' }, { header, payload: this._payload })
      } else if (jwtIssuer.method === 'x5c') {
        this._payload.iss = jwtIssuer.issuer
        this._payload.sub = jwtIssuer.issuer

        const header = { x5c: jwtIssuer.x5c, typ: 'JWT' }
        this._jwt = await this._responseOpts.createJwtCallback(jwtIssuer, { header, payload: this._payload })
      } else if (jwtIssuer.method === 'jwk') {
        const jwkThumbprintUri = await calculateJwkThumbprintUri(jwtIssuer.jwk as JWK)
        this._payload.sub = jwkThumbprintUri
        this._payload.iss = jwkThumbprintUri
        this._payload.sub_jwk = jwtIssuer.jwk

        const header = { jwk: jwtIssuer.jwk, alg: jwtIssuer.jwk.alg, typ: 'JWT' }
        this._jwt = await this._responseOpts.createJwtCallback(jwtIssuer, { header, payload: this._payload })
      } else {
        throw new Error(`JwtIssuer method '${(jwtIssuer as JwtIssuer).method}' not implemented`)
      }

      const { header, payload } = this.parseAndVerifyJwt()
      this._header = header
      this._payload = payload
    }
    return this._jwt
  }

  private parseAndVerifyJwt(): { header: JwtHeader; payload: IDTokenPayload } {
    const { header, payload } = parseJWT(this._jwt)
    this.assertValidResponseJWT({ header, payload })
    const idTokenPayload = payload as IDTokenPayload
    return { header, payload: idTokenPayload }
  }

  /**
   * Verifies a SIOP ID Response JWT on the RP Side
   *
   * @param idToken ID token to be validated
   * @param verifyOpts
   */
  public async verify(verifyOpts: VerifyAuthorizationResponseOpts): Promise<VerifiedIDToken> {
    assertValidVerifyOpts(verifyOpts)

    if (!this._jwt) {
      throw new Error(SIOPErrors.NO_JWT)
    }

    const parsedJwt = parseJWT(this._jwt)
    this.assertValidResponseJWT(parsedJwt)
    const idTokenPayload = parsedJwt.payload as IDTokenPayload

    const jwtVerifier = await getJwtVerifierWithContext(parsedJwt, { type: 'id-token' })
    const verificationResult = await verifyOpts.verifyJwtCallback(jwtVerifier, { ...parsedJwt, raw: this._jwt })
    if (!verificationResult) {
      throw Error(SIOPErrors.ERROR_VERIFYING_SIGNATURE)
    }

    this.assertValidResponseJWT({ header: parsedJwt.header, verPayload: idTokenPayload, audience: verifyOpts.audience })
    // Enforces verifyPresentationCallback function on the RP side,
    if (!verifyOpts?.verification.presentationVerificationCallback) {
      throw new Error(SIOPErrors.VERIFIABLE_PRESENTATION_VERIFICATION_FUNCTION_MISSING)
    }
    return {
      jwt: this._jwt,
      payload: { ...idTokenPayload },
      verifyOpts,
    }
  }

  static async verify(idTokenJwt: IDTokenJwt, verifyOpts: VerifyAuthorizationResponseOpts): Promise<VerifiedIDToken> {
    const idToken = await IDToken.fromIDToken(idTokenJwt, verifyOpts)
    const verifiedIdToken = await idToken.verify(verifyOpts)

    return {
      ...verifiedIdToken,
    }
  }

  private assertValidResponseJWT(opts: { header: JwtHeader; payload?: JWTPayload; verPayload?: IDTokenPayload; audience?: string; nonce?: string }) {
    if (!opts.header) {
      throw new Error(SIOPErrors.BAD_PARAMS)
    }
    if (opts.payload) {
      if (!opts.payload.iss || !(opts.payload.iss.includes(ResponseIss.SELF_ISSUED_V2) || opts.payload.iss.startsWith('did:'))) {
        throw new Error(`${SIOPErrors.NO_SELF_ISSUED_ISS}, got: ${opts.payload.iss}`)
      }
    }

    if (opts.verPayload) {
      if (!opts.verPayload.nonce) {
        throw Error(SIOPErrors.NO_NONCE)
        // No need for our own expiration check. DID jwt already does that
        /*} else if (!opts.verPayload.exp || opts.verPayload.exp < Date.now() / 1000) {
        throw Error(SIOPErrors.EXPIRED);
        /!*} else if (!opts.verPayload.iat || opts.verPayload.iat > (Date.now() / 1000)) {
                          throw Error(SIOPErrors.EXPIRED);*!/
        // todo: Add iat check

       */
      }
      if ((opts.verPayload.aud && !opts.audience) || (!opts.verPayload.aud && opts.audience)) {
        throw Error(SIOPErrors.NO_AUDIENCE)
      } else if (opts.audience && opts.audience != opts.verPayload.aud) {
        throw Error(SIOPErrors.INVALID_AUDIENCE)
      } else if (opts.nonce && opts.nonce != opts.verPayload.nonce) {
        throw Error(SIOPErrors.BAD_NONCE)
      }
    }
  }

  get header(): JwtHeader {
    return this._header
  }

  get responseOpts(): AuthorizationResponseOpts {
    return this._responseOpts
  }

  public async isSelfIssued(): Promise<boolean> {
    const payload = await this.payload()
    return payload.iss === ResponseIss.SELF_ISSUED_V2 || (payload.sub !== undefined && payload.sub === payload.iss)
  }
}
