import { parseJWT } from '@sphereon/oid4vc-common'

import { Dcql } from '../authorization-response'
import { PresentationExchange } from '../authorization-response/PresentationExchange'
import { decodeUriAsJson, encodeJsonAsURI, fetchByReferenceOrUseByValue } from '../helpers'
import { assertValidRequestObjectPayload, RequestObject } from '../request-object'
import {
  AuthorizationRequestPayload,
  AuthorizationRequestURI,
  ObjectBy,
  PassBy,
  RequestObjectJwt,
  RequestObjectPayload,
  RPRegistrationMetadataPayload,
  SIOPErrors,
  SupportedVersion,
  UrlEncodingFormat,
} from '../types'

import { AuthorizationRequest } from './AuthorizationRequest'
import { assertValidRPRegistrationMedataPayload } from './Payload'
import { CreateAuthorizationRequestOpts } from './types'

export class URI implements AuthorizationRequestURI {
  private readonly _scheme: string
  private readonly _requestObjectJwt: RequestObjectJwt | undefined
  private readonly _authorizationRequestPayload: AuthorizationRequestPayload
  private readonly _encodedUri: string // The encoded URI
  private readonly _encodingFormat: UrlEncodingFormat
  // private _requestObjectBy: ObjectBy;

  private _registrationMetadataPayload: RPRegistrationMetadataPayload

  private constructor({ scheme, encodedUri, encodingFormat, authorizationRequestPayload, requestObjectJwt }: Partial<AuthorizationRequestURI>) {
    this._scheme = scheme
    this._encodedUri = encodedUri
    this._encodingFormat = encodingFormat
    this._authorizationRequestPayload = authorizationRequestPayload
    this._requestObjectJwt = requestObjectJwt
  }

  public static async fromUri(uri: string): Promise<URI> {
    if (!uri) {
      throw Error(SIOPErrors.BAD_PARAMS)
    }
    const { scheme, requestObjectJwt, authorizationRequestPayload, registrationMetadata } = await URI.parseAndResolve(uri)
    const requestObjectPayload = requestObjectJwt ? (parseJWT(requestObjectJwt).payload as RequestObjectPayload) : undefined
    if (requestObjectPayload) {
      assertValidRequestObjectPayload(requestObjectPayload)
    }

    const result = new URI({
      scheme,
      encodingFormat: UrlEncodingFormat.FORM_URL_ENCODED,
      encodedUri: uri,
      authorizationRequestPayload,
      requestObjectJwt,
    })
    result._registrationMetadataPayload = registrationMetadata
    return result
  }

  /**
   * Create a signed URL encoded URI with a signed SIOP request token on RP side
   *
   * @param opts Request input data to build a  SIOP Request Token
   * @remarks This method is used to generate a SIOP request with info provided by the RP.
   * First it generates the request payload and then it creates the signed JWT, which is returned as a URI
   *
   * Normally you will want to use this method to create the request.
   */
  public static async fromOpts(opts: CreateAuthorizationRequestOpts): Promise<URI> {
    if (!opts) {
      throw Error(SIOPErrors.BAD_PARAMS)
    }
    const authorizationRequest = await AuthorizationRequest.fromOpts(opts)
    return await URI.fromAuthorizationRequest(authorizationRequest)
  }

  public async toAuthorizationRequest(): Promise<AuthorizationRequest> {
    return await AuthorizationRequest.fromUriOrJwt(this)
  }

  get requestObjectBy(): ObjectBy {
    if (!this.requestObjectJwt) {
      return { passBy: PassBy.NONE }
    }
    if (this.authorizationRequestPayload.request_uri) {
      return { passBy: PassBy.REFERENCE, reference_uri: this.authorizationRequestPayload.request_uri }
    }
    return { passBy: PassBy.VALUE }
  }

  get metadataObjectBy(): ObjectBy {
    if (!this.authorizationRequestPayload.registration_uri && !this.authorizationRequestPayload.registration) {
      return { passBy: PassBy.NONE }
    }
    if (this.authorizationRequestPayload.registration_uri) {
      return { passBy: PassBy.REFERENCE, reference_uri: this.authorizationRequestPayload.registration_uri }
    }
    return { passBy: PassBy.VALUE }
  }

  /**
   * Create a URI from the request object, typically you will want to use the createURI version!
   *
   * @remarks This method is used to generate a SIOP request Object with info provided by the RP.
   * First it generates the request object payload, and then it creates the signed JWT.
   *
   * Please note that the createURI method allows you to differentiate between OAuth2 and OpenID parameters that become
   * part of the URI and which become part of the Request Object. If you generate a URI based upon the result of this method,
   * the URI will be constructed based on the Request Object only!
   */
  static async fromRequestObject(requestObject: RequestObject): Promise<URI> {
    if (!requestObject) {
      throw Error(SIOPErrors.BAD_PARAMS)
    }
    return await URI.fromAuthorizationRequestPayload(requestObject.options, await AuthorizationRequest.fromUriOrJwt(await requestObject.toJwt()))
  }

  static async fromAuthorizationRequest(authorizationRequest: AuthorizationRequest): Promise<URI> {
    if (!authorizationRequest) {
      throw Error(SIOPErrors.BAD_PARAMS)
    }
    return await URI.fromAuthorizationRequestPayload(
      {
        ...authorizationRequest.options.requestObject,
        version: authorizationRequest.options.version,
        uriScheme: authorizationRequest.options.uriScheme,
      },
      authorizationRequest.payload,
      authorizationRequest.requestObject,
    )
  }

  /**
   * Creates an URI Request
   * @param opts Options to define the Uri Request
   * @param authorizationRequestPayload
   *
   */
  private static async fromAuthorizationRequestPayload(
    opts: { uriScheme?: string; passBy: PassBy; reference_uri?: string; version?: SupportedVersion },
    authorizationRequestPayload: AuthorizationRequestPayload,
    requestObject?: RequestObject,
  ): Promise<URI> {
    if (!authorizationRequestPayload) {
      if (!requestObject || !(await requestObject.getPayload())) {
        throw Error(SIOPErrors.BAD_PARAMS)
      }
      authorizationRequestPayload = {} // No auth request payload, so the eventual URI will contain a `request_uri` or `request` value only
    }

    const isJwt = typeof authorizationRequestPayload === 'string'
    const requestObjectJwt = requestObject
      ? await requestObject.toJwt()
      : typeof authorizationRequestPayload === 'string'
        ? authorizationRequestPayload
        : authorizationRequestPayload.request

    if (isJwt && (!requestObjectJwt || !requestObjectJwt.startsWith('ey'))) {
      throw Error(SIOPErrors.NO_JWT)
    }
    const requestObjectPayload: RequestObjectPayload = requestObjectJwt ? (parseJWT(requestObjectJwt).payload as RequestObjectPayload) : undefined

    if (requestObjectPayload) {
      // Only used to validate if the request object contains presentation definition(s) | a dcql query
      await PresentationExchange.findValidPresentationDefinitions({ ...authorizationRequestPayload, ...requestObjectPayload })
      await Dcql.findValidDcqlQuery({ ...authorizationRequestPayload, ...requestObjectPayload })

      assertValidRequestObjectPayload(requestObjectPayload)
      if (requestObjectPayload.registration) {
        assertValidRPRegistrationMedataPayload(requestObjectPayload.registration)
      }
    }
    const uniformAuthorizationRequestPayload: AuthorizationRequestPayload =
      typeof authorizationRequestPayload === 'string' ? (requestObjectPayload as AuthorizationRequestPayload) : authorizationRequestPayload
    if (!uniformAuthorizationRequestPayload) {
      throw Error(SIOPErrors.BAD_PARAMS)
    }
    const type = opts.passBy
    if (!type) {
      throw new Error(SIOPErrors.REQUEST_OBJECT_TYPE_NOT_SET)
    }
    const authorizationRequest = await AuthorizationRequest.fromUriOrJwt(requestObjectJwt)

    let scheme
    if (opts.uriScheme) {
      scheme = opts.uriScheme.endsWith('://') ? opts.uriScheme : `${opts.uriScheme}://`
    } else if (opts.version) {
      if (opts.version === SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1) {
        scheme = 'openid-vc://'
      } else {
        scheme = 'openid4vp://'
      }
    } else {
      try {
        scheme =
          (await authorizationRequest.getSupportedVersion()) === SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1 ? 'openid-vc://' : 'openid4vp://'
      } catch (error: unknown) {
        scheme = 'openid4vp://'
      }
    }

    if (type === PassBy.REFERENCE) {
      if (!opts.reference_uri) {
        throw new Error(SIOPErrors.NO_REFERENCE_URI)
      }
      uniformAuthorizationRequestPayload.request_uri = opts.reference_uri
      delete uniformAuthorizationRequestPayload.request
    } else if (type === PassBy.VALUE) {
      uniformAuthorizationRequestPayload.request = requestObjectJwt
      delete uniformAuthorizationRequestPayload.request_uri
    }
    return new URI({
      scheme,
      encodedUri: `${scheme}?${encodeJsonAsURI(uniformAuthorizationRequestPayload)}`,
      encodingFormat: UrlEncodingFormat.FORM_URL_ENCODED,
      // requestObjectBy: opts.requestBy,
      authorizationRequestPayload: uniformAuthorizationRequestPayload,
      requestObjectJwt: requestObjectJwt,
    })
  }

  /**
   * Create a Authentication Request Payload from a URI string
   *
   * @param uri
   */
  public static parse(uri: string): { scheme: string; authorizationRequestPayload: AuthorizationRequestPayload } {
    if (!uri) {
      throw Error(SIOPErrors.BAD_PARAMS)
    }
    // We strip the uri scheme before passing it to the decode function
    const scheme: string = uri.match(/^([a-zA-Z][a-zA-Z0-9-_]*:\/\/)/g)[0]
    const authorizationRequestPayload = decodeUriAsJson(uri) as AuthorizationRequestPayload
    return { scheme, authorizationRequestPayload }
  }

  public static async parseAndResolve(uri: string, rpRegistrationMetadata?: RPRegistrationMetadataPayload) {
    if (!uri) {
      throw Error(SIOPErrors.BAD_PARAMS)
    }
    const { authorizationRequestPayload, scheme } = this.parse(uri)

    const requestObjectJwt = await fetchByReferenceOrUseByValue(authorizationRequestPayload.request_uri, authorizationRequestPayload.request, true)
    let registrationMetadata: RPRegistrationMetadataPayload
    if (rpRegistrationMetadata !== undefined && rpRegistrationMetadata !== null) {
      registrationMetadata = rpRegistrationMetadata
    } else {
        registrationMetadata = await fetchByReferenceOrUseByValue(
        authorizationRequestPayload['client_metadata_uri'] ?? authorizationRequestPayload['registration_uri'],
        authorizationRequestPayload['client_metadata'] ?? authorizationRequestPayload['registration'],
      )
    }
    assertValidRPRegistrationMedataPayload(registrationMetadata)
    return { scheme, authorizationRequestPayload, requestObjectJwt, registrationMetadata }
  }

  get encodingFormat(): UrlEncodingFormat {
    return this._encodingFormat
  }

  get encodedUri(): string {
    return this._encodedUri
  }

  get authorizationRequestPayload(): AuthorizationRequestPayload {
    return this._authorizationRequestPayload
  }

  get requestObjectJwt(): RequestObjectJwt | undefined {
    return this._requestObjectJwt
  }

  get scheme(): string {
    return this._scheme
  }

  get registrationMetadataPayload(): RPRegistrationMetadataPayload {
    return this._registrationMetadataPayload
  }
}
