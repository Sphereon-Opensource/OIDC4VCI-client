import { EventEmitter } from 'events'

import { IPresentationDefinition } from '@sphereon/pex'
import { Hasher } from '@sphereon/ssi-types'
import { DcqlQuery } from 'dcql'

import { PropertyTarget, PropertyTargets } from '../authorization-request'
import { PresentationVerificationCallback } from '../authorization-response'
import { ClientIdScheme, CreateJwtCallback, RequestAud, VerifyJwtCallback } from '../types'
import {
  AuthorizationRequestPayload,
  ClientMetadataOpts,
  ObjectBy,
  PassBy,
  RequestObjectPayload,
  ResponseIss,
  ResponseMode,
  ResponseType,
  RevocationVerification,
  RevocationVerificationCallback,
  SupportedVersion,
} from '../types'

import { assignIfAuth, assignIfRequestObject, isTarget, isTargetOrNoTargets } from './Opts'
import { RP } from './RP'
import { IRPSessionManager } from './types'


export class RPBuilder {
  requestObjectBy: ObjectBy
  createJwtCallback?: CreateJwtCallback
  verifyJwtCallback?: VerifyJwtCallback
  revocationVerification?: RevocationVerification
  revocationVerificationCallback?: RevocationVerificationCallback
  presentationVerificationCallback?: PresentationVerificationCallback
  supportedVersions: SupportedVersion[]
  eventEmitter?: EventEmitter
  sessionManager?: IRPSessionManager
  _responseRedirectUri?: string
  private _authorizationRequestPayload: Partial<AuthorizationRequestPayload> = {}
  private _requestObjectPayload: Partial<RequestObjectPayload> = {}

  clientMetadata?: ClientMetadataOpts = undefined
  clientId: string
  entityId: string
  clientIdScheme: string

  hasher: Hasher

  private constructor(supportedRequestVersion?: SupportedVersion) {
    if (supportedRequestVersion) {
      this.addSupportedVersion(supportedRequestVersion)
    }
  }

  withScope(scope: string, targets?: PropertyTargets): RPBuilder {
    this._authorizationRequestPayload.scope = assignIfAuth({ propertyValue: scope, targets }, false)
    this._requestObjectPayload.scope = assignIfRequestObject({ propertyValue: scope, targets }, true)
    return this
  }

  withResponseType(responseType: ResponseType | ResponseType[] | string, targets?: PropertyTargets): RPBuilder {
    const propertyValue = Array.isArray(responseType) ? responseType.join(' ').trim() : responseType
    this._authorizationRequestPayload.response_type = assignIfAuth({ propertyValue, targets }, false)
    this._requestObjectPayload.response_type = assignIfRequestObject({ propertyValue, targets }, true)
    return this
  }

  withHasher(hasher: Hasher): RPBuilder {
    this.hasher = hasher

    return this
  }

  withClientId(clientId: string, targets?: PropertyTargets): RPBuilder {
    this._authorizationRequestPayload.client_id = assignIfAuth({ propertyValue: clientId, targets }, false)
    this._requestObjectPayload.client_id = assignIfRequestObject({ propertyValue: clientId, targets }, true)
    this.clientId = clientId
    return this
  }

  withClientIdScheme(clientIdScheme: ClientIdScheme, targets?: PropertyTargets): RPBuilder {
    this._authorizationRequestPayload.client_id_scheme = assignIfAuth({ propertyValue: clientIdScheme, targets }, false)
    this._requestObjectPayload.client_id_scheme = assignIfRequestObject({ propertyValue: clientIdScheme, targets }, true)
    this.clientIdScheme = clientIdScheme
    return this
  }

  withEntityId(entityId: string, targets?: PropertyTargets): RPBuilder {
    this._authorizationRequestPayload.entity_id = assignIfAuth({ propertyValue: entityId, targets }, false)
    this._requestObjectPayload.entity_id = assignIfRequestObject({ propertyValue: entityId, targets }, true)
    this.entityId = entityId
    return this
  }

  withIssuer(issuer: ResponseIss, targets?: PropertyTargets): RPBuilder {
    this._authorizationRequestPayload.iss = assignIfAuth({ propertyValue: issuer, targets }, false)
    this._requestObjectPayload.iss = assignIfRequestObject({ propertyValue: issuer, targets }, true)
    return this
  }

  withAudience(issuer: RequestAud, targets?: PropertyTargets): RPBuilder {
    this._authorizationRequestPayload.aud = assignIfAuth({ propertyValue: issuer, targets }, false)
    this._requestObjectPayload.aud = assignIfRequestObject({ propertyValue: issuer, targets }, true)
    return this
  }

  withPresentationVerification(presentationVerificationCallback: PresentationVerificationCallback): RPBuilder {
    this.presentationVerificationCallback = presentationVerificationCallback
    return this
  }

  withRevocationVerification(mode: RevocationVerification): RPBuilder {
    this.revocationVerification = mode
    return this
  }

  withRevocationVerificationCallback(callback: RevocationVerificationCallback): RPBuilder {
    this.revocationVerificationCallback = callback
    return this
  }

  withAuthorizationEndpoint(authorizationEndpoint: string, targets?: PropertyTargets): RPBuilder {
    this._authorizationRequestPayload.authorization_endpoint = assignIfAuth(
      {
        propertyValue: authorizationEndpoint,
        targets,
      },
      false,
    )
    this._requestObjectPayload.authorization_endpoint = assignIfRequestObject(
      {
        propertyValue: authorizationEndpoint,
        targets,
      },
      true,
    )
    return this
  }

  withRedirectUri(redirectUri: string, targets?: PropertyTargets): RPBuilder {
    this._authorizationRequestPayload.redirect_uri = assignIfAuth({ propertyValue: redirectUri, targets }, false)
    this._requestObjectPayload.redirect_uri = assignIfRequestObject({ propertyValue: redirectUri, targets }, true)
    return this
  }

  withResponseRedirectUri(responseRedirectUri: string): RPBuilder {
    this._responseRedirectUri = responseRedirectUri
    return this
  }

  withResponseUri(redirectUri: string, targets?: PropertyTargets): RPBuilder {
    this._authorizationRequestPayload.response_uri = assignIfAuth({ propertyValue: redirectUri, targets }, false)
    this._requestObjectPayload.response_uri = assignIfRequestObject({ propertyValue: redirectUri, targets }, true)
    return this
  }

  withRequestByReference(referenceUri: string): RPBuilder {
    return this.withRequestBy(PassBy.REFERENCE, referenceUri /*, PropertyTarget.AUTHORIZATION_REQUEST*/)
  }
  withRequestByValue(): RPBuilder {
    return this.withRequestBy(PassBy.VALUE, undefined /*, PropertyTarget.AUTHORIZATION_REQUEST*/)
  }

  withRequestBy(passBy: PassBy, referenceUri?: string /*, targets?: PropertyTargets*/): RPBuilder {
    if (passBy === PassBy.REFERENCE && !referenceUri) {
      throw Error('Cannot use pass by reference without a reference URI')
    }
    this.requestObjectBy = {
      passBy,
      reference_uri: referenceUri,
      targets: PropertyTarget.AUTHORIZATION_REQUEST,
    }
    return this
  }

  withResponseMode(responseMode: ResponseMode, targets?: PropertyTargets): RPBuilder {
    this._authorizationRequestPayload.response_mode = assignIfAuth({ propertyValue: responseMode, targets }, false)
    this._requestObjectPayload.response_mode = assignIfRequestObject({ propertyValue: responseMode, targets }, true)
    return this
  }

  withClientMetadata(clientMetadata: ClientMetadataOpts, targets?: PropertyTargets): RPBuilder {
    clientMetadata.targets = targets
    if (this.getSupportedRequestVersion() < SupportedVersion.SIOPv2_D11) {
      this._authorizationRequestPayload.registration = assignIfAuth(
        {
          propertyValue: clientMetadata,
          targets,
        },
        false,
      )
      this._requestObjectPayload.registration = assignIfRequestObject(
        {
          propertyValue: clientMetadata,
          targets,
        },
        true,
      )
    } else {
      this._authorizationRequestPayload.client_metadata = assignIfAuth(
        {
          propertyValue: clientMetadata,
          targets,
        },
        false,
      )
      this._requestObjectPayload.client_metadata = assignIfRequestObject(
        {
          propertyValue: clientMetadata,
          targets,
        },
        true,
      )
    }
    this.clientMetadata = clientMetadata
    //fixme: Add URL
    return this
  }

  withCreateJwtCallback(createJwtCallback: CreateJwtCallback): RPBuilder {
    this.createJwtCallback = createJwtCallback
    return this
  }

  withVerifyJwtCallback(verifyJwtCallback: VerifyJwtCallback): RPBuilder {
    this.verifyJwtCallback = verifyJwtCallback
    return this
  }

  withDcqlQuery(dcqlQuery: DcqlQuery | string, targets?: PropertyTargets): RPBuilder {
    if (this.getSupportedRequestVersion() >= SupportedVersion.SIOPv2_D12_OID4VP_D20) {
      this._authorizationRequestPayload.dcql_query = assignIfAuth(
        {
          propertyValue: typeof dcqlQuery === 'string' ? dcqlQuery : JSON.stringify(dcqlQuery),
          targets
        },
        false
      )
      this._requestObjectPayload.dcql_query = assignIfRequestObject(
        {
          propertyValue: typeof dcqlQuery === 'string' ? dcqlQuery : JSON.stringify(dcqlQuery),
          targets
        },
        true
      )

      // FIXME we need to find a way in the config to select dcql vs PD without breaking OID4VC-DEMO
      this._authorizationRequestPayload.presentation_definition = undefined;
      this._authorizationRequestPayload.presentation_definition_uri = undefined;
      this._requestObjectPayload.presentation_definition = undefined;
      this._requestObjectPayload.presentation_definition_uri = undefined;
    }
    return this
  }

  withPresentationDefinition(definitionOpts: {
    definition: IPresentationDefinition;
    definitionUri?: string
  }, targets?: PropertyTargets): RPBuilder {
    if(this._authorizationRequestPayload.dcql_query) {
      return this
    }

    const { definition, definitionUri } = definitionOpts

    if (this.getSupportedRequestVersion() < SupportedVersion.SIOPv2_D11) {
      const definitionProperties = {
        presentation_definition: definition,
        presentation_definition_uri: definitionUri
      }
      const vp_token = { ...definitionProperties }
      if (isTarget(PropertyTarget.AUTHORIZATION_REQUEST, targets)) {
        this._authorizationRequestPayload.claims = {
          ...(this._authorizationRequestPayload.claims ? this._authorizationRequestPayload.claims : {}),
          vp_token: vp_token
        }
      }
      if (isTargetOrNoTargets(PropertyTarget.REQUEST_OBJECT, targets)) {
        this._requestObjectPayload.claims = {
          ...(this._requestObjectPayload.claims ? this._requestObjectPayload.claims : {}),
          vp_token: vp_token
        }
      }
    } else {
      this._authorizationRequestPayload.presentation_definition = assignIfAuth(
        {
          propertyValue: definition,
          targets
        },
        false
      )
      this._authorizationRequestPayload.presentation_definition_uri = assignIfAuth(
        {
          propertyValue: definitionUri,
          targets
        },
        true
      )
      this._requestObjectPayload.presentation_definition = assignIfRequestObject(
        {
          propertyValue: definition,
          targets
        },
        true
      )
      this._requestObjectPayload.presentation_definition_uri = assignIfRequestObject(
        {
          propertyValue: definitionUri,
          targets
        },
        true
      )
    }
    return this
  }

  private initSupportedVersions() {
    if (!this.supportedVersions) {
      this.supportedVersions = []
    }
  }

  addSupportedVersion(supportedVersion: SupportedVersion): RPBuilder {
    this.initSupportedVersions()
    if (!this.supportedVersions.includes(supportedVersion)) {
      this.supportedVersions.push(supportedVersion)
    }
    return this
  }

  withSupportedVersions(supportedVersion: SupportedVersion[] | SupportedVersion): RPBuilder {
    const versions = Array.isArray(supportedVersion) ? supportedVersion : [supportedVersion]
    for (const version of versions) {
      this.addSupportedVersion(version)
    }
    return this
  }

  withEventEmitter(eventEmitter?: EventEmitter): RPBuilder {
    this.eventEmitter = eventEmitter ?? new EventEmitter()
    return this
  }

  withSessionManager(sessionManager: IRPSessionManager): RPBuilder {
    this.sessionManager = sessionManager
    return this
  }

  public getSupportedRequestVersion(requireVersion?: boolean): SupportedVersion | undefined {
    if (!this.supportedVersions || this.supportedVersions.length === 0) {
      if (requireVersion !== false) {
        throw Error('No supported version supplied/available')
      }
      return undefined
    }
    return this.supportedVersions[0]
  }

  public static newInstance(supportedVersion?: SupportedVersion) {
    return new RPBuilder(supportedVersion)
  }

  build(): RP {
    if (this.sessionManager && !this.eventEmitter) {
      throw Error('Please enable the event emitter on the RP when using a replay registry')
    }

    // We do not want others to directly use the RP class
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    return new RP({ builder: this })
  }

  get authorizationRequestPayload(): Partial<AuthorizationRequestPayload> {
    return this._authorizationRequestPayload
  }

  get requestObjectPayload(): Partial<RequestObjectPayload> {
    return this._requestObjectPayload
  }

  /* public mergedPayload(): Partial<AuthorizationRequestPayload> {
    return { ...this.authorizationRequestPayload, ...this.requestObjectPayload };
  }*/
}
