import { uuidv4 } from '@sphereon/oid4vc-common'

import { CreateAuthorizationRequestOpts, createPresentationDefinitionClaimsProperties } from '../authorization-request'
import { createRequestRegistration } from '../authorization-request/RequestRegistration'
import { getNonce, getState, removeNullUndefined } from '../helpers'
import { RequestObjectPayload, ResponseMode, ResponseType, SIOPErrors, SupportedVersion } from '../types'

import { assertValidRequestObjectOpts } from './Opts'

export const createRequestObjectPayload = async (opts: CreateAuthorizationRequestOpts): Promise<RequestObjectPayload | undefined> => {
  assertValidRequestObjectOpts(opts.requestObject, false)
  if (!opts.requestObject?.payload) {
    return undefined // No request object apparently
  }
  assertValidRequestObjectOpts(opts.requestObject, true)

  const payload = opts.requestObject.payload

  const state = getState(payload.state)
  const registration = await createRequestRegistration(opts.clientMetadata, opts)
  const claims = createPresentationDefinitionClaimsProperties(payload.claims)

  const metadataKey = opts.version >= SupportedVersion.SIOPv2_D11.valueOf() ? 'client_metadata' : 'registration'
  const clientId = payload.client_id ?? registration.payload[metadataKey]?.client_id

  const now = Math.round(new Date().getTime() / 1000)
  const validInSec = 120 // todo config/option
  const iat = payload.iat ?? now
  const nbf = payload.nbf ?? iat
  const exp = payload.exp ?? iat + validInSec
  const aud = payload.aud
  const jti = payload.jti ?? uuidv4()

  return removeNullUndefined({
    response_type: payload.response_type ?? ResponseType.ID_TOKEN,
    scope: payload.scope,
    //TODO implement /.well-known/openid-federation support in the OP side to resolve the client_id (URL) and retrieve the metadata
    client_id_scheme: payload.client_id_scheme,
    ...(clientId && { client_id: clientId }),
    ...(payload.entity_id && { entity_id: payload.entity_id }),
    ...(payload.redirect_uri && { redirect_uri: payload.redirect_uri }),
    ...(payload.response_uri && { response_uri: payload.response_uri }),
    response_mode: payload.response_mode ?? ResponseMode.DIRECT_POST,
    ...(payload.id_token_hint && { id_token_hint: payload.id_token_hint }),
    registration_uri: registration.clientMetadataOpts.reference_uri,
    nonce: getNonce(state, payload.nonce),
    state,
    ...registration.payload,
    claims,
    ...(payload.presentation_definition_uri && { presentation_definition_uri: payload.presentation_definition_uri }),
    ...(payload.presentation_definition && { presentation_definition: payload.presentation_definition }),
    ...(payload.dcql_query && { dcql_query: payload.dcql_query }),
    client_metadata: payload.client_metadata,
    iat,
    nbf,
    exp,
    jti,
    aud,
  })
}

export const assertValidRequestObjectPayload = (verPayload: RequestObjectPayload): void => {
  if (verPayload['registration_uri'] && verPayload['registration']) {
    throw new Error(`${SIOPErrors.REG_OBJ_N_REG_URI_CANT_BE_SET_SIMULTANEOUSLY}`)
  }
}
