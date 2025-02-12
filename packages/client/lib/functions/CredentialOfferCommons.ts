import {
  decodeJsonProperties,
  getClientIdFromCredentialOfferPayload,
  getURIComponentsAsArray,
  PRE_AUTH_CODE_LITERAL,
  PRE_AUTH_GRANT_LITERAL,
  UniformCredentialOfferRequest
} from '@sphereon/oid4vci-common'
import { fetch } from 'cross-fetch'

export function isUriEncoded(str: string): boolean {
  const pattern = /%[0-9A-F]{2}/i
  return pattern.test(str)
}

export async function handleCredentialOfferUri(uri: string) {
  const uriObj = getURIComponentsAsArray(uri) as unknown as Record<string, string>
  const credentialOfferUri = decodeURIComponent(uriObj['credential_offer_uri'])
  const decodedUri = isUriEncoded(credentialOfferUri) ? decodeURIComponent(credentialOfferUri) : credentialOfferUri
  const response = await fetch(decodedUri)

  if (!(response && response.status >= 200 && response.status < 400)) {
    return Promise.reject(`the credential offer URI endpoint call was not successful. http code ${response.status} - reason ${response.statusText}`)
  }

  if (response.headers.get('Content-Type')?.startsWith('application/json') === false) {
    return Promise.reject('the credential offer URI endpoint did not return content type application/json')
  }

  return {
    credential_offer: decodeJsonProperties(await response.json())
  }
}

export function constructBaseResponse(request: UniformCredentialOfferRequest, scheme: string, baseUrl: string) {
  const clientId = getClientIdFromCredentialOfferPayload(request.credential_offer)
  const grants = request.credential_offer?.grants

  return {
    scheme,
    baseUrl,
    ...(clientId && { clientId }),
    ...request,
    ...(grants?.authorization_code?.issuer_state && { issuerState: grants.authorization_code.issuer_state }),
    ...(grants?.[PRE_AUTH_GRANT_LITERAL]?.[PRE_AUTH_CODE_LITERAL] && {
      preAuthorizedCode: grants[PRE_AUTH_GRANT_LITERAL][PRE_AUTH_CODE_LITERAL]
    }),
    ...(request.credential_offer?.grants?.[PRE_AUTH_GRANT_LITERAL]?.tx_code && {
      txCode: request.credential_offer.grants[PRE_AUTH_GRANT_LITERAL].tx_code
    })
  }
}