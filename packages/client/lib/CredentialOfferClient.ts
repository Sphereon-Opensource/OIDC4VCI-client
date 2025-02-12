import {
  convertJsonToURI,
  convertURIToJsonObject,
  CredentialOffer,
  CredentialOfferPayload,
  CredentialOfferPayloadV1_0_09,
  CredentialOfferRequestWithBaseUrl,
  CredentialOfferV1_0_11,
  CredentialOfferV1_0_13,
  determineSpecVersionFromURI,
  OpenId4VCIVersion,
  PRE_AUTH_GRANT_LITERAL,
  toUniformCredentialOfferRequest
} from '@sphereon/oid4vci-common'
import Debug from 'debug'

import { LOG } from './types'
import { constructBaseResponse, handleCredentialOfferUri } from './functions'

const debug = Debug('sphereon:oid4vci:offer');

export class CredentialOfferClient {
  public static async fromURI(uri: string, opts?: { resolve?: boolean }): Promise<CredentialOfferRequestWithBaseUrl> {
    debug(`Credential Offer URI: ${uri}`);
    if (!uri.includes('?') || !uri.includes('://')) {
      debug(`Invalid Credential Offer URI: ${uri}`);
      throw Error(`Invalid Credential Offer Request`);
    }
    const scheme = uri.split('://')[0];
    const baseUrl = uri.split('?')[0];
    const version = determineSpecVersionFromURI(uri);
    LOG.log(`Offer URL determined to be of version ${version}`);
    let credentialOffer: CredentialOffer;
    let credentialOfferPayload: CredentialOfferPayload;
    // credential offer was introduced in draft 9 and credential_offer_uri in draft 11
    if (version < OpenId4VCIVersion.VER_1_0_11) {
      credentialOfferPayload = convertURIToJsonObject(uri, {
        arrayTypeProperties: ['credential_type'],
        requiredProperties: uri.includes('credential_offer=') ? ['credential_offer'] : ['issuer', 'credential_type'],
      }) as CredentialOfferPayloadV1_0_09;
      credentialOffer = {
        credential_offer: credentialOfferPayload,
      };
    } else {
      if (uri.includes('credential_offer_uri')) {
        credentialOffer = await handleCredentialOfferUri(uri) as CredentialOfferV1_0_11 | CredentialOfferV1_0_13
      } else {
        credentialOffer = convertURIToJsonObject(uri, {
          // It must have the '=' sign after credential_offer otherwise the uri will get split at openid_credential_offer
          arrayTypeProperties: uri.includes('credential_offer_uri=') ? ['credential_offer_uri='] : ['credential_offer='],
          requiredProperties: uri.includes('credential_offer_uri=') ? ['credential_offer_uri='] : ['credential_offer=']
        }) as CredentialOfferV1_0_11 | CredentialOfferV1_0_13
      }
      if (credentialOffer?.credential_offer_uri === undefined && !credentialOffer?.credential_offer) {
        throw Error('Either a credential_offer or credential_offer_uri should be present in ' + uri) // cannot be reached since convertURIToJsonObject will check the params
      }
    }

    const request = await toUniformCredentialOfferRequest(credentialOffer, {
      ...opts,
      version
    })

    return {
      ...constructBaseResponse(request, scheme, baseUrl),
      userPinRequired:
        request.credential_offer?.grants?.[PRE_AUTH_GRANT_LITERAL]?.user_pin_required ??
        !!request.credential_offer?.grants?.[PRE_AUTH_GRANT_LITERAL]?.tx_code ??
        false
    }
  }

  public static toURI(
    requestWithBaseUrl: CredentialOfferRequestWithBaseUrl,
    opts?: {
      version?: OpenId4VCIVersion;
    },
  ): string {
    debug(`Credential Offer Request with base URL: ${JSON.stringify(requestWithBaseUrl)}`);
    const version = opts?.version ?? requestWithBaseUrl.version;
    let baseUrl = requestWithBaseUrl.baseUrl.includes(requestWithBaseUrl.scheme)
      ? requestWithBaseUrl.baseUrl
      : `${requestWithBaseUrl.scheme.replace('://', '')}://${requestWithBaseUrl.baseUrl}`;
    let param: string | undefined;

    const isUri = requestWithBaseUrl.credential_offer_uri !== undefined;

    if (version.valueOf() >= OpenId4VCIVersion.VER_1_0_11.valueOf()) {
      // v11 changed from encoding every param to a encoded json object with a credential_offer param key
      if (!baseUrl.includes('?')) {
        param = isUri ? 'credential_offer_uri' : 'credential_offer';
      } else {
        const split = baseUrl.split('?');
        if (split.length > 1 && split[1] !== '') {
          if (baseUrl.endsWith('&')) {
            param = isUri ? 'credential_offer_uri' : 'credential_offer';
          } else if (!baseUrl.endsWith('=')) {
            baseUrl += `&`;
            param = isUri ? 'credential_offer_uri' : 'credential_offer';
          }
        }
      }
    }
    return convertJsonToURI(requestWithBaseUrl.credential_offer_uri ?? requestWithBaseUrl.original_credential_offer, {
      baseUrl,
      arrayTypeProperties: isUri ? [] : ['credential_type'],
      uriTypeProperties: isUri
        ? ['credential_offer_uri']
        : version >= OpenId4VCIVersion.VER_1_0_13
          ? ['credential_issuer', 'credential_type']
          : ['issuer', 'credential_type'],
      param,
      version,
    });
  }
}
