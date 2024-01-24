import {
  AuthorizationDetails,
  AuthorizationRequestOpts,
  CodeChallengeMethod,
  convertJsonToURI,
  CredentialOfferRequestWithBaseUrl,
  CredentialSupported,
  EndpointMetadataResult,
  JsonURIMode,
  PARMode,
  PKCEOpts,
  PushedAuthorizationResponse,
  ResponseType,
} from '@sphereon/oid4vci-common';
import { formPost } from '@sphereon/oid4vci-common';

export const createAuthorizationRequestUrl = async ({
  pkce,
  endpointMetadata,
  authorizationRequest,
  credentialOffer,
  credentialsSupported,
}: {
  pkce: PKCEOpts;
  endpointMetadata: EndpointMetadataResult;
  authorizationRequest: AuthorizationRequestOpts;
  credentialOffer?: CredentialOfferRequestWithBaseUrl;
  credentialsSupported?: CredentialSupported[];
}): Promise<string> => {
  const { redirectUri } = authorizationRequest;
  let { scope, authorizationDetails } = authorizationRequest;
  const parMode = endpointMetadata?.credentialIssuerMetadata?.require_pushed_authorization_requests
    ? PARMode.REQUIRE
    : authorizationRequest.parMode ?? PARMode.AUTO;
  // Scope and authorization_details can be used in the same authorization request
  // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rar-23#name-relationship-to-scope-param
  if (!scope && !authorizationDetails) {
    if (!credentialOffer) {
      throw Error('Please provide a scope or authorization_details if no credential offer is present');
    }
    const creds = credentialOffer.credential_offer.credentials;

    // FIXME: complains about VCT for sd-jwt
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    authorizationDetails = creds
      .flatMap((cred) => (typeof cred === 'string' ? credentialsSupported : (cred as CredentialSupported)))
      .filter((cred) => !!cred)
      .map((cred) => {
        return {
          ...cred,
          type: 'openid_credential',
          locations: [endpointMetadata.issuer],

          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-ignore
          format: cred!.format,
        } satisfies AuthorizationDetails;
      });
    if (!authorizationDetails || authorizationDetails.length === 0) {
      throw Error(`Could not create authorization details from credential offer. Please pass in explicit details`);
    }
  }
  if (!endpointMetadata?.authorization_endpoint) {
    throw Error('Server metadata does not contain authorization endpoint');
  }
  const parEndpoint = endpointMetadata.credentialIssuerMetadata?.pushed_authorization_request_endpoint;

  // add 'openid' scope if not present
  if (!scope?.includes('openid')) {
    scope = ['openid', scope].filter((s) => !!s).join(' ');
  }

  let queryObj: { [key: string]: string } | PushedAuthorizationResponse = {
    response_type: ResponseType.AUTH_CODE,
    ...(!pkce.disabled && {
      code_challenge_method: pkce.codeChallengeMethod ?? CodeChallengeMethod.S256,
      code_challenge: pkce.codeChallenge,
    }),
    authorization_details: JSON.stringify(handleAuthorizationDetails(endpointMetadata, authorizationDetails)),
    redirect_uri: redirectUri,
    scope: scope,
  };

  if (authorizationRequest.clientId) {
    queryObj['client_id'] = authorizationRequest.clientId;
  }

  if (credentialOffer?.issuerState) {
    queryObj['issuer_state'] = credentialOffer.issuerState;
  }
  if (!parEndpoint && parMode === PARMode.REQUIRE) {
    throw Error(`PAR mode is set to required by Authorization Server does not support PAR!`);
  } else if (parEndpoint && parMode !== PARMode.NEVER) {
    const parResponse = await formPost<PushedAuthorizationResponse>(parEndpoint, new URLSearchParams(queryObj));
    if (parResponse.errorBody || !parResponse.successBody) {
      throw Error(`PAR error`);
    }
    queryObj = { request_uri: parResponse.successBody.request_uri };
  }

  const url = convertJsonToURI(queryObj, {
    baseUrl: endpointMetadata.authorization_endpoint,
    uriTypeProperties: ['request_uri', 'redirect_uri', 'scope', 'authorization_details', 'issuer_state'],
    mode: JsonURIMode.X_FORM_WWW_URLENCODED,
    // We do not add the version here, as this always needs to be form encoded
  });
  console.log(`Authorization Request URL: ${url}`);
  return url;
};

const handleAuthorizationDetails = (
  endpointMetadata: EndpointMetadataResult,
  authorizationDetails?: AuthorizationDetails | AuthorizationDetails[],
): AuthorizationDetails | AuthorizationDetails[] | undefined => {
  if (authorizationDetails) {
    if (typeof authorizationDetails === 'string') {
      // backwards compat for older versions of the lib
      return authorizationDetails;
    }
    if (Array.isArray(authorizationDetails)) {
      return authorizationDetails
        .filter((value) => typeof value !== 'string')
        .map((value) => handleLocations(endpointMetadata, typeof value === 'string' ? value : { ...value }));
    } else {
      return handleLocations(endpointMetadata, { ...authorizationDetails });
    }
  }
  return authorizationDetails;
};

const handleLocations = (endpointMetadata: EndpointMetadataResult, authorizationDetails: AuthorizationDetails) => {
  if (typeof authorizationDetails === 'string') {
    // backwards compat for older versions of the lib
    return authorizationDetails;
  }
  if (authorizationDetails && (endpointMetadata.credentialIssuerMetadata?.authorization_server || endpointMetadata.authorization_endpoint)) {
    if (authorizationDetails.locations) {
      if (Array.isArray(authorizationDetails.locations)) {
        (authorizationDetails.locations as string[]).push(endpointMetadata.issuer);
      } else {
        authorizationDetails.locations = [authorizationDetails.locations as string, endpointMetadata.issuer];
      }
    } else {
      authorizationDetails.locations = [endpointMetadata.issuer];
    }
  }
  return authorizationDetails;
};