import { SigningAlgo } from '@sphereon/oid4vc-common'
import {
  AuthorizationServerMetadata,
  OAuthGrantType,
  OAuthResponseMode,
  OAuthResponseType,
  OAuthScope,
  PKCECodeChallengeMethod,
  RevocationEndpointAuthMethod,
  RevocationEndpointAuthSigningAlg,
  TokenEndpointAuthMethod,
  TokenEndpointAuthSigningAlg,
} from '@sphereon/oid4vci-common'

export class AuthorizationServerMetadataBuilder {
  private metadata: Partial<AuthorizationServerMetadata> = {}

  public withIssuer(issuer: string): AuthorizationServerMetadataBuilder {
    this.metadata.issuer = issuer
    return this
  }

  public withAuthorizationEndpoint(endpoint: string): AuthorizationServerMetadataBuilder {
    this.metadata.authorization_endpoint = endpoint
    return this
  }

  public withAuthorizationChallengeEndpoint(endpoint: string): AuthorizationServerMetadataBuilder {
    this.metadata.authorization_challenge_endpoint = endpoint
    return this
  }

  public withTokenEndpoint(endpoint: string): AuthorizationServerMetadataBuilder {
    this.metadata.token_endpoint = endpoint
    return this
  }

  public withTokenEndpointAuthMethodsSupported(methods: Array<TokenEndpointAuthMethod>): AuthorizationServerMetadataBuilder {
    this.metadata.token_endpoint_auth_methods_supported = methods
    return this
  }

  public withTokenEndpointAuthSigningAlgValuesSupported(algs: Array<TokenEndpointAuthSigningAlg>): AuthorizationServerMetadataBuilder {
    this.metadata.token_endpoint_auth_signing_alg_values_supported = algs
    return this
  }

  public withRegistrationEndpoint(endpoint: string): AuthorizationServerMetadataBuilder {
    this.metadata.registration_endpoint = endpoint
    return this
  }

  public withScopesSupported(scopes: Array<OAuthScope | string>): AuthorizationServerMetadataBuilder {
    this.metadata.scopes_supported = scopes
    return this
  }

  public withResponseTypesSupported(types: Array<OAuthResponseType>): AuthorizationServerMetadataBuilder {
    this.metadata.response_types_supported = types
    return this
  }

  public withResponseModesSupported(modes: Array<OAuthResponseMode>): AuthorizationServerMetadataBuilder {
    this.metadata.response_modes_supported = modes
    return this
  }

  public withGrantTypesSupported(types: Array<OAuthGrantType>): AuthorizationServerMetadataBuilder {
    this.metadata.grant_types_supported = types
    return this
  }

  public withServiceDocumentation(url: string): AuthorizationServerMetadataBuilder {
    this.metadata.service_documentation = url
    return this
  }

  public withUILocalesSupported(locales: string[]): AuthorizationServerMetadataBuilder {
    this.metadata.ui_locales_supported = locales
    return this
  }

  public withOpPolicyUri(uri: string): AuthorizationServerMetadataBuilder {
    this.metadata.op_policy_uri = uri
    return this
  }

  public withOpTosUri(uri: string): AuthorizationServerMetadataBuilder {
    this.metadata.op_tos_uri = uri
    return this
  }

  public withRevocationEndpoint(endpoint: string): AuthorizationServerMetadataBuilder {
    this.metadata.revocation_endpoint = endpoint
    return this
  }

  public withRevocationEndpointAuthMethodsSupported(methods: Array<RevocationEndpointAuthMethod>): AuthorizationServerMetadataBuilder {
    this.metadata.revocation_endpoint_auth_methods_supported = methods
    return this
  }

  public withRevocationEndpointAuthSigningAlgValuesSupported(algs: Array<RevocationEndpointAuthSigningAlg>): AuthorizationServerMetadataBuilder {
    this.metadata.revocation_endpoint_auth_signing_alg_values_supported = algs
    return this
  }

  public withIntrospectionEndpoint(endpoint: string): AuthorizationServerMetadataBuilder {
    this.metadata.introspection_endpoint = endpoint
    return this
  }

  public withCodeChallengeMethodsSupported(methods: Array<PKCECodeChallengeMethod>): AuthorizationServerMetadataBuilder {
    this.metadata.code_challenge_methods_supported = methods
    return this
  }

  public withPushedAuthorizationRequestEndpoint(endpoint: string): AuthorizationServerMetadataBuilder {
    this.metadata.pushed_authorization_request_endpoint = endpoint
    return this
  }

  public withRequirePushedAuthorizationRequests(required: boolean): AuthorizationServerMetadataBuilder {
    this.metadata.require_pushed_authorization_requests = required
    return this
  }

  public withPreAuthorizedGrantAnonymousAccessSupported(supported: boolean): AuthorizationServerMetadataBuilder {
    this.metadata['pre-authorized_grant_anonymous_access_supported'] = supported
    return this
  }

  public withDPoPSigningAlgValuesSupported(algs: (string | SigningAlgo)[]): AuthorizationServerMetadataBuilder {
    this.metadata.dpop_signing_alg_values_supported = algs
    return this
  }

  // OIDC specific methods
  public withFrontchannelLogoutSupported(supported: boolean): AuthorizationServerMetadataBuilder {
    this.metadata.frontchannel_logout_supported = supported
    return this
  }

  public withFrontchannelLogoutSessionSupported(supported: boolean): AuthorizationServerMetadataBuilder {
    this.metadata.frontchannel_logout_session_supported = supported
    return this
  }

  public withBackchannelLogoutSupported(supported: boolean): AuthorizationServerMetadataBuilder {
    this.metadata.backchannel_logout_supported = supported
    return this
  }

  public withBackchannelLogoutSessionSupported(supported: boolean): AuthorizationServerMetadataBuilder {
    this.metadata.backchannel_logout_session_supported = supported
    return this
  }

  public withUserinfoEndpoint(endpoint: string): AuthorizationServerMetadataBuilder {
    this.metadata.userinfo_endpoint = endpoint
    return this
  }

  public withCheckSessionIframe(url: string): AuthorizationServerMetadataBuilder {
    this.metadata.check_session_iframe = url
    return this
  }

  public withEndSessionEndpoint(endpoint: string): AuthorizationServerMetadataBuilder {
    this.metadata.end_session_endpoint = endpoint
    return this
  }

  public withAcrValuesSupported(values: string[]): AuthorizationServerMetadataBuilder {
    this.metadata.acr_values_supported = values
    return this
  }

  public withSubjectTypesSupported(types: string[]): AuthorizationServerMetadataBuilder {
    this.metadata.subject_types_supported = types
    return this
  }

  public withRequestObjectSigningAlgValuesSupported(algs: string[]): AuthorizationServerMetadataBuilder {
    this.metadata.request_object_signing_alg_values_supported = algs
    return this
  }

  public withDisplayValuesSupported(values: string[]): AuthorizationServerMetadataBuilder {
    this.metadata.display_values_supported = values
    return this
  }

  public withClaimTypesSupported(types: string[]): AuthorizationServerMetadataBuilder {
    this.metadata.claim_types_supported = types
    return this
  }

  public withClaimsSupported(claims: string[]): AuthorizationServerMetadataBuilder {
    this.metadata.claims_supported = claims
    return this
  }

  public withClaimsParameterSupported(supported: boolean): AuthorizationServerMetadataBuilder {
    this.metadata.claims_parameter_supported = supported
    return this
  }

  // VCI specific methods
  public withCredentialEndpoint(endpoint: string): AuthorizationServerMetadataBuilder {
    this.metadata.credential_endpoint = endpoint
    return this
  }

  public withDeferredCredentialEndpoint(endpoint: string): AuthorizationServerMetadataBuilder {
    this.metadata.deferred_credential_endpoint = endpoint
    return this
  }

  public build(): AuthorizationServerMetadata {
    if (!this.metadata.issuer) {
      throw new Error('Issuer is required')
    }

    if (!this.metadata.response_types_supported) {
      throw new Error('Response types supported is required')
    }

    return this.metadata as AuthorizationServerMetadata
  }
}
