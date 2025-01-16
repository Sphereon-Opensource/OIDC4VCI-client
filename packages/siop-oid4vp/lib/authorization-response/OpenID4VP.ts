import { IPresentationDefinition, PEX, PresentationSubmissionLocation } from '@sphereon/pex'
import { Format } from '@sphereon/pex-models'
import {
  CompactSdJwtVc,
  CredentialMapper,
  Hasher,
  IVerifiablePresentation,
  PresentationSubmission,
  W3CVerifiablePresentation,
  WrappedVerifiablePresentation,
} from '@sphereon/ssi-types'
import { DcqlPresentation, DcqlQuery } from 'dcql'

import { AuthorizationRequest } from '../authorization-request'
import { verifyRevocation } from '../helpers'
import {
  AuthorizationResponsePayload,
  IDTokenPayload,
  ResponseType,
  RevocationVerification,
  SIOPErrors,
  SupportedVersion,
  VerifiedOpenID4VPSubmission,
  VerifiedOpenID4VPSubmissionDcql,
} from '../types'

import { AuthorizationResponse } from './AuthorizationResponse'
import { Dcql } from './Dcql'
import { PresentationExchange } from './PresentationExchange'
import {
  AuthorizationResponseOpts,
  PresentationDefinitionWithLocation,
  PresentationVerificationCallback,
  VerifyAuthorizationResponseOpts,
  VPTokenLocation,
} from './types'

export const extractNonceFromWrappedVerifiablePresentation = (wrappedVp: WrappedVerifiablePresentation): string | undefined => {
  // SD-JWT uses kb-jwt for the nonce
  if (CredentialMapper.isWrappedSdJwtVerifiablePresentation(wrappedVp)) {
    // SD-JWT uses kb-jwt for the nonce
    // TODO: replace this once `kbJwt.payload` is available on the decoded sd-jwt (pr in ssi-sdk)
    // If it doesn't end with ~, it contains a kbJwt
    if (!wrappedVp.presentation.compactSdJwtVc.endsWith('~')) {
      return wrappedVp.presentation.kbJwt.payload.nonce
    }

    // No kb-jwt means no nonce (error will be handled later)
    return undefined
  }

  if (wrappedVp.format === 'jwt_vp') {
    return wrappedVp.decoded.nonce
  }

  // For LDP-VP a challenge is also fine
  if (wrappedVp.format === 'ldp_vp') {
    const w3cPresentation = wrappedVp.decoded as IVerifiablePresentation
    const proof = Array.isArray(w3cPresentation.proof) ? w3cPresentation.proof[0] : w3cPresentation.proof

    return proof.nonce ?? proof.challenge
  }

  return undefined
}

export const verifyPresentations = async (
  authorizationResponse: AuthorizationResponse,
  verifyOpts: VerifyAuthorizationResponseOpts,
): Promise<{ presentationExchange?: VerifiedOpenID4VPSubmission; dcql?: VerifiedOpenID4VPSubmissionDcql }> => {
  let idPayload: IDTokenPayload | undefined
  if (authorizationResponse.idToken) {
    idPayload = await authorizationResponse.idToken.payload()
  }

  let wrappedPresentations: WrappedVerifiablePresentation[] = []
  const presentationDefinitions = verifyOpts.presentationDefinitions
    ? Array.isArray(verifyOpts.presentationDefinitions)
      ? verifyOpts.presentationDefinitions
      : [verifyOpts.presentationDefinitions]
    : []

  let presentationSubmission: PresentationSubmission | undefined

  let dcqlPresentation: { [credentialQueryId: string]: WrappedVerifiablePresentation } | undefined

  let dcqlQuery = verifyOpts.dcqlQuery ?? authorizationResponse?.authorizationRequest?.payload.dcql_query
  if (dcqlQuery) {
    dcqlQuery = DcqlQuery.parse(dcqlQuery)
    dcqlPresentation = extractDcqlPresentationFromDcqlVpToken(authorizationResponse.payload.vp_token as string, { hasher: verifyOpts.hasher })
    wrappedPresentations = Object.values(dcqlPresentation)

    const verifiedPresentations = await Promise.all(
      wrappedPresentations.map((presentation) =>
        verifyOpts.verification.presentationVerificationCallback(presentation.original as W3CVerifiablePresentation),
      ),
    )

    await Dcql.assertValidDcqlPresentationResult(authorizationResponse.payload.vp_token as string, dcqlQuery, { hasher: verifyOpts.hasher })

    if (verifiedPresentations.some((verified) => !verified)) {
      const message = verifiedPresentations
        .map((verified) => verified.reason)
        .filter(Boolean)
        .join(', ')

      throw Error(`Failed to verify presentations. ${message}`)
    }
  } else {
    const presentations = authorizationResponse.payload.vp_token
      ? extractPresentationsFromVpToken(authorizationResponse.payload.vp_token, { hasher: verifyOpts.hasher })
      : []
    wrappedPresentations = Array.isArray(presentations) ? presentations : [presentations]

    // todo: Probably wise to check against request for the location of the submission_data
    presentationSubmission = idPayload?._vp_token?.presentation_submission ?? authorizationResponse.payload.presentation_submission

    await assertValidVerifiablePresentations({
      presentationDefinitions,
      presentations,
      verificationCallback: verifyOpts.verification.presentationVerificationCallback,
      opts: {
        presentationSubmission,
        restrictToFormats: verifyOpts.restrictToFormats,
        restrictToDIDMethods: verifyOpts.restrictToDIDMethods,
        hasher: verifyOpts.hasher,
      },
    })
  }

  const presentationsWithoutMdoc = wrappedPresentations.filter((p) => p.format !== 'mso_mdoc')
  const nonces = new Set(presentationsWithoutMdoc.map(extractNonceFromWrappedVerifiablePresentation))
  if (presentationsWithoutMdoc.length > 0 && nonces.size !== 1) {
    throw Error(`${nonces.size} nonce values found for ${presentationsWithoutMdoc.length}. Should be 1`)
  }

  // Nonce may be undefined in case there's only mdoc presentations (verified differently)
  const nonce = Array.from(nonces)[0] as string | undefined
  if (presentationsWithoutMdoc.length > 0 && typeof nonce !== 'string') {
    throw new Error('Expected all presentations to contain a nonce value')
  }

  const revocationVerification = verifyOpts.verification?.revocationOpts
    ? verifyOpts.verification.revocationOpts.revocationVerification
    : RevocationVerification.IF_PRESENT
  if (revocationVerification !== RevocationVerification.NEVER) {
    if (!verifyOpts.verification.revocationOpts?.revocationVerificationCallback) {
      throw Error(`Please provide a revocation callback as revocation checking of credentials and presentations is not disabled`)
    }
    for (const vp of wrappedPresentations) {
      await verifyRevocation(vp, verifyOpts.verification.revocationOpts.revocationVerificationCallback, revocationVerification)
    }
  }
  if (presentationDefinitions) {
    return { presentationExchange: { nonce, presentations: wrappedPresentations, presentationDefinitions, submissionData: presentationSubmission } }
  } else {
    return { dcql: { nonce, presentation: dcqlPresentation, dcqlQuery } }
  }
}

export const extractDcqlPresentationFromDcqlVpToken = (
  vpToken: DcqlPresentation.Input | string,
  opts?: { hasher?: Hasher },
): { [credentialQueryId: string]: WrappedVerifiablePresentation } => {
  const dcqlPresentation = Object.fromEntries(
    Object.entries(DcqlPresentation.parse(vpToken)).map(([credentialQueryId, vp]) => [
      credentialQueryId,
      CredentialMapper.toWrappedVerifiablePresentation(vp as W3CVerifiablePresentation | CompactSdJwtVc | string, { hasher: opts.hasher }),
    ]),
  )

  return dcqlPresentation
}

export const extractPresentationsFromDcqlVpToken = (
  vpToken: DcqlPresentation.Input | string,
  opts?: { hasher?: Hasher },
): WrappedVerifiablePresentation[] => {
  return Object.values(extractDcqlPresentationFromDcqlVpToken(vpToken, opts))
}

export const extractPresentationsFromVpToken = (
  vpToken: Array<W3CVerifiablePresentation | CompactSdJwtVc | string> | W3CVerifiablePresentation | CompactSdJwtVc | string,
  opts?: { hasher?: Hasher },
): WrappedVerifiablePresentation[] | WrappedVerifiablePresentation => {
  const tokens = Array.isArray(vpToken) ? vpToken : [vpToken]
  const wrappedTokens = tokens.map((vp) => CredentialMapper.toWrappedVerifiablePresentation(vp, { hasher: opts?.hasher }))

  return tokens.length === 1 ? wrappedTokens[0] : wrappedTokens
}

export const createPresentationSubmission = async (
  verifiablePresentations: W3CVerifiablePresentation[],
  opts?: { presentationDefinitions: (PresentationDefinitionWithLocation | IPresentationDefinition)[] },
): Promise<PresentationSubmission> => {
  let submission_data: PresentationSubmission
  for (const verifiablePresentation of verifiablePresentations) {
    const wrappedPresentation = CredentialMapper.toWrappedVerifiablePresentation(verifiablePresentation)

    let submission: PresentationSubmission | undefined =
      CredentialMapper.isWrappedW3CVerifiablePresentation(wrappedPresentation) &&
      (wrappedPresentation.presentation.presentation_submission ??
        wrappedPresentation.decoded.presentation_submission ??
        (typeof wrappedPresentation.original !== 'string' && wrappedPresentation.original.presentation_submission))
    if (typeof submission === 'string') {
      submission = JSON.parse(submission)
    }
    if (!submission && opts?.presentationDefinitions && !CredentialMapper.isWrappedMdocPresentation(wrappedPresentation)) {
      console.log(`No submission_data in VPs and not provided. Will try to deduce, but it is better to create the submission data beforehand`)
      for (const definitionOpt of opts.presentationDefinitions) {
        const definition = 'definition' in definitionOpt ? definitionOpt.definition : definitionOpt
        const result = new PEX().evaluatePresentation(definition, wrappedPresentation.original, {
          generatePresentationSubmission: true,
          presentationSubmissionLocation: PresentationSubmissionLocation.EXTERNAL,
        })
        if (result.areRequiredCredentialsPresent) {
          submission = result.value
          break
        }
      }
    }
    if (!submission) {
      throw Error('Verifiable Presentation has no submission_data, it has not been provided separately, and could also not be deduced')
    }
    // let's merge all submission data into one object
    if (!submission_data) {
      submission_data = submission
    } else {
      // We are pushing multiple descriptors into one submission_data, as it seems this is something which is assumed in OpenID4VP, but not supported in Presentation Exchange (a single VP always has a single submission_data)
      Array.isArray(submission_data.descriptor_map)
        ? submission_data.descriptor_map.push(...submission.descriptor_map)
        : (submission_data.descriptor_map = [...submission.descriptor_map])
    }
  }
  if (typeof submission_data === 'string') {
    submission_data = JSON.parse(submission_data)
  }
  return submission_data
}

export const putPresentationSubmissionInLocation = async (
  authorizationRequest: AuthorizationRequest,
  responsePayload: AuthorizationResponsePayload,
  resOpts: AuthorizationResponseOpts,
  idTokenPayload?: IDTokenPayload,
): Promise<void> => {
  const version = await authorizationRequest.getSupportedVersion()
  const idTokenType = await authorizationRequest.containsResponseType(ResponseType.ID_TOKEN)
  const authResponseType = await authorizationRequest.containsResponseType(ResponseType.VP_TOKEN)
  // const requestPayload = await authorizationRequest.mergedPayloads();
  if (!resOpts.presentationExchange) {
    return
  } else if (resOpts.presentationExchange.verifiablePresentations.length === 0) {
    throw Error('Presentation Exchange options set, but no verifiable presentations provided')
  }
  if (
    !resOpts.presentationExchange.presentationSubmission &&
    (!resOpts.presentationExchange.verifiablePresentations || resOpts.presentationExchange.verifiablePresentations.length === 0)
  ) {
    throw Error(`Either a presentationSubmission or verifiable presentations are needed at this point`)
  }
  const submissionData =
    resOpts.presentationExchange.presentationSubmission ??
    (await createPresentationSubmission(resOpts.presentationExchange.verifiablePresentations, {
      presentationDefinitions: await authorizationRequest.getPresentationDefinitions(),
    }))

  const location =
    resOpts.presentationExchange?.vpTokenLocation ??
    (idTokenType && version < SupportedVersion.SIOPv2_D11 ? VPTokenLocation.ID_TOKEN : VPTokenLocation.AUTHORIZATION_RESPONSE)

  switch (location) {
    case VPTokenLocation.TOKEN_RESPONSE: {
      throw Error('Token response for VP token is not supported yet')
    }
    case VPTokenLocation.ID_TOKEN: {
      if (!idTokenPayload) {
        throw Error('Cannot place submission data _vp_token in id token if no id token is present')
      } else if (version >= SupportedVersion.SIOPv2_D11) {
        throw Error(`This version of the OpenID4VP spec does not allow to store the vp submission data in the ID token`)
      } else if (!idTokenType) {
        throw Error(`Cannot place vp token in ID token as the RP didn't provide an "openid" scope in the request`)
      }
      if (idTokenPayload._vp_token?.presentation_submission) {
        if (submissionData !== idTokenPayload._vp_token.presentation_submission) {
          throw Error('Different submission data was provided as an option, but exising submission data was already present in the id token')
        }
      } else {
        if (!idTokenPayload._vp_token) {
          idTokenPayload._vp_token = { presentation_submission: submissionData }
        } else {
          idTokenPayload._vp_token.presentation_submission = submissionData
        }
      }
      break
    }
    case VPTokenLocation.AUTHORIZATION_RESPONSE: {
      if (!authResponseType) {
        throw Error('Cannot place vp token in Authorization Response as there is no vp_token scope in the auth request')
      }
      if (responsePayload.presentation_submission) {
        if (submissionData !== responsePayload.presentation_submission) {
          throw Error(
            'Different submission data was provided as an option, but exising submission data was already present in the authorization response',
          )
        }
      } else {
        responsePayload.presentation_submission = submissionData
      }
    }
  }

  responsePayload.vp_token =
    resOpts.presentationExchange?.verifiablePresentations.length === 1
      ? resOpts.presentationExchange.verifiablePresentations[0]
      : resOpts.presentationExchange?.verifiablePresentations
}

export const assertValidVerifiablePresentations = async (args: {
  presentationDefinitions: PresentationDefinitionWithLocation[]
  presentations: Array<WrappedVerifiablePresentation> | WrappedVerifiablePresentation
  verificationCallback: PresentationVerificationCallback
  opts?: {
    limitDisclosureSignatureSuites?: string[]
    restrictToFormats?: Format
    restrictToDIDMethods?: string[]
    presentationSubmission?: PresentationSubmission
    hasher?: Hasher
  }
}): Promise<void> => {
  const { presentations } = args
  if (!presentations || (Array.isArray(presentations) && presentations.length === 0)) {
    return Promise.reject(Error('missing presentation(s)'))
  }

  // Handle mdocs, keep them out of pex
  let presentationsArray = Array.isArray(presentations) ? presentations : [presentations]
  if (presentationsArray.every((p) => p.format === 'mso_mdoc')) {
    return
  }
  presentationsArray = presentationsArray.filter((p) => p.format !== 'mso_mdoc')

  if (
    (!args.presentationDefinitions || args.presentationDefinitions.filter((a) => a.definition).length === 0) &&
    (!presentationsArray || (Array.isArray(presentationsArray) && presentationsArray.filter((vp) => vp.presentation).length === 0))
  ) {
    return
  }
  PresentationExchange.assertValidPresentationDefinitionWithLocations(args.presentationDefinitions)

  if (
    args.presentationDefinitions &&
    args.presentationDefinitions.length &&
    (!presentationsArray || (Array.isArray(presentationsArray) && presentationsArray.length === 0))
  ) {
    return Promise.reject(Error(SIOPErrors.AUTH_REQUEST_EXPECTS_VP))
  } else if (
    (!args.presentationDefinitions || args.presentationDefinitions.length === 0) &&
    presentationsArray &&
    ((Array.isArray(presentationsArray) && presentationsArray.length > 0) || !Array.isArray(presentationsArray))
  ) {
    return Promise.reject(Error(SIOPErrors.AUTH_REQUEST_DOESNT_EXPECT_VP))
  } else if (args.presentationDefinitions && !args.opts.presentationSubmission) {
    return Promise.reject(Error(`No presentation submission present. Please use presentationSubmission opt argument!`))
  } else if (args.presentationDefinitions && presentationsArray) {
    await PresentationExchange.validatePresentationsAgainstDefinitions(
      args.presentationDefinitions,
      args.presentations,
      args.verificationCallback,
      args.opts,
    )
  }
}
