import {
  IPresentationDefinition,
  KeyEncoding,
  PEX,
  PresentationSubmissionLocation,
  SelectResults,
  Status,
  Validated,
  VerifiablePresentationFromOpts,
  VerifiablePresentationResult,
} from '@sphereon/pex'
import { PresentationEvaluationResults } from '@sphereon/pex/dist/main/lib/evaluation'
import { Format, PresentationDefinitionV1, PresentationDefinitionV2, PresentationSubmission } from '@sphereon/pex-models'
import {
  CredentialMapper,
  Hasher,
  IProofPurpose,
  IProofType,
  OriginalVerifiableCredential,
  OriginalVerifiablePresentation,
  W3CVerifiablePresentation,
  WrappedVerifiablePresentation,
} from '@sphereon/ssi-types'

import { extractDataFromPath, getWithUrl } from '../helpers'
import { AuthorizationRequestPayload, SIOPErrors, SupportedVersion } from '../types'

import {
  PresentationDefinitionLocation,
  PresentationDefinitionWithLocation,
  PresentationSignCallback,
  PresentationVerificationCallback,
  PresentationVerificationResult,
} from './types'

export class PresentationExchange {
  readonly pex: PEX
  readonly allVerifiableCredentials: OriginalVerifiableCredential[]
  readonly allDIDs

  constructor(opts: { allDIDs?: string[]; allVerifiableCredentials: OriginalVerifiableCredential[]; hasher?: Hasher }) {
    this.allDIDs = opts.allDIDs
    this.allVerifiableCredentials = opts.allVerifiableCredentials
    this.pex = new PEX({ hasher: opts.hasher })
  }

  /**
   * Construct presentation submission from selected credentials
   * @param presentationDefinition payload object received by the OP from the RP
   * @param selectedCredentials
   * @param presentationSignCallback
   * @param options
   */
  public async createVerifiablePresentation(
    presentationDefinition: IPresentationDefinition,
    selectedCredentials: OriginalVerifiableCredential[],
    presentationSignCallback: PresentationSignCallback,
    // options2?: { nonce?: string; domain?: string, proofType?: IProofType, verificationMethod?: string, signatureKeyEncoding?: KeyEncoding },
    options?: VerifiablePresentationFromOpts,
  ): Promise<VerifiablePresentationResult> {
    if (!presentationDefinition) {
      throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID)
    }

    const signOptions: VerifiablePresentationFromOpts = {
      ...options,
      presentationSubmissionLocation: PresentationSubmissionLocation.EXTERNAL,
      proofOptions: {
        ...options?.proofOptions,
        proofPurpose: options?.proofOptions?.proofPurpose ?? IProofPurpose.authentication,
        type: options?.proofOptions?.type ?? IProofType.EcdsaSecp256k1Signature2019,
        /* challenge: options?.proofOptions?.challenge,
        domain: options?.proofOptions?.domain,*/
      },
      signatureOptions: {
        ...options?.signatureOptions,
        // verificationMethod: options?.signatureOptions?.verificationMethod,
        keyEncoding: options?.signatureOptions?.keyEncoding ?? KeyEncoding.Hex,
      },
    }

    // When there are MDoc credentials among the selected ones, filter those out as pex does not support mdoc credentials
    const filteredCredentials = this.removeMDocCredentials(selectedCredentials)
    return await this.pex.verifiablePresentationFrom(presentationDefinition, filteredCredentials, presentationSignCallback, signOptions)
  }

  private removeMDocCredentials(selectedCredentials: OriginalVerifiableCredential[]) {
    return selectedCredentials.filter((vc) => !CredentialMapper.isMsoMdocDecodedCredential(vc) && !CredentialMapper.isMsoMdocOid4VPEncoded(vc))
  }

  /**
   * This method will be called from the OP when we are certain that we have a
   * PresentationDefinition object inside our requestPayload
   * Finds a set of `VerifiableCredential`s from a list supplied to this class during construction,
   * matching presentationDefinition object found in the requestPayload
   * if requestPayload doesn't contain any valid presentationDefinition throws an error
   * if PEX library returns any error in the process, throws the error
   * returns the SelectResults object if successful
   * @param presentationDefinition object received by the OP from the RP
   * @param opts
   */
  public async selectVerifiableCredentialsForSubmission(
    presentationDefinition: IPresentationDefinition,
    opts?: {
      holderDIDs?: string[]
      restrictToFormats?: Format
      restrictToDIDMethods?: string[]
    },
  ): Promise<SelectResults> {
    if (!presentationDefinition) {
      throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID)
    } else if (!this.allVerifiableCredentials || this.allVerifiableCredentials.length == 0) {
      throw new Error(`${SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD}, no VCs were provided`)
    }

    const selectResults: SelectResults = this.pex.selectFrom(presentationDefinition, this.allVerifiableCredentials, {
      ...opts,
      holderDIDs: opts?.holderDIDs ?? this.allDIDs,
      // fixme limited disclosure
      limitDisclosureSignatureSuites: [],
    })
    if (selectResults.areRequiredCredentialsPresent === Status.ERROR) {
      throw new Error(`message: ${SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD}, details: ${JSON.stringify(selectResults.errors)}`)
    }
    return selectResults
  }

  /**
   * validatePresentationAgainstDefinition function is called mainly by the RP
   * after receiving the VP from the OP
   * @param presentationDefinition object containing PD
   * @param verifiablePresentation
   * @param opts
   */
  public static async validatePresentationAgainstDefinition(
    presentationDefinition: IPresentationDefinition,
    verifiablePresentation: OriginalVerifiablePresentation | WrappedVerifiablePresentation,
    opts?: {
      limitDisclosureSignatureSuites?: string[]
      restrictToFormats?: Format
      restrictToDIDMethods?: string[]
      presentationSubmission?: PresentationSubmission
      hasher?: Hasher
    },
  ): Promise<PresentationEvaluationResults> {
    const wvp: WrappedVerifiablePresentation =
      typeof verifiablePresentation === 'object' && 'original' in verifiablePresentation
        ? (verifiablePresentation as WrappedVerifiablePresentation)
        : CredentialMapper.toWrappedVerifiablePresentation(verifiablePresentation as OriginalVerifiablePresentation)
    if (!presentationDefinition) {
      throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID)
    } else if (
      !wvp ||
      !wvp.presentation ||
      (CredentialMapper.isWrappedW3CVerifiablePresentation(wvp) &&
        (!wvp.presentation.verifiableCredential || wvp.presentation.verifiableCredential.length === 0))
    ) {
      throw new Error(SIOPErrors.NO_VERIFIABLE_PRESENTATION_NO_CREDENTIALS)
    }

    const evaluationResults = new PEX({ hasher: opts?.hasher }).evaluatePresentation(presentationDefinition, wvp.original, opts)
    if (evaluationResults.errors?.length) {
      throw new Error(`message: ${SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD}, details: ${JSON.stringify(evaluationResults.errors)}`)
    }
    return evaluationResults
  }

  public static assertValidPresentationSubmission(presentationSubmission: PresentationSubmission) {
    const validationResult: Validated = PEX.validateSubmission(presentationSubmission)
    if (
      (Array.isArray(validationResult) && validationResult[0].message != 'ok') ||
      (!Array.isArray(validationResult) && validationResult.message != 'ok')
    ) {
      throw new Error(`${SIOPErrors.RESPONSE_OPTS_PRESENTATIONS_SUBMISSION_IS_NOT_VALID}, details ${JSON.stringify(validationResult)}`)
    }
  }

  /**
   * Finds a valid PresentationDefinition inside the given AuthenticationRequestPayload
   * throws exception if the PresentationDefinition is not valid
   * returns null if no property named "presentation_definition" is found
   * returns a PresentationDefinition if a valid instance found
   * @param authorizationRequestPayload object that can have a presentation_definition inside
   * @param version
   */
  public static async findValidPresentationDefinitions(
    authorizationRequestPayload: AuthorizationRequestPayload,
    version?: SupportedVersion,
  ): Promise<PresentationDefinitionWithLocation[]> {
    const allDefinitions: PresentationDefinitionWithLocation[] = []

    async function extractDefinitionFromVPToken() {
      const vpTokens: PresentationDefinitionV1[] | PresentationDefinitionV2[] = extractDataFromPath(
        authorizationRequestPayload,
        '$..vp_token.presentation_definition',
      ).map((d) => d.value)
      const vpTokenRefs = extractDataFromPath(authorizationRequestPayload, '$..vp_token.presentation_definition_uri')
      if (vpTokens && vpTokens.length && vpTokenRefs && vpTokenRefs.length) {
        throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_NON_EXCLUSIVE)
      }
      if (vpTokens && vpTokens.length) {
        vpTokens.forEach((vpToken: PresentationDefinitionV1 | PresentationDefinitionV2) => {
          if (allDefinitions.find((value) => value.definition.id === vpToken.id)) {
            console.log(
              `Warning. We encountered presentation definition with id ${vpToken.id}, more then once whilst processing! Make sure your payload is valid!`,
            )
            return
          }
          PresentationExchange.assertValidPresentationDefinition(vpToken)
          allDefinitions.push({
            definition: vpToken,
            location: PresentationDefinitionLocation.CLAIMS_VP_TOKEN,
            version,
          })
        })
      } else if (vpTokenRefs && vpTokenRefs.length) {
        for (const vpTokenRef of vpTokenRefs) {
          const pd: PresentationDefinitionV1 | PresentationDefinitionV2 = (await getWithUrl(vpTokenRef.value)) as unknown as
            | PresentationDefinitionV1
            | PresentationDefinitionV2
          if (allDefinitions.find((value) => value.definition.id === pd.id)) {
            console.log(
              `Warning. We encountered presentation definition with id ${pd.id}, more then once whilst processing! Make sure your payload is valid!`,
            )
            return
          }
          PresentationExchange.assertValidPresentationDefinition(pd)
          allDefinitions.push({ definition: pd, location: PresentationDefinitionLocation.CLAIMS_VP_TOKEN, version })
        }
      }
    }

    function addSingleToplevelPDToPDs(definition: IPresentationDefinition, version?: SupportedVersion): void {
      if (allDefinitions.find((value) => value.definition.id === definition.id)) {
        console.log(
          `Warning. We encountered presentation definition with id ${definition.id}, more then once whilst processing! Make sure your payload is valid!`,
        )
        return
      }
      PresentationExchange.assertValidPresentationDefinition(definition)
      allDefinitions.push({
        definition,
        location: PresentationDefinitionLocation.TOPLEVEL_PRESENTATION_DEF,
        version,
      })
    }

    async function extractDefinitionFromTopLevelDefinitionProperty(version?: SupportedVersion) {
      const definitions = extractDataFromPath(authorizationRequestPayload, '$.presentation_definition')
      const definitionsFromList = extractDataFromPath(authorizationRequestPayload, '$.presentation_definition[*]')
      const definitionRefs = extractDataFromPath(authorizationRequestPayload, '$.presentation_definition_uri')
      const definitionRefsFromList = extractDataFromPath(authorizationRequestPayload, '$.presentation_definition_uri[*]')
      const hasPD = (definitions && definitions.length > 0) || (definitionsFromList && definitionsFromList.length > 0)
      const hasPdRef = (definitionRefs && definitionRefs.length > 0) || (definitionRefsFromList && definitionRefsFromList.length > 0)
      if (hasPD && hasPdRef) {
        throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_NON_EXCLUSIVE)
      }
      if (definitions && definitions.length > 0) {
        definitions.forEach((definition) => {
          addSingleToplevelPDToPDs(definition.value, version)
        })
      } else if (definitionsFromList && definitionsFromList.length > 0) {
        definitionsFromList.forEach((definition) => {
          addSingleToplevelPDToPDs(definition.value, version)
        })
      } else if (definitionRefs && definitionRefs.length > 0) {
        for (const definitionRef of definitionRefs) {
          const pd: PresentationDefinitionV1 | PresentationDefinitionV2 = await getWithUrl(definitionRef.value)
          addSingleToplevelPDToPDs(pd, version)
        }
      } else if (definitionsFromList && definitionRefsFromList.length > 0) {
        for (const definitionRef of definitionRefsFromList) {
          const pd: PresentationDefinitionV1 | PresentationDefinitionV2 = await getWithUrl(definitionRef.value)
          addSingleToplevelPDToPDs(pd, version)
        }
      }
    }

    if (authorizationRequestPayload) {
      if (!version || version < SupportedVersion.SIOPv2_D11) {
        await extractDefinitionFromVPToken()
      }
      await extractDefinitionFromTopLevelDefinitionProperty()
    }
    return allDefinitions
  }

  public static assertValidPresentationDefinitionWithLocations(definitionsWithLocations: PresentationDefinitionWithLocation[]) {
    if (definitionsWithLocations && definitionsWithLocations.length > 0) {
      definitionsWithLocations.forEach((definitionWithLocation) =>
        PresentationExchange.assertValidPresentationDefinition(definitionWithLocation.definition),
      )
    }
  }

  private static assertValidPresentationDefinition(presentationDefinition: IPresentationDefinition) {
    const validationResult = PEX.validateDefinition(presentationDefinition)
    if (
      (Array.isArray(validationResult) && validationResult[0].message != 'ok') ||
      (!Array.isArray(validationResult) && validationResult.message != 'ok')
    ) {
      throw new Error(`${SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID}`)
    }
  }

  static async validatePresentationsAgainstDefinitions(
    definitions: PresentationDefinitionWithLocation[],
    vpPayloads: Array<WrappedVerifiablePresentation> | WrappedVerifiablePresentation,
    verifyPresentationCallback?: PresentationVerificationCallback | undefined,
    opts?: {
      limitDisclosureSignatureSuites?: string[]
      restrictToFormats?: Format
      restrictToDIDMethods?: string[]
      presentationSubmission?: PresentationSubmission
      hasher?: Hasher
    },
  ) {
    if (!definitions || !vpPayloads || (Array.isArray(vpPayloads) && vpPayloads.length === 0) || !definitions.length) {
      throw new Error(SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD)
    }
    await Promise.all(
      definitions.map(
        async (pd) => await PresentationExchange.validatePresentationsAgainstDefinition(pd.definition, vpPayloads, verifyPresentationCallback, opts),
      ),
    )
  }

  static async validatePresentationsAgainstDefinition(
    definition: IPresentationDefinition,
    vpPayloads: Array<WrappedVerifiablePresentation> | WrappedVerifiablePresentation,
    verifyPresentationCallback?: PresentationVerificationCallback,
    opts?: {
      limitDisclosureSignatureSuites?: string[]
      restrictToFormats?: Format
      restrictToDIDMethods?: string[]
      presentationSubmission?: PresentationSubmission
      hasher?: Hasher
    },
  ) {
    const pex = new PEX({ hasher: opts?.hasher })
    const vpPayloadsArray = Array.isArray(vpPayloads) ? vpPayloads : [vpPayloads]

    let evaluationResults: PresentationEvaluationResults | undefined = undefined
    if (opts?.presentationSubmission) {
      evaluationResults = pex.evaluatePresentation(
        definition,
        // It's important the structure matches what we received so it can be correctly matched against the submission
        Array.isArray(vpPayloads) ? vpPayloads.map((wvp) => wvp.original) : vpPayloads.original,
        {
          ...opts,
          presentationSubmissionLocation: PresentationSubmissionLocation.EXTERNAL,
        },
      )
    } else {
      for (const wvp of vpPayloadsArray) {
        if (CredentialMapper.isWrappedW3CVerifiablePresentation(wvp) && wvp.presentation.presentation_submission) {
          const presentationSubmission = wvp.presentation.presentation_submission
          evaluationResults = pex.evaluatePresentation(definition, wvp.original, {
            ...opts,
            presentationSubmission,
            presentationSubmissionLocation: PresentationSubmissionLocation.PRESENTATION,
          })
          const submission = evaluationResults.value

          // Found valid submission
          if (evaluationResults.areRequiredCredentialsPresent && submission && submission.definition_id === definition.id) break
        }
      }
    }

    if (!evaluationResults) {
      throw new Error(SIOPErrors.NO_PRESENTATION_SUBMISSION)
    }

    if (
      evaluationResults.areRequiredCredentialsPresent === Status.ERROR ||
      (evaluationResults.errors && evaluationResults.errors.length > 0) ||
      !evaluationResults.value
    ) {
      throw new Error(`message: ${SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD}, details: ${JSON.stringify(evaluationResults.errors)}`)
    }

    if (evaluationResults.value.definition_id !== definition.id) {
      throw new Error(
        `${SIOPErrors.PRESENTATION_SUBMISSION_DEFINITION_ID_DOES_NOT_MATCHING_DEFINITION_ID}. submission.definition_id: ${evaluationResults.value.definition_id}, definition.id: ${definition.id}`,
      )
    }

    const presentationsToVerify = evaluationResults.presentations
    // The verifyPresentationCallback function is mandatory for RP only,
    // So the behavior here is to bypass it if not present
    if (verifyPresentationCallback && evaluationResults.value !== undefined) {
      // Verify the signature of all VPs
      await Promise.all(
        presentationsToVerify.map(async (presentation) => {
          let verificationResult: PresentationVerificationResult
          try {
            verificationResult = await verifyPresentationCallback(presentation as W3CVerifiablePresentation, evaluationResults.value!)
          } catch (error: unknown) {
            const errorMessage = error instanceof Error ? error.message : String(error)
            throw new Error(`${SIOPErrors.VERIFIABLE_PRESENTATION_SIGNATURE_NOT_VALID}: ${errorMessage}`)
          }

          if (!verificationResult.verified) {
            throw new Error(
              SIOPErrors.VERIFIABLE_PRESENTATION_SIGNATURE_NOT_VALID + (verificationResult.reason ? `. ${verificationResult.reason}` : ''),
            )
          }
        }),
      )
    }

    PresentationExchange.assertValidPresentationSubmission(evaluationResults.value)

    return evaluationResults
  }
}
