export {
  WebAuthnParseError,
  WEBAUTHN_PARSE_LIMITS,
  type WebAuthnParseErrorCode,
} from "./errors.js";
export {
  parseCoseP256PublicKey,
  parseAuthenticatorData,
  parseNoneAttestationObject,
  derToP256Signature,
  type WebAuthnCeremony,
  type ParsedP256PublicKey,
  type ParsedAuthenticatorData,
  type ParsedNoneAttestation,
} from "./parsers.js";
export { parseClientDataJSON, type ParsedClientData } from "./client-data.js";
export {
  WebAuthnBrowserError,
  type WebAuthnBrowserErrorCode,
} from "./browser-errors.js";
export {
  webAuthnCapabilities,
  createPasskeyCredential,
  getPasskeyAssertion,
  type WebAuthnCapabilities,
  type PasskeyCeremonyOptions,
  type PasskeyRegistrationOptions,
  type PasskeyAssertionOptions,
} from "./ceremonies.js";
export {
  serializePasskeyRegistration,
  serializePasskeyAssertion,
  type SerializedPasskeyRegistration,
  type SerializedPasskeyAssertion,
} from "./serialization.js";
