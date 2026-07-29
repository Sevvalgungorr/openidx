// MFA API client with proper error handling for authentication failures
import { api } from '../lib/api'
import axios from 'axios'

// Types
export interface WebAuthnCredential {
  id: string
  credential_id: string
  friendly_name: string
  authenticator: string
  is_passkey: boolean
  backup_eligible: boolean
  backup_state: boolean
  created_at: string
  last_used_at?: string
}

export interface WebAuthnRegisterBeginRequest {
  username: string
  display_name: string
  friendly_name?: string
}

export interface WebAuthnRegisterFinishRequest {
  response: string // JSON string of CredentialCreationResponse
}

export interface WebAuthnRegisterBeginResponse {
  status: string
  message: string
  options: {
    publicKey: {
      rp: { name: string; id?: string }
      user: { id: string; name: string; displayName: string }
      challenge: string
      pubKeyCredParams: { type: string; alg: number }[]
      timeout?: number
      excludeCredentials?: Array<{ id: string; type: string }>
      authenticatorSelection?: {
        authenticatorAttachment?: AuthenticatorAttachment
        requireResidentKey?: boolean
        residentKey?: ResidentKeyRequirement
        userVerification?: UserVerificationRequirement
      }
      attestation?: AttestationConveyancePreference
    }
  }
}

export interface WebAuthnRegisterFinishResponse {
  success: boolean
  credential_id: string
  friendly_name: string
  message: string
}

export interface WebAuthnLoginBeginRequest {
  user_id: string
}

export interface WebAuthnLoginBeginResponse {
  status: string
  message: string
  options: {
    publicKey: {
      challenge: string
      timeout?: number
      rpId?: string
      allowCredentials?: Array<{ id: string; type: string }>
      userVerification?: string
    }
  }
}

export interface WebAuthnLoginFinishRequest {
  user_id: string
  response: string // JSON string of CredentialAssertionResponse
}

export interface WebAuthnLoginFinishResponse {
  success: boolean
  message: string
  credential_id: string
  friendly_name: string
}

export interface RenameCredentialRequest {
  friendly_name: string
}

export interface APIError {
  error: string
  message?: string
}

// MFA API client
export const mfaApi = {
  /**
   * List all WebAuthn credentials for the authenticated user
   * Uses JWT token for authentication (no user_id parameter needed)
   */
  listWebAuthnCredentials: async (): Promise<WebAuthnCredential[]> => {
    try {
      const response = await api.get<{ credentials: WebAuthnCredential[]; count: number }>(
        '/api/v1/identity/mfa/webauthn/credentials'
      )
      return response.credentials || []
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 401) {
        throw new Error('Authentication required. Please log in again.')
      }
      if (axios.isAxiosError(error) && error.response?.status === 403) {
        throw new Error('You do not have permission to access these credentials.')
      }
      throw error
    }
  },

  /**
   * Begin WebAuthn registration for the authenticated user
   */
  beginWebAuthnRegistration: async (
    request: WebAuthnRegisterBeginRequest
  ): Promise<WebAuthnRegisterBeginResponse> => {
    try {
      return await api.post<WebAuthnRegisterBeginResponse>(
        '/api/v1/identity/mfa/webauthn/register/begin',
        request
      )
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 401) {
        throw new Error('Authentication required. Please log in again.')
      }
      throw error
    }
  },

  /**
   * Finish WebAuthn registration
   */
  finishWebAuthnRegistration: async (
    request: WebAuthnRegisterFinishRequest
  ): Promise<WebAuthnRegisterFinishResponse> => {
    try {
      return await api.post<WebAuthnRegisterFinishResponse>(
        '/api/v1/identity/mfa/webauthn/register/finish',
        request
      )
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 401) {
        throw new Error('Authentication required. Please log in again.')
      }
      throw error
    }
  },

  /**
   * Delete a WebAuthn credential
   * Ownership is verified server-side using JWT token
   */
  deleteWebAuthnCredential: async (credentialId: string): Promise<void> => {
    try {
      await api.delete<void>(`/api/v1/identity/mfa/webauthn/credentials/${credentialId}`)
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 401) {
        throw new Error('Authentication required. Please log in again.')
      }
      if (axios.isAxiosError(error) && error.response?.status === 403) {
        throw new Error('You do not have permission to delete this credential.')
      }
      if (axios.isAxiosError(error) && error.response?.status === 404) {
        throw new Error('Credential not found.')
      }
      throw error
    }
  },

  /**
   * Rename a WebAuthn credential
   * Ownership is verified server-side using JWT token
   */
  renameWebAuthnCredential: async (
    credentialId: string,
    request: RenameCredentialRequest
  ): Promise<void> => {
    try {
      await api.put<void>(
        `/api/v1/identity/mfa/webauthn/credentials/${credentialId}/name`,
        request
      )
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 401) {
        throw new Error('Authentication required. Please log in again.')
      }
      if (axios.isAxiosError(error) && error.response?.status === 403) {
        throw new Error('You do not have permission to modify this credential.')
      }
      if (axios.isAxiosError(error) && error.response?.status === 404) {
        throw new Error('Credential not found.')
      }
      throw error
    }
  },

  /**
   * Begin WebAuthn authentication (login)
   */
  beginWebAuthnLogin: async (
    request: WebAuthnLoginBeginRequest
  ): Promise<WebAuthnLoginBeginResponse> => {
    try {
      return await api.post<WebAuthnLoginBeginResponse>(
        '/api/v1/identity/mfa/webauthn/authenticate/begin',
        request
      )
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 401) {
        throw new Error('Authentication required. Please log in again.')
      }
      throw error
    }
  },

  /**
   * Finish WebAuthn authentication (login)
   */
  finishWebAuthnLogin: async (
    request: WebAuthnLoginFinishRequest
  ): Promise<WebAuthnLoginFinishResponse> => {
    try {
      return await api.post<WebAuthnLoginFinishResponse>(
        '/api/v1/identity/mfa/webauthn/authenticate/finish',
        request
      )
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 401) {
        throw new Error('Authentication failed. Please try again.')
      }
      throw error
    }
  },
}

export default mfaApi
