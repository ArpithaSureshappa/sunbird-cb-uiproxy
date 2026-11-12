// Uses the REAL whitelistApis.ts data (not mocked) to verify the
// /ciosIntegration/lti/ssotest/:partnerCode entry is wired correctly end-to-end:
// registered with the right role check AND registered as a URL_PATTERN so the
// dynamic :partnerCode segment actually resolves at request time.

jest.mock('../../../src/utils/custom-keycloak', () => ({
  deauthenticateKeycloakSession: jest.fn().mockResolvedValue(undefined),
}))

import { isAllowed } from '../../../src/utils/apiWhiteList'
import { CONSTANTS } from '../../../src/utils/env'
import { API_LIST } from '../../../src/utils/whitelistApis'

const PATH_PATTERN = '/proxies/v8/ciosIntegration/lti/ssotest/:partnerCode'
const REAL_PATH = '/proxies/v8/ciosIntegration/lti/ssotest/IGOT-TESTINGLTI-OGDTD'

// tslint:disable-next-line: no-any
function buildRes() {
  const res: any = {}
  res.status = jest.fn().mockReturnValue(res)
  res.send = jest.fn().mockReturnValue(res)
  res.end = jest.fn().mockReturnValue(res)
  return res
}

// tslint:disable-next-line: no-any
function buildReq(path: string, overrides: any = {}): any {
  return { path, session: {}, ...overrides }
}

describe('whitelistApis: /ciosIntegration/lti/ssotest/:partnerCode entry', () => {
  it('is registered in API_LIST.URL with a role check requiring SPV_ADMIN', () => {
    // tslint:disable-next-line: no-any
    const entry = (API_LIST.URL as any)[PATH_PATTERN]
    expect(entry).toBeDefined()
    expect(entry.checksNeeded).toContain('ROLE_CHECK')
    expect(entry.ROLE_CHECK).toEqual(expect.arrayContaining(['SPV_ADMIN']))
  })

  it('is registered in API_LIST.URL_PATTERN so the :partnerCode segment resolves', () => {
    expect(API_LIST.URL_PATTERN).toContain(PATH_PATTERN)
  })
})

describe('isAllowed middleware against the real whitelist data for the LTI sso-test path', () => {
  const middleware = isAllowed()

  beforeEach(() => {
    // tslint:disable-next-line: no-any
    (CONSTANTS as any).PORTAL_API_WHITELIST_CHECK = 'true'
  })

  it('allows the request through when the session has the required role (SPV_ADMIN)', async () => {
    const next = jest.fn()
    const req = buildReq(REAL_PATH, { session: { userRoles: ['SPV_ADMIN'] } })
    middleware(req, buildRes(), next)
    // role checks resolve asynchronously
    await new Promise((resolve) => setImmediate(resolve))
    expect(next).toHaveBeenCalledTimes(1)
  })

  it('responds 403 when the session role is not SPV_ADMIN (e.g. MDO_ADMIN)', async () => {
    const next = jest.fn()
    const res = buildRes()
    const req = buildReq(REAL_PATH, { session: { userRoles: ['MDO_ADMIN'] } })
    middleware(req, res, next)
    await new Promise((resolve) => setImmediate(resolve))
    expect(next).not.toHaveBeenCalled()
    expect(res.status).toHaveBeenCalledWith(403)
  })

  it('responds 403 for an unrelated role (PUBLIC)', async () => {
    const next = jest.fn()
    const res = buildRes()
    const req = buildReq(REAL_PATH, { session: { userRoles: ['PUBLIC'] } })
    middleware(req, res, next)
    await new Promise((resolve) => setImmediate(resolve))
    expect(next).not.toHaveBeenCalled()
    expect(res.status).toHaveBeenCalledWith(403)
  })

  it('responds 403 when the session has no roles at all', async () => {
    const next = jest.fn()
    const res = buildRes()
    const req = buildReq(REAL_PATH, { session: {} })
    middleware(req, res, next)
    await new Promise((resolve) => setImmediate(resolve))
    expect(next).not.toHaveBeenCalled()
    expect(res.status).toHaveBeenCalledWith(403)
  })

  it('resolves different partnerCode values to the same whitelisted pattern', async () => {
    const next = jest.fn()
    const req = buildReq('/proxies/v8/ciosIntegration/lti/ssotest/ANOTHER-PARTNER-CODE', { session: { userRoles: ['SPV_ADMIN'] } })
    middleware(req, buildRes(), next)
    await new Promise((resolve) => setImmediate(resolve))
    expect(next).toHaveBeenCalledTimes(1)
  })
})
