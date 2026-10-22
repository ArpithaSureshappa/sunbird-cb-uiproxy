import axios from 'axios'
import express from 'express'
import { axiosRequestConfig } from '../configs/request.config'
import { CONSTANTS } from '../utils/env'
import { logDebug, logError } from '../utils/logger'

const GENERAL_ERROR_MSG = 'Failed to reach cios-content-service for the LTI OIDC authorize request'

export const ltiCios = express.Router()

// Proxies Moodle's authorize redirect to cios-content-service's LTI Platform
// authorize endpoint over the internal network, bypassing the public domain
// entirely for this hop. Deliberately builds an explicit header set rather
// than forwarding req.headers, so the incoming request's cookies are never
// relayed server-to-server.
ltiCios.get('/oidc/authorize', async (req, res) => {
  const targetUrl = `${CONSTANTS.CIOS_CONTENT_SERVICE_API_BASE}/ciosIntegration/v1/lti/oidc/authorize`
  logDebug('Proxying LTI OIDC authorize request to ' + targetUrl)
  try {
    const response = await axios.get(targetUrl, {
      ...axiosRequestConfig,
      headers: {
        Accept: 'text/html',
      },
      params: req.query,
    })
    res.status(response.status)
    res.set('Content-Type', response.headers['content-type'] || 'text/html')
    res.send(response.data)
  } catch (err) {
    if (err && err.response) {
      logError('LTI OIDC authorize proxy received an error response from cios-content-service: '
        + JSON.stringify(err.response.data))
      res.status(err.response.status)
      res.set('Content-Type', err.response.headers['content-type'] || 'application/json')
      res.send(err.response.data)
    } else {
      logError('LTI OIDC authorize proxy failed to reach cios-content-service: ' + JSON.stringify(err))
      res.status(502).json({ error: GENERAL_ERROR_MSG })
    }
  }
})
