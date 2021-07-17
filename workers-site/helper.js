/**
* Parse HTTP Basic Authorization value.
* 元ソース: https://github.com/cloudflare/cloudflare-docs/blob/production/products/workers/src/content/examples/basic-auth.md
* @param {Request} request
* @returns {{ user: string, pass: string , error: string}}
*/
export function parseBasicAuthenticationParams(request) {
  const Authorization = request.headers.get('Authorization')
  
  const [scheme, encoded] = Authorization.split(' ')
  
  // The Authorization header must start with "Basic", followed by a space.
  if (!encoded || scheme !== 'Basic') {
    return { 
      user: null,
      pass: null,
      error: 'Malformed authorization header.'
    }
  }
  
  // Decodes the base64 value and performs unicode normalization.
  // @see https://datatracker.ietf.org/doc/html/rfc7613#section-3.3.2 (and #section-4.2.2)
  // @see https://dev.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String/normalize
  const decoded = atob(encoded).normalize()
  
  // The username & password are split by the first colon.
  //=> example: "username:password"
  const index = decoded.indexOf(':')
  
  // The user & password are split by the first colon and MUST NOT contain control characters.
  // @see https://tools.ietf.org/html/rfc5234#appendix-B.1 (=> "CTL = %x00-1F / %x7F")
  if (index === -1 || /[\0-\x1F\x7F]/.test(decoded)) {
    return { 
      user: null,
      pass: null,
      error: 'Invalid authorization value.'
    }
  }
  
  return { 
    user: decoded.substring(0, index),
    pass: decoded.substring(index + 1),
    error: null
  }
}
