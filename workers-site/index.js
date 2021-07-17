import { getAssetFromKV } from '@cloudflare/kv-asset-handler'
import{ parseBasicAuthenticationParams } from './helper'

// Basic認証用ユーザ情報
const BASIC_USER = "testuser"
const BASIC_PASS = "testpass"


addEventListener('fetch', event => {
  event.respondWith(handleEvent(event).catch(
    new Response("Unknown Error", {status: 500})
  ))
})

async function handleEvent(event) {
  const request = event.request
  const { protocol:request_protocol, pathname:request_path } = new URL(request.url)

  if (request_protocol !== 'https:' || request.headers.get('X-Forwarded-Proto' !== 'https')) {
    return createBadRequestResponse("Please Use a HTTPS connection.")
  }
  switch (request_path) {
    case '/logout':
      return createUnauthorizedResponse("Logged out.")

    default:
      // Basic認証
      if (request.headers.has('Authorization')) {
        // 認証パラメータに不正な文字は無いか?
        const { user, pass, error } = parseBasicAuthenticationParams(request)
        if (error !== null) {
          return createBasicAuthRequiredResponse(error)
        }
        // ユーザ,パスワードが正しいか?
        if (user !== BASIC_USER || pass !== BASIC_PASS) {
          return createBasicAuthRequiredResponse("Invalid user.")
        }
      } else {
        return createBasicAuthRequiredResponse("Authentication required.")
      }

      // 認証をパスできた場合
      try {
        // KVからコンテンツファイル取得
        const content = await getAssetFromKV(event, null)

        // セキュリティ対策用ヘッダいろいろ
        const response = new Response(content.body, content)
        response.headers.set('X-XSS-Protection', '1; mode=block')
        response.headers.set('X-Content-Type-Options', 'nosniff')
        response.headers.set('X-Frame-Options', 'DENY')
        response.headers.set('Referrer-Policy', 'unsafe-url')
        response.headers.set('Feature-Policy', 'none')

        return response
      } catch (ex) {
        // コンテンツファイルが見つからなかった場合は/404.htmlに飛ばす
        let notFoundResponse = await getAssetFromKV(event, {
          mapRequestToAsset: mapReq => new Request(`${new URL(mapReq.url).origin}/404.html`, mapReq)
        })
        return new Response(notFoundResponse.body, { ...notFoundResponse, status: 404 })
      }
  }
}


// ヘルパー関数っぽいものたち
function createUnauthorizedResponse(message) {
  return new Response(message, {status: 401})
}

function createBasicAuthRequiredResponse(message) {
  return new Response(message, {status: 401, headers: {'WWW-Authenticate': 'Basic realm="members only", charset="UTF-8"'}})
}

function createBadRequestResponse(message) {
  return new Response(message, {status: 400})
}
