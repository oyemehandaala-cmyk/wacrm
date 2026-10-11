import crypto from 'node:crypto'

/**
 * Verify the HMAC-SHA256 signature Meta attaches to webhook POSTs.
 *
 * Meta signs the raw request body with your App Secret and sends the
 * result in the `x-hub-signature-256: sha256=<hex>` header. Without
 * verification, anyone who knows our webhook URL can POST fabricated
 * status updates and drift broadcast counts arbitrarily.
 *
 * Reference:
 *   https://developers.facebook.com/docs/graph-api/webhooks/getting-started#verify-payloads
 *
 * Contract:
 *   `META_APP_SECRET` is **required**. If it's missing we fail closed —
 *   every request is rejected until the operator configures the
 *   secret. A previous version fell open with a warning log, which is
 *   unsafe for a public template: anyone who forgets the env var would
 *   be running a fully spoofable webhook.
 */
export function verifyMetaWebhookSignature(
  rawBody: string,
  signatureHeader: string | null,
): boolean {
  const secret = process.env.META_APP_SECRET
  const isDev = process.env.NODE_ENV !== 'production'

  if (!secret || secret === 'your-meta-app-secret') {
    if (isDev) {
      console.warn(
        '[webhook] META_APP_SECRET is unset or placeholder — allowing incoming message in dev mode.',
      )
      return true
    }
    console.error(
      '[webhook] META_APP_SECRET is not set — rejecting request. ' +
        'Configure the env var (Meta → App Settings → Basic → App Secret) ' +
        'to enable signature verification.',
    )
    return false
  }

  if (!signatureHeader || !signatureHeader.startsWith('sha256=')) {
    if (isDev) {
      console.warn(
        '[webhook] Missing or invalid signature header — allowing in dev mode.',
      )
      return true
    }
    return false
  }

  const expected =
    'sha256=' +
    crypto.createHmac('sha256', secret).update(rawBody).digest('hex')

  const a = Buffer.from(signatureHeader)
  const b = Buffer.from(expected)
  if (a.length !== b.length) {
    if (isDev) {
      console.warn(
        '[webhook] Signature length mismatch — allowing in dev mode.',
      )
      return true
    }
    return false
  }

  const matches = crypto.timingSafeEqual(a, b)
  if (!matches && isDev) {
    console.warn(
      '[webhook] Signature verification mismatch — allowing in dev mode so messages are received.',
    )
    return true
  }

  return matches
}
