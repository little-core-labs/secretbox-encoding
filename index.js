const {
  crypto_secretbox_MACBYTES,
  crypto_secretbox_open_easy,
  crypto_secretbox_easy,
  crypto_generichash,
} = require('sodium-universal')

class DefaultEncoding {
  encode(value) { return value }
  decode(value) { return value }
}

function blake2b(size, message) {
  const out = Buffer.alloc(size)
  crypto_generichash(out, message)
  return out
}

function createCodec(nonce, key, opts) {
  if (Buffer.isBuffer(nonce) && Buffer.isBuffer(key)) {
    if (32 === nonce.length && 24 === key.length) {
      [ nonce, key ] = [ key, nonce ]
    }
  }

  if (32 === nonce.length && !Buffer.isBuffer(key)) {
    opts = key
    key = nonce
    nonce = blake2b(24, key)
  }

  if (!opts || 'object' !== typeof opts) {
    opts = {}
  }

  if (!Buffer.isBuffer(key)) {
    throw new TypeError('Expecting secret key to be a buffer')
  }

  if (key.length < 32) {
    throw new RangeError('Expecting secret key to be at least 32 bytes')
  }

  if (!Buffer.isBuffer(nonce)) {
    throw new TypeError('Expecting nonce to be a buffer')
  }

  if (nonce.length < 24) {
    throw new RangeError('Expecting nonce to be at least 24 bytes')
  }

  const { valueEncoding = new DefaultEncoding() } = opts

  nonce = nonce.slice(0, 24)
  key = key.slice(0, 32)

  encode.bytes = 0
  decode.bytes = 0

  return {
    encodingLength,
    valueEncoding,
    encode,
    decode,
    nonce,
    key,
  }

  function encode(value, buffer, offset) {
    const encodedValue = valueEncoding.encode(value)
    const plaintext = toBuffer(encodedValue)
    const length = encodingLength(encodedValue) + crypto_secretbox_MACBYTES

    if (!Buffer.isBuffer(plaintext)) {
      throw new TypeError('Cannot convert value to a buffer')
    }

    if ('number' === typeof buffer) {
      offset = buffer
    }

    if (!Buffer.isBuffer(buffer)) {
      buffer = Buffer.alloc(length)
    }

    if (!offset || 'number' !== typeof offset) {
      offset = 0
    }

    const ciphertext = buffer.slice(offset)

    if (ciphertext.length < length) {
      throw new RangeError('Cannot store ciphertext in buffer at offset.')
    }

    crypto_secretbox_easy(ciphertext, plaintext, nonce, key)

    encode.bytes = length
    return ciphertext
  }

  function decode(buffer, offset) {
    if (!offset || 'number' !== typeof offset) {
      offset = 0
    }

    if (!Buffer.isBuffer(buffer)) {
      throw new TypeError('Expecting decode input to be a buffer.')
    }

    const ciphertext = buffer.slice(offset)
    const length = encodingLength(ciphertext) - crypto_secretbox_MACBYTES

    if (0 === length) {
      throw new RangeError('Cannot decode empty ciphertext at offset.')
    }

    const plaintext = Buffer.allocUnsafe(length)

    crypto_secretbox_open_easy(plaintext, ciphertext, nonce, key)

    const decodedValue = valueEncoding.decode(plaintext, 0)

    return decodedValue
  }
}

function encodingLength(value) {
  const buffer = toBuffer(value)
  return buffer ? buffer.length : 0
}

function toBuffer(value) {
  if (Buffer.isBuffer(value)) {
    return value
  }

  if ('string' === typeof value) {
    return Buffer.from(value)
  }

  if (Array.isArray(value)) {
    return Buffer.from(value)
  }

  if (value && 'object' === value && 'Buffer' === value.type) {
    if (Array.isArray(value.data)) {
      return Buffer.from(value.data)
    }
  }

  return null
}

module.exports = createCodec
