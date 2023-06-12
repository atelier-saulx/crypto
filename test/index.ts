import test from 'ava'
import { generateKeyPair, sign, verify, encrypt, decrypt } from '../src'
import { randomBytes } from 'node:crypto'

test('should sign and verify string', async (t) => {
  const { publicKey, privateKey } = await generateKeyPair()
  const data = 'wawa'

  const start = Date.now()
  const signed = sign(data, privateKey)
  t.log(`Sign time: ${Date.now() - start}ms`)

  t.notThrows(() => {
    const start = Date.now()
    const verified = verify(signed, publicKey)
    t.log(`Verify time: ${Date.now() - start}ms`)
    t.is(data, verified)
  })
})

test('should sign and verify huge string', async (t) => {
  const { publicKey, privateKey } = await generateKeyPair()

  const data = randomBytes(2 * 1024 * 1024).toString('hex')

  const start = Date.now()
  const signed = sign(data, privateKey)
  t.log(`Sign time: ${Date.now() - start}ms`)

  t.notThrows(() => {
    const start = Date.now()
    const verified = verify(signed, publicKey)
    t.log(`Verify time: ${Date.now() - start}ms`)
    t.is(data, verified)
  })
})

test('should sign and verify object', async (t) => {
  const { publicKey, privateKey } = await generateKeyPair()
  const data = {
    wawa: 'wawa',
    yeye: {
      wuhuu: 'ye',
    },
  }

  const start = Date.now()
  const signed = sign(data, privateKey)
  t.log(`Sign time: ${Date.now() - start}ms`)

  t.notThrows(() => {
    const start = Date.now()
    const verified = verify<object>(signed, publicKey)
    t.log(`Verify time: ${Date.now() - start}ms`)
    t.deepEqual(data, verified)
  })
})

test('should fail verify with different key', async (t) => {
  const { privateKey: priv1 } = await generateKeyPair()
  const { publicKey: pub2 } = await generateKeyPair()
  const signed = sign('wawa', priv1)
  t.throws(() => {
    verify(signed, pub2)
  })
})

test('should fail verify with tampered data', async (t) => {
  const { publicKey, privateKey } = await generateKeyPair()
  let signed = sign('wawa', privateKey)
  signed = signed.substring(0, 4) + '1' + signed.substring(5)
  t.throws(() => {
    verify(signed, publicKey)
  })
})

test('should encrypt and decrypt', async (t) => {
  const { publicKey, privateKey } = await generateKeyPair()

  const plain =
    'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Duis sed ultrices est. Mauris tortor metus, fringilla eget turpis in, suscipit facilisis ante. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Proin blandit id risus sed pharetra. Vestibulum ante velit, posuere eget auctor nec, scelerisque ut tortor. Duis rhoncus mauris tincidunt magna mattis pretium. Etiam sit amet ipsum quis justo condimentum vulputate ac sed eros. Vivamus pretium finibus leo ac suscipit. Cras sit amet tortor in augue ultrices fringilla non at metus. Nullam mattis eleifend nisi quis aliquam. Vestibulum a euismod nibh. Sed vitae ligula nulla.'

  let start = Date.now()
  const cypher = encrypt(plain, publicKey)
  t.log(`Encrypt time: ${Date.now() - start}ms`)

  start = Date.now()
  const decrypted = decrypt(cypher, privateKey)
  t.log(`Decrypt time: ${Date.now() - start}ms`)

  t.is(plain, decrypted)
})

test('should encrypt and decrypt small', async (t) => {
  const { publicKey, privateKey } = await generateKeyPair()

  const plain = 'wawa'

  let start = Date.now()
  const encrypted = encrypt(plain, publicKey)
  t.log(`Encrypt time: ${Date.now() - start}ms`)

  start = Date.now()
  const decrypted = decrypt(encrypted, privateKey)
  t.log(`Decrypt time: ${Date.now() - start}ms`)

  t.is(plain, decrypted)
})

test('should encrypt and decrypt huge', async (t) => {
  const { publicKey, privateKey } = await generateKeyPair()

  const plain = randomBytes(2 * 1024 * 1024).toString('hex')

  let start = Date.now()
  const encrypted = encrypt(plain, publicKey)
  t.log(`Encrypt time: ${Date.now() - start}ms`)

  start = Date.now()
  const decrypted = decrypt(encrypted, privateKey)
  t.log(`Decrypt time: ${Date.now() - start}ms`)

  t.is(plain, decrypted)
})

test('should fail with wrong key', async (t) => {
  const { privateKey: priv1 } = await generateKeyPair()
  const { publicKey: pub2 } = await generateKeyPair()

  const plain = 'wawa'
  const encrypted = encrypt(plain, pub2)
  const error = t.throws(() => {
    decrypt(encrypted, priv1)
  })
})
