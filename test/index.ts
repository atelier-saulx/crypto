import test from 'ava'
import {
  generateKeyPair,
  sign,
  verify,
  encrypt,
  decrypt,
  encryptId,
  generateTokenKey,
  decryptId,
} from '../src'
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
    t.is(data, verified as string)
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
    t.is(data, verified as string)
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

test('sign creates different signed token each time', async (t) => {
  const { publicKey, privateKey } = await generateKeyPair()
  const data = {
    wawa: 'wawa',
    yeye: {
      wuhuu: 'ye',
    },
  }

  const signed1 = sign(data, privateKey)
  const signed2 = sign(data, privateKey)

  t.not(signed1, signed2)

  const verified1 = verify(signed1, publicKey)
  const verified2 = verify(signed2, publicKey)

  t.deepEqual(data, verified1)
  t.deepEqual(verified1, verified2)
})

test('encrypt creates different cipher text each time', async (t) => {
  const { publicKey, privateKey } = await generateKeyPair()

  const plain = 'wawa'

  const encrypted1 = encrypt(plain, publicKey)
  const encrypted2 = encrypt(plain, publicKey)

  t.not(encrypted1, encrypted2)

  const decrypted1 = decrypt(encrypted1, privateKey)
  const decrypted2 = decrypt(encrypted2, privateKey)

  t.is(plain, decrypted1)
  t.is(decrypted1, decrypted2)
})

test('Legacy compatibility', (t) => {
  // INFO: This is a test key not used anywhere
  const publicKey =
    '-----BEGIN RSA PUBLIC KEY-----\n' +
    'MIIBCgKCAQEAu1ze8eitZfmeAY5D3U+NfVjSd33/fpquVxZqP155hZXX3Gt1K4EF\n' +
    'GkmgRGAqk5VFz9Hq+cE7HNEGM1OAtWbRIqxpgcTi1peZxEg3iSbkMjFLjSoUOrV4\n' +
    'OR772lky/c4tysrtUznYHau/VnVno+F2LglCxbIZNVs5buWe5TLliLpX5NFHxHdb\n' +
    'Ekt2nLRRWdlgB2iLUwcCUWug9Eu3v5pqLRpMCKtn6alC/PeHMPbCIWUlflHDlWkx\n' +
    'C+2+7Ln8BPJtwnQEWoggRGaa+5MamiQy4tU2tGFoDf+lRSmjmYyz9/YDOVTGvXqi\n' +
    '3bu3S/qGIoeXtFAkBhinsD5+D6EY/RrdRQIDAQAB\n' +
    '-----END RSA PUBLIC KEY-----\n'
  const privateKey =
    '-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIIEpAIBAAKCAQEAu1ze8eitZfmeAY5D3U+NfVjSd33/fpquVxZqP155hZXX3Gt1\n' +
    'K4EFGkmgRGAqk5VFz9Hq+cE7HNEGM1OAtWbRIqxpgcTi1peZxEg3iSbkMjFLjSoU\n' +
    'OrV4OR772lky/c4tysrtUznYHau/VnVno+F2LglCxbIZNVs5buWe5TLliLpX5NFH\n' +
    'xHdbEkt2nLRRWdlgB2iLUwcCUWug9Eu3v5pqLRpMCKtn6alC/PeHMPbCIWUlflHD\n' +
    'lWkxC+2+7Ln8BPJtwnQEWoggRGaa+5MamiQy4tU2tGFoDf+lRSmjmYyz9/YDOVTG\n' +
    'vXqi3bu3S/qGIoeXtFAkBhinsD5+D6EY/RrdRQIDAQABAoIBAFHubjWl1HGj4tL2\n' +
    'Vbno6Ev4c+y55eiElplRnXuBgi2G1YK3YOD5xfP1X0aXMPchjwouVw0JUSKsSwRV\n' +
    'zxJEWE7Ly0VqhfFmEOEy3Uo1/hLu2IVt8bOsmFqOMH8Og4xWRVMJQxeiU13CNWUG\n' +
    '6R/SX34JIbBWzcw1zJswgTfj9li/uFXd4i7NRmCH2g7gd9ecmId8mbl3moggUd9b\n' +
    'rgYmLBKCFqS7loEmSKNUDkzDnsGBkre8SKzuU9gqjvuDAlkLnrWyi92RqDVv2vof\n' +
    'PlGrD+DNkKYzRVpRASd3mPRxcYXfTuNXKcmNfSmMjE7y0V6+BK8vYN0hldZOuVDM\n' +
    '+wLx6v8CgYEA2xstRYlOfqPpUfuSOW7l1Y7hfemhOqnxJ1DeBZqfMGNOWsLOljMx\n' +
    '+5wYQU2ys0jr9o4zk9LGhshMY1Z7XcZha4YDZPFm7GYJwowEsGqpRdVkjwu+eisS\n' +
    'XLaRkTNbhi6zleZuXMyqmW/cvfbhIFuqB5kGn/uD/ilV3rkEIZJ/LksCgYEA2ulb\n' +
    '5yQKvhssKVkt7o7tKWE1FnpV7b75Ey/QyKSn4YWaNlxQI6ReuXnMHrb0nTlYre/d\n' +
    'AmStDAdtwHSHJQWLWh0p+1LNUR9jZNms/NzKX6prtOLEZ4OsafKu/Vb9SwnHKUyl\n' +
    'ivjfO+mVZ6XVID99gB/AxJbpHzVWpprchBO7qK8CgYEAqQSG4Lwxo/lXU9mni8xj\n' +
    'WWE1ywZ9TB6qG3UDP/lt0UrZt6PM7wqhBQH9p+qC7lBTTceWO/L9GB3M51hgJA+T\n' +
    'OPmRBr49ciCoaL3QJDKzT150ivA5SE6PhJuFISgn8xN1jy3Jdqae92vWMWgPdAGh\n' +
    '4OiHtsOzp01Fo2C/shIrL48CgYEAvMCRmY8eJCTRwyU90YAzRYane6YoCUKtCLol\n' +
    'z5sJlg7YlR6ris/jTRGTyrf92sLjj7ZOXg3ol4KgQ102WdmZ+i1DUYxntBbYYNC/\n' +
    's5e8dxg+nk0ZBBgoxYGXGKG07MqViyqnYliMQuB5DlGSnqef0qWOVPO6NkqLWEQW\n' +
    '91r8Z8kCgYAR9AIwGHxGOelsP1QTyrh1SF37IXA1YsvOGp0c7+JwdYgVgWesLf05\n' +
    'LxlU60/DXvjAdpwrk0mn5MVYnwXEUysaPr4GOw7kBcQg1g6gKKpW2N0Gx+hrJCak\n' +
    'msSmG79Dz2AAEdHTrdjGBN0p0Bh1JkPU/5W4VHAo1kzYbyfrMrCuoA==\n' +
    '-----END RSA PRIVATE KEY-----\n'
  const signed =
    'ggfMH51zJiLHKxVxh1WeOlFXcW1O33xPRdEJZGzR3teiV6KtQ1MAN03hfqdcii99NKZkqGx0pdq6PWBCS+c3l6wS+MYYgqAtEhWfULcB6eTTCgqXIdOYVZhgT3n5/EeMIK6q1N6OVYdXzP5drQijBruGUFQpP53O9mkfLa4EzNC68b9xk4LRMi0u5ajb6k2sQTYjLjT3jcZ5kt6T0Rdftvzl1ATUKGZE8EZS3tARBB3CXYz4HmJHhYP7n3BV+j1pMsbaG/FAHVkqrVfn6TLiFIw58msRrMsDNVDI+7FA1d914Gxp66IFK+xSqGrxThPhJ2Zv8dzGvztPT5spwAsQmXsiaWQiOjIyMzM0LCJleHAiOjE3NDU2NjAxMDI1Nzh9ag=='
  const encrypted =
    'NKFErwJ+4Jz7Lk4XMzSrmEBU6RSs5bxrun8oBdXoBfVQsCHTKEExnvKFAz0W3IN4ugFDwlQP8F7xYQWsi6UdgaKmeOf2SqWnGx26krsFJKR4fYSnSkTJHIzesU4PCyeHscbpqhHOUiFsN5ulUog+GzRt6f59gnk7+B28yEfeqJV4YBaw2Z0siXhNr+5f15h7Kj218qRsl01DrCJNI/xa5R1ZuQcKYlE9AiEHZcaB3jgEdDr8AOWvD0zbrkqyrD/n11MPJi95lq3hPvwbzXpOtlE7STmD0IPOoKL8SP1iZ1VcHmHQnmmYoAdc+5Kx2/ubqEgBu2tGeNYinbzvVkalFuo88lPup8fgRfpj4tLjBbuqvHQ+ba6GgoLVwZ0LwdBv'

  const id = 22334
  const exp = 1745660102578
  let body = { id, exp }

  t.deepEqual(verify(signed, publicKey), body)
  t.deepEqual(decrypt(encrypted, privateKey), JSON.stringify(body))
})

test('encryptId/decryptId', (t) => {
  const id = 22334
  const exp = Date.now() + 300_000
  let body = { id, exp }

  t.throws(() => encryptId(randomBytes(16).toString('hex'), id, exp), {
    message: /^Invalid tokenKey size/,
  })
  t.throws(() => encryptId(undefined, id, exp), {
    message: 'tokenKey must be a string.',
  })
  t.throws(() => encryptId(null, id, exp), {
    message: 'tokenKey must be a string.',
  })

  // @ts-ignore
  t.throws(() => encryptId(generateTokenKey(), 'wawwa', exp), {
    message: /^id must be an integer/,
  })
  // @ts-ignore
  t.throws(() => encryptId(generateTokenKey(), undefined, exp), {
    message: /^id must be an integer/,
  })
  // @ts-ignore
  t.throws(() => encryptId(generateTokenKey(), null, exp), {
    message: /^id must be an integer/,
  })

  // @ts-ignore
  t.throws(() => encryptId(generateTokenKey(), id, 'wawa'), {
    message: /^exp must be an integer/,
  })

  let tokenKey = generateTokenKey()
  const encryptedId1 = encryptId(tokenKey, id, exp)
  const encryptedId2 = encryptId(tokenKey, id, exp)

  t.not(encryptedId1, encryptedId2)
  t.deepEqual(decryptId(tokenKey, encryptedId1), body)
  t.deepEqual(decryptId(tokenKey, encryptedId2), body)

  tokenKey = generateTokenKey()
  let encryptedId = encryptId(tokenKey, id, Date.now() - 100_000)
  t.throws(() => decryptId(tokenKey, encryptedId), {
    message: 'Expired token.',
  })

  tokenKey = generateTokenKey()
  encryptedId = encryptId(tokenKey, id, 0)
  t.notThrows(() => decryptId(tokenKey, encryptedId))
  encryptedId = encryptId(tokenKey, id)
  t.notThrows(() => decryptId(tokenKey, encryptedId))
})
