import { generateKeyPair } from '../src'
;(async () => {
  const { publicKey, privateKey } = await generateKeyPair()
  console.info(publicKey)
  console.info(privateKey)
})()
