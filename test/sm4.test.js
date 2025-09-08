const sm4 = require('../src/index').sm4
const msg = 'hello world! 我是 juneandgreen.'
const input = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]
const output_1 = [0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46, 0x00, 0x2a, 0x8a, 0x4e, 0xfa, 0x86, 0x3c, 0xca, 0xd0, 0x24, 0xac, 0x03, 0x00, 0xbb, 0x40, 0xd2]
const output_2 = [0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46]
const output_3 = [0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46, 0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46, 0x00, 0x2a, 0x8a, 0x4e, 0xfa, 0x86, 0x3c, 0xca, 0xd0, 0x24, 0xac, 0x03, 0x00, 0xbb, 0x40, 0xd2]
const outputHexStr_1 = '681edf34d206965e86b3e94f536e4246002a8a4efa863ccad024ac0300bb40d2'
const outputHexStr_2 = '681edf34d206965e86b3e94f536e4246'
const outputHexStr_3 = '681edf34d206965e86b3e94f536e4246681edf34d206965e86b3e94f536e4246002a8a4efa863ccad024ac0300bb40d2'
const input2 = [0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x20, 0xe6, 0x88, 0x91, 0xe6, 0x98, 0xaf, 0x20, 0x6a, 0x75, 0x6e, 0x65, 0x61, 0x6e, 0x64, 0x67, 0x72, 0x65, 0x65, 0x6e, 0x2e]
const output2HexStr = '0e395deb10f6e8a17e17823e1fd9bd98a1bff1df508b5b8a1efb79ec633d1bb129432ac1b74972dbe97bab04f024e89c'
const output3HexStr = '0d6cfa73c823b2ac0d6a92c564171892000fbea90be7a4d440bc58a9044fcb5f3d1615d91a6dbfb4dfb0c6915071527b'
const output2 = [0x0e, 0x39, 0x5d, 0xeb, 0x10, 0xf6, 0xe8, 0xa1, 0x7e, 0x17, 0x82, 0x3e, 0x1f, 0xd9, 0xbd, 0x98, 0xa1, 0xbf, 0xf1, 0xdf, 0x50, 0x8b, 0x5b, 0x8a, 0x1e, 0xfb, 0x79, 0xec, 0x63, 0x3d, 0x1b, 0xb1, 0x29, 0x43, 0x2a, 0xc1, 0xb7, 0x49, 0x72, 0xdb, 0xe9, 0x7b, 0xab, 0x04, 0xf0, 0x24, 0xe8, 0x9c]
const iv = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
const ivHexStr = 'fedcba98765432100123456789abcdef'
const key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]
const keyHexStr = '0123456789abcdeffedcba9876543210'

test('sm4: encrypt a group', () => {
    expect(sm4.encrypt(input, key)).toBe(outputHexStr_1)
    expect(sm4.encrypt(input, key, {output: 'array'})).toEqual(output_1)
    expect(sm4.encrypt(input, key, {padding: 'pkcs#5'})).toBe(outputHexStr_1)
    expect(sm4.encrypt(input, key, {padding: 'pkcs#5', output: 'array'})).toEqual(output_1)
    expect(sm4.encrypt(input, key, {padding: 'none'})).toBe(outputHexStr_2)
    expect(sm4.encrypt(input, key, {padding: 'none', output: 'array'})).toEqual(output_2)
    expect(sm4.encrypt(msg, keyHexStr)).toBe(output2HexStr)
    expect(sm4.encrypt(msg, keyHexStr, {output: 'array'})).toEqual(output2)
    expect(sm4.encrypt(msg, keyHexStr, {mode: 'cbc', iv})).toBe(output3HexStr)
    expect(sm4.encrypt(msg, keyHexStr, {mode: 'cbc', iv: ivHexStr})).toBe(output3HexStr)
    expect(sm4.encrypt(input2, keyHexStr)).toBe(output2HexStr)
    expect(sm4.encrypt(input2, keyHexStr, {output: 'array'})).toEqual(output2)
})

test('sm4: decrypt a group', () => {
    expect(sm4.decrypt(outputHexStr_1, key, {output: 'array'})).toEqual(input)
    expect(sm4.decrypt(output_1, key, {output: 'array'})).toEqual(input)
    expect(sm4.decrypt(outputHexStr_2, key, {padding: 'none', output: 'array'})).toEqual(input)
    expect(sm4.decrypt(output_2, key, {padding: 'none', output: 'array'})).toEqual(input)
    expect(sm4.decrypt(output2HexStr, keyHexStr)).toBe(msg)
    expect(sm4.decrypt(output2, keyHexStr)).toBe(msg)
    expect(sm4.decrypt(output2HexStr, keyHexStr, {output: 'array'})).toEqual(input2)
    expect(sm4.decrypt(output3HexStr, keyHexStr, {mode: 'cbc', iv})).toBe(msg)
    expect(sm4.decrypt(output3HexStr, keyHexStr, {mode: 'cbc', iv: ivHexStr})).toBe(msg)
    expect(sm4.decrypt(output2, keyHexStr, {output: 'array'})).toEqual(input2)
})

test('sm4: encrypt several groups', () => {
    expect(sm4.encrypt([...input, ...input], key)).toBe(outputHexStr_3)
    expect(sm4.encrypt([...input, ...input], key, {output: 'array'})).toEqual(output_3)
    expect(sm4.encrypt([...input, ...input], key, {padding: 'none'})).toBe(outputHexStr_2 + outputHexStr_2)
    expect(sm4.encrypt([...input, ...input], key, {padding: 'none', output: 'array'})).toEqual([...output_2, ...output_2])
})

test('sm4: decrypt several groups', () => {
    expect(sm4.decrypt(outputHexStr_3, key, {output: 'array'})).toEqual([...input, ...input])
    expect(sm4.decrypt(output_3, key, {output: 'array'})).toEqual([...input, ...input])
    expect(sm4.decrypt(outputHexStr_2 + outputHexStr_2, key, {padding: 'none', output: 'array'})).toEqual([...input, ...input])
    expect(sm4.decrypt([...output_2, ...output_2], key, {padding: 'none', output: 'array'})).toEqual([...input, ...input])
})

test('sm4: encrypt unicode string', () => {
    expect(sm4.encrypt('🇨🇳𠮷😀😃😄😁😆😅', keyHexStr)).toBe('a0b1aac2e6db928ddfc8a081a6661d0452b44e5720db106714ffc8cbee29bcf7d96b4d64bffd07553e6a2ee096523b7f')
    expect(sm4.decrypt('a0b1aac2e6db928ddfc8a081a6661d0452b44e5720db106714ffc8cbee29bcf7d96b4d64bffd07553e6a2ee096523b7f', keyHexStr)).toBe('🇨🇳𠮷😀😃😄😁😆😅')
})

test('sm4: encrypt a group whit 1000000 times', () => {
    let temp = input
    for (let i = 0; i < 1000000; i++) {
        temp = sm4.encrypt(temp, key, {padding: 'none', output: 'array'})
    }
    expect(temp).toEqual([0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f, 0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66])
})

test('sm4: invalid padding', () => {
    expect(() => sm4.decrypt('a0b1aac2e6db928ddfc8a081a6661d0452b44e5720db106714ffc8cbee29bcf7d96b4d64bffd07553e6a2ee096523b7a', keyHexStr)).toThrow('padding is invalid')
    expect(() => sm4.decrypt('a0b1aac2e6db928ddfc8a081a6661d0452b44e5720db106714ffc8cbee29bcf7d96b4d64bffd07553e6a2ee096523b7f', ivHexStr)).toThrow('padding is invalid')
})

// GCM Mode Tests
test('sm4-gcm: basic encryption and decryption', () => {
  const msg = 'hello world'
  const key = '0123456789abcdeffedcba9876543210'
  const iv = '000102030405060708090a0b'
  const aad = ''

  const encrypted = sm4.encrypt(msg, key, {mode: 'gcm', iv, aad})
  expect(encrypted).toHaveProperty('ciphertext')
  expect(encrypted).toHaveProperty('tag')
  expect(typeof encrypted.ciphertext).toBe('string')
  expect(typeof encrypted.tag).toBe('string')
  expect(encrypted.tag.length).toBe(32) // 16 bytes = 32 hex chars

  const decrypted = sm4.decrypt(encrypted, key, {mode: 'gcm', iv, aad})
  expect(decrypted).toBe(msg)
})

test('sm4-gcm: known test vectors', () => {
  // Test vector 1
  const result1 = sm4.encrypt('hello world', '0123456789abcdeffedcba9876543210', {
    mode: 'gcm', 
    iv: '000102030405060708090a0b', 
    aad: ''
  })
  expect(result1.ciphertext).toBe('3d4474fdde91de7016ece7')
  expect(result1.tag).toBe('821ccac5fddfac593634ca5363b25c76')
  
  // Verify decryption
  const decrypt1 = sm4.decrypt(result1, '0123456789abcdeffedcba9876543210', {
    mode: 'gcm', 
    iv: '000102030405060708090a0b', 
    aad: ''
  })
  expect(decrypt1).toBe('hello world')
})

test('sm4-gcm: encryption and decryption with AAD', () => {
  const msg = 'test message with authentication'
  const key = '0123456789abcdeffedcba9876543210'
  const iv = '000102030405060708090a0b'
  const aad = '112233445566778899aabbccddee'

  const encrypted = sm4.encrypt(msg, key, {mode: 'gcm', iv, aad})
  const decrypted = sm4.decrypt(encrypted, key, {mode: 'gcm', iv, aad})
  expect(decrypted).toBe(msg)
})

test('sm4-gcm: authentication failure with wrong AAD', () => {
  const msg = 'secret message'
  const key = '0123456789abcdeffedcba9876543210'
  const iv = '000102030405060708090a0b'
  const aad = '112233445566778899aabbcc'

  const encrypted = sm4.encrypt(msg, key, {mode: 'gcm', iv, aad})
  
  expect(() => {
    sm4.decrypt(encrypted, key, {mode: 'gcm', iv, aad: '112233445566778899aabbcd'})
  }).toThrow('Authentication tag verification failed')
})

test('sm4-gcm: different tag lengths', () => {
  const msg = 'test message'
  const key = '0123456789abcdeffedcba9876543210'
  const iv = '000102030405060708090a0b'
  const aad = ''

  // Test with 12-byte tag
  const encrypted12 = sm4.encrypt(msg, key, {mode: 'gcm', iv, aad, tagLength: 12})
  expect(encrypted12.tag.length).toBe(24) // 12 bytes = 24 hex chars
  
  const decrypted12 = sm4.decrypt(encrypted12, key, {mode: 'gcm', iv, aad, tagLength: 12})
  expect(decrypted12).toBe(msg)

  // Test with 8-byte tag
  const encrypted8 = sm4.encrypt(msg, key, {mode: 'gcm', iv, aad, tagLength: 8})
  expect(encrypted8.tag.length).toBe(16) // 8 bytes = 16 hex chars
  
  const decrypted8 = sm4.decrypt(encrypted8, key, {mode: 'gcm', iv, aad, tagLength: 8})
  expect(decrypted8).toBe(msg)
})

test('sm4-gcm: array input/output format', () => {
  const msg = [0x68, 0x65, 0x6c, 0x6c, 0x6f] // "hello"
  const key = '0123456789abcdeffedcba9876543210'
  const iv = '000102030405060708090a0b'
  const aad = [0x11, 0x22, 0x33]

  const encrypted = sm4.encrypt(msg, key, {mode: 'gcm', iv, aad, output: 'array'})
  expect(Array.isArray(encrypted.ciphertext)).toBe(true)
  expect(Array.isArray(encrypted.tag)).toBe(true)

  const decrypted = sm4.decrypt(encrypted, key, {mode: 'gcm', iv, aad, output: 'array'})
  expect(decrypted).toEqual(msg)
})

test('sm4-gcm: error cases', () => {
  const msg = 'test message'
  const key = '0123456789abcdeffedcba9876543210'

  // Missing IV
  expect(() => {
    sm4.encrypt(msg, key, {mode: 'gcm'})
  }).toThrow('iv is required for GCM mode')

  // Invalid tag length
  expect(() => {
    sm4.encrypt(msg, key, {mode: 'gcm', iv: '000102030405060708090a0b', tagLength: 3})
  }).toThrow('tagLength must be between 4 and 16 bytes')

  expect(() => {
    sm4.encrypt(msg, key, {mode: 'gcm', iv: '000102030405060708090a0b', tagLength: 17})
  }).toThrow('tagLength must be between 4 and 16 bytes')

  // Invalid decrypt input format
  expect(() => {
    sm4.decrypt('invalidformat', key, {mode: 'gcm', iv: '000102030405060708090a0b'})
  }).toThrow('GCM decryption requires {ciphertext, tag} input format')
})