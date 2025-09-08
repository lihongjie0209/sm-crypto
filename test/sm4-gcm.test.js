const sm4 = require('../src/index').sm4

describe('SM4 GCM Mode Tests', () => {
  
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

  test('sm4-gcm: authentication failure with wrong tag', () => {
    const msg = 'secret message'
    const key = '0123456789abcdeffedcba9876543210'
    const iv = '000102030405060708090a0b'
    const aad = ''

    const encrypted = sm4.encrypt(msg, key, {mode: 'gcm', iv, aad})
    
    // Modify the tag
    const modifiedEncrypted = {
      ciphertext: encrypted.ciphertext,
      tag: encrypted.tag.slice(0, -2) + '00'
    }
    
    expect(() => {
      sm4.decrypt(modifiedEncrypted, key, {mode: 'gcm', iv, aad})
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

  test('sm4-gcm: different IV lengths', () => {
    const msg = 'test message'
    const key = '0123456789abcdeffedcba9876543210'
    const aad = ''

    // Standard 12-byte IV
    const iv12 = '000102030405060708090a0b'
    const encrypted12 = sm4.encrypt(msg, key, {mode: 'gcm', iv: iv12, aad})
    const decrypted12 = sm4.decrypt(encrypted12, key, {mode: 'gcm', iv: iv12, aad})
    expect(decrypted12).toBe(msg)

    // Non-standard 16-byte IV
    const iv16 = '000102030405060708090a0b0c0d0e0f'
    const encrypted16 = sm4.encrypt(msg, key, {mode: 'gcm', iv: iv16, aad})
    const decrypted16 = sm4.decrypt(encrypted16, key, {mode: 'gcm', iv: iv16, aad})
    expect(decrypted16).toBe(msg)

    // 8-byte IV
    const iv8 = '000102030405060'
    const encrypted8 = sm4.encrypt(msg, key, {mode: 'gcm', iv: iv8, aad})
    const decrypted8 = sm4.decrypt(encrypted8, key, {mode: 'gcm', iv: iv8, aad})
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

  test('sm4-gcm: empty message', () => {
    const msg = ''
    const key = '0123456789abcdeffedcba9876543210'
    const iv = '000102030405060708090a0b'
    const aad = 'aad_data'

    const encrypted = sm4.encrypt(msg, key, {mode: 'gcm', iv, aad})
    expect(encrypted.ciphertext).toBe('')
    expect(encrypted.tag.length).toBe(32)

    const decrypted = sm4.decrypt(encrypted, key, {mode: 'gcm', iv, aad})
    expect(decrypted).toBe(msg)
  })

  test('sm4-gcm: large message', () => {
    const msg = 'a'.repeat(1000) // 1000 character message
    const key = '0123456789abcdeffedcba9876543210'
    const iv = '000102030405060708090a0b'
    const aad = 'additional_authenticated_data'

    const encrypted = sm4.encrypt(msg, key, {mode: 'gcm', iv, aad})
    const decrypted = sm4.decrypt(encrypted, key, {mode: 'gcm', iv, aad})
    expect(decrypted).toBe(msg)
  })

})