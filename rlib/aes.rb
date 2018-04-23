#!/usr/local/bin/ruby
require 'openssl'
require 'digest/sha2'
require 'base64'

class AES_256

  def initialize
  end

  def encrypt(text:, password:, base64_source: true)
    text = StringIO.new(text) if(text.class == String)
    cipher = OpenSSL::Cipher.new('aes256')
    cipher.encrypt

    iv  = cipher.random_iv

    # Password derivation
    #salt = OpenSSL::Random.random_bytes(16)
    key  = OpenSSL::PKCS5.pbkdf2_hmac_sha1(password, "", 20_000, cipher.key_len)

    cipher.key = key

    cipher_text = ""
    while ((s = text.read(4096)) != nil) do cipher_text << cipher.update(s) end
    cipher_text << cipher.final

    return iv, cipher_text
  end

  #Decrypts source using AES 256 CBC, using @key and @iv
  #  @param encrypted_source [String|File]
  #  @param base64_source [Boolean] if true, then source is assumed to be base64 encoded.
  #  @return [String] String representing the original unencypted source
  def decrypt(encrypted_source:, password:, salt:, iv:, base64_source: false)
    encrypted_source = StringIO.new(encrypted_source) if(encrypted_source.class == String)
    read_count = base64_source ? 5464:4096
    decode_cipher = OpenSSL::Cipher.new('aes256')
    decode_cipher.decrypt
    decode_cipher.iv = iv
    decode_cipher.key  = OpenSSL::PKCS5.pbkdf2_hmac_sha1(password, salt, 20_000, decode_cipher.key_len)
    plain_text = ""
    while (et = encrypted_source.read(read_count)) != nil do
      plain_text << (base64_source ? decode_cipher.update(et.unpack('m')[0]) : decode_cipher.update(et))
    end
    plain_text << decode_cipher.final
  end

end
