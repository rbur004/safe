#!/usr/local/bin/ruby
require_relative '../rlib/aes'


salt, iv, encoded_text = AES_256.encrypt(text: 'The quick brown fox', password: 'password')
s = "#{[salt].pack('m').chomp}$#{[iv].pack('m').chomp}$#{[encoded_text].pack('m').chomp}"
puts s
salt2, iv2, encoded_text2 = s.split('$')
puts AES_256.decrypt(password: 'password', encrypted_source: encoded_text2, salt: salt2.unpack('m')[0], iv: iv2.unpack('m')[0], base64_source: true)
