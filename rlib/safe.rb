#!/usr/local/bin/ruby
require_relative 'aes.rb'
require 'dbm'

#Playing with DBM, creating a key, encrypted value database
module SAFE
  class Safe
    # @param filename [String] db database filename
    # @param conf [Wikk_Conf]
    def initialize(filename:, conf:)
      @db = DBM.open(filename, 0600, DBM::WRCREAT)
      @aes = AES_256.new #(conf.key, conf.iv)
    end

    #Save a password in the database
    # @param key [String] password entry identity
    # @param value [String] password or string to encrypt and Save
    def save(key:, value:)
      @db[key] = @aes.cipher_to_s(value)
    end

    #Recover a password
    # @param key [String] password entry identity
    # @return [String] password
    def get(key:)
      iv, text = @db[key].split('$')
      @aes.decrypt(encrypted_source: text, password: @password, iv: iv, base64_source: true)
    end

    def get_raw(key:)
      @db[key]
    end

    #iterate over keys
    # @yield key [String]
    def each_key
      @db.each_key { |k| yield k }
    end
  end
end
